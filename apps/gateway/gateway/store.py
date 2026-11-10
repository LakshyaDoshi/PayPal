"""
gateway.store

SQLite-backed persistence for MandateGate using the standard library ``sqlite3``
module (WAL mode, single-writer lock, atomic budget reservation).

Tables
------
mandates          Signed mandate JSON blobs, revocation flag.
revocations       Explicit revocation events with reason and timestamp.
decisions         Hash-chained audit log (each row stores prev_hash + hash).
pending_approvals Escalated payments awaiting human sign-off.
spend_ledger      Immutable per-mandate spend records tied to decision IDs.

Concurrency model
-----------------
A single ``threading.Lock`` serialises all *write* operations.  The
``reserve_spend`` method opens a ``BEGIN IMMEDIATE`` transaction so that
two threads racing to spend the last cents will have one transaction
blocked at the SQLite level until the first commits, at which point the
second can re-check the budget and either succeed or fail cleanly.

Hash chain
----------
Each decision row stores:
  prev_hash  SHA-256 hex of the previous row (or 64 × '0' for the genesis row)
  hash       SHA-256 hex of (prev_hash || canonical_decision_json)

``verify_chain()`` walks every row in insertion order and returns the id of
the first broken row, or ``None`` if the chain is intact.

Invariants
----------
- No float for money — all amounts are integer minor units.
- No FastAPI / MCP imports.
- All writes serialised through ``_lock``.
- Fail closed: any unexpected exception propagates; callers must BLOCK.
"""

from __future__ import annotations

import hashlib
import json

# ---------------------------------------------------------------------------
# Database path — defaults to in-memory for tests, overridden via DB_PATH env
# ---------------------------------------------------------------------------
import os
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from gateway.contract import Decision, Mandate

_DEFAULT_DB_PATH: str = os.environ.get("DB_PATH", ":memory:")


# ---------------------------------------------------------------------------
# Per-instance lock (all writes go through self._lock)
# ---------------------------------------------------------------------------
# Using an instance-level lock (rather than module-level) means that two
# separate MandateStore objects wrapping the *same* file-backed SQLite DB
# will race at the SQLite layer (BEGIN IMMEDIATE serialises them there),
# which is exactly what the concurrent-spend test needs to exercise.


# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS mandates (
    id              TEXT PRIMARY KEY,
    json_blob       TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS revocations (
    id              TEXT PRIMARY KEY,
    mandate_id      TEXT NOT NULL REFERENCES mandates(id),
    reason          TEXT NOT NULL DEFAULT '',
    revoked_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    id              TEXT PRIMARY KEY,
    mandate_id      TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    json_blob       TEXT NOT NULL,
    prev_hash       TEXT NOT NULL,
    hash            TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_approvals (
    id              TEXT PRIMARY KEY,
    decision_id     TEXT NOT NULL REFERENCES decisions(id),
    mandate_id      TEXT NOT NULL,
    amount_minor    INTEGER NOT NULL,
    currency        TEXT NOT NULL,
    payee           TEXT NOT NULL,
    memo            TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    resolved_at     TEXT,
    resolution      TEXT
);

CREATE TABLE IF NOT EXISTS spend_ledger (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mandate_id      TEXT NOT NULL REFERENCES mandates(id),
    decision_id     TEXT NOT NULL,
    amount_minor    INTEGER NOT NULL CHECK(amount_minor > 0),
    currency        TEXT NOT NULL,
    payee           TEXT NOT NULL DEFAULT '',
    memo            TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT NOT NULL DEFAULT '',
    recorded_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS frozen_mandates (
    mandate_id      TEXT PRIMARY KEY,
    reason          TEXT NOT NULL,
    consecutive_blocks INTEGER NOT NULL,
    frozen_at       TEXT NOT NULL
);
"""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _decision_canonical(decision: Decision) -> str:
    """Compact, sorted-key JSON of a Decision for chain hashing."""
    return json.dumps(
        decision.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _chain_hash(prev_hash: str, decision_json: str) -> str:
    """SHA-256(prev_hash_bytes + decision_json_bytes) as hex string."""
    payload = (prev_hash + decision_json).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


_GENESIS_HASH = "0" * 64  # sentinel for the first row in the chain


# ---------------------------------------------------------------------------
# MandateStore
# ---------------------------------------------------------------------------


class MandateStore:
    """Thread-safe SQLite store for MandateGate domain objects.

    Parameters
    ----------
    db_path:
        Filesystem path (or ``":memory:"`` for tests).  Defaults to the
        ``DB_PATH`` environment variable, or ``":memory:"`` if unset.
    """

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        self._db_path = db_path
        self._lock: threading.Lock = threading.Lock()
        # Use check_same_thread=False — self._lock guards all writes.
        self._conn: sqlite3.Connection = sqlite3.connect(
            db_path, check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._apply_schema()

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _apply_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_SCHEMA_SQL)

    @contextmanager
    def _immediate(self) -> Generator[sqlite3.Cursor, None, None]:
        """Context manager for a BEGIN IMMEDIATE transaction (write-lock)."""
        cur = self._conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            yield cur
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Mandates
    # ------------------------------------------------------------------

    def save_mandate(self, mandate: Mandate) -> None:
        """Persist a signed mandate.  Overwrites if id already exists."""
        blob = mandate.model_dump_json()
        with self._lock:
            with self._immediate() as cur:
                cur.execute(
                    """
                    INSERT INTO mandates (id, json_blob, created_at, revoked)
                    VALUES (?, ?, ?, 0)
                    ON CONFLICT(id) DO UPDATE SET json_blob=excluded.json_blob,
                                                  created_at=excluded.created_at,
                                                  revoked=0
                    """,
                    (mandate.id, blob, _now_iso()),
                )

    def load_mandate(self, mandate_id: str) -> Mandate | None:
        """Return the ``Mandate`` for *mandate_id*, or ``None`` if not found."""
        row = self._conn.execute(
            "SELECT json_blob FROM mandates WHERE id = ?", (mandate_id,)
        ).fetchone()
        if row is None:
            return None
        return Mandate.model_validate_json(row["json_blob"])

    def count_mandates(self) -> int:
        """Return the total number of mandates stored in the database."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) AS total FROM mandates")
            row = cur.fetchone()
            return int(row["total"]) if row else 0

    def is_revoked(self, mandate_id: str) -> bool:
        """Return ``True`` if the mandate has been revoked."""
        row = self._conn.execute(
            "SELECT revoked FROM mandates WHERE id = ?", (mandate_id,)
        ).fetchone()
        return bool(row and row["revoked"])

    def revoke_mandate(self, mandate_id: str, reason: str = "") -> None:
        """Mark a mandate as revoked and record the revocation event."""
        revocation_id = f"rev_{mandate_id}_{_now_iso()}"
        with self._lock:
            with self._immediate() as cur:
                cur.execute("UPDATE mandates SET revoked = 1 WHERE id = ?", (mandate_id,))
                cur.execute(
                    """
                    INSERT INTO revocations (id, mandate_id, reason, revoked_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (revocation_id, mandate_id, reason, _now_iso()),
                )

    # ------------------------------------------------------------------
    # Decisions (hash-chained audit log)
    # ------------------------------------------------------------------

    def _last_chain_hash(self, cur: sqlite3.Cursor) -> str:
        """Return the hash of the most recent decision row, or genesis hash."""
        row = cur.execute("SELECT hash FROM decisions ORDER BY rowid DESC LIMIT 1").fetchone()
        return row["hash"] if row else _GENESIS_HASH

    def save_decision(self, decision: Decision, mandate_id: str) -> None:
        """Append a decision to the hash-chained audit log."""
        dec_json = _decision_canonical(decision)
        with self._lock:
            with self._immediate() as cur:
                prev_hash = self._last_chain_hash(cur)
                row_hash = _chain_hash(prev_hash, dec_json)
                cur.execute(
                    """
                    INSERT INTO decisions
                        (id, mandate_id, verdict, json_blob, prev_hash, hash, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        decision.id,
                        mandate_id,
                        decision.verdict.value,
                        dec_json,
                        prev_hash,
                        row_hash,
                        decision.created_at.isoformat(),
                    ),
                )

    def load_decision(self, decision_id: str) -> Decision | None:
        """Return the ``Decision`` for *decision_id*, or ``None``."""
        row = self._conn.execute(
            "SELECT json_blob FROM decisions WHERE id = ?", (decision_id,)
        ).fetchone()
        if row is None:
            return None
        return Decision.model_validate_json(row["json_blob"])

    def verify_chain(self) -> str | None:
        """Walk the decision log and return the id of the first broken row.

        Returns ``None`` if the chain is intact (or empty).
        A broken row is one where the stored hash does not match the
        recomputed ``SHA-256(prev_hash + canonical_decision_json)``.
        """
        rows = self._conn.execute(
            "SELECT id, json_blob, prev_hash, hash FROM decisions ORDER BY rowid ASC"
        ).fetchall()

        running_prev = _GENESIS_HASH
        for row in rows:
            expected_prev = running_prev
            if row["prev_hash"] != expected_prev:
                return row["id"]
            recomputed = _chain_hash(row["prev_hash"], row["json_blob"])
            if recomputed != row["hash"]:
                return row["id"]
            running_prev = row["hash"]

        return None

    # ------------------------------------------------------------------
    # Atomic budget reservation
    # ------------------------------------------------------------------

    def reserve_spend(
        self,
        mandate_id: str,
        decision_id: str,
        amount_minor: int,
        currency: str,
        payee: str = "",
        memo: str = "",
        idempotency_key: str = "",
    ) -> bool:
        """Atomically reserve *amount_minor* against the mandate budget.

        Opens a ``BEGIN IMMEDIATE`` transaction so that concurrent callers
        block at the SQLite level — only one can proceed at a time.

        Returns
        -------
        True
            Reservation succeeded; the spend is recorded in ``spend_ledger``.
        False
            Insufficient remaining budget; nothing is written.

        Raises
        ------
        ValueError
            If *mandate_id* does not exist or *amount_minor* is not positive.
        RuntimeError
            If the mandate currency does not match *currency*.
        """
        if amount_minor <= 0:
            raise ValueError(f"amount_minor must be positive, got {amount_minor}")

        with self._lock:
            with self._immediate() as cur:
                # Load mandate inside the transaction for consistency.
                row = cur.execute(
                    "SELECT json_blob FROM mandates WHERE id = ? AND revoked = 0",
                    (mandate_id,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"Mandate '{mandate_id}' not found or has been revoked.")

                mandate = Mandate.model_validate_json(row["json_blob"])

                if mandate.currency != currency:
                    raise RuntimeError(
                        f"Currency mismatch: mandate is {mandate.currency}, request is {currency}."
                    )

                # Sum all approved spends for this mandate.
                spent_row = cur.execute(
                    "SELECT COALESCE(SUM(amount_minor), 0) AS total "
                    "FROM spend_ledger WHERE mandate_id = ?",
                    (mandate_id,),
                ).fetchone()
                total_spent: int = int(spent_row["total"])

                # Idempotency check: prevent duplicate transactions with same idempotency_key
                if idempotency_key:
                    dup_row = cur.execute(
                        "SELECT 1 FROM spend_ledger WHERE mandate_id = ? AND idempotency_key = ?",
                        (mandate_id, idempotency_key),
                    ).fetchone()
                    if dup_row is not None:
                        return False

                remaining = mandate.max_amount_minor - total_spent
                if amount_minor > remaining:
                    return False

                # Record the spend.
                cur.execute(
                    """
                    INSERT INTO spend_ledger
                        (mandate_id, decision_id, amount_minor, currency,
                         payee, memo, idempotency_key, recorded_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        mandate_id,
                        decision_id,
                        amount_minor,
                        currency,
                        payee,
                        memo,
                        idempotency_key,
                        _now_iso(),
                    ),
                )
                return True

    def release_spend(self, mandate_id: str, decision_id: str) -> None:
        """Rollback a reserved spend from spend_ledger if downstream execution failed."""
        with self._lock:
            with self._immediate() as cur:
                cur.execute(
                    "DELETE FROM spend_ledger WHERE mandate_id = ? AND decision_id = ?",
                    (mandate_id, decision_id),
                )

    def consecutive_blocks(self, mandate_id: str) -> int:
        """Count the number of consecutive recent BLOCK decisions for a mandate."""
        rows = self._conn.execute(
            """
            SELECT verdict FROM decisions
            WHERE mandate_id = ?
            ORDER BY rowid DESC
            LIMIT 100
            """,
            (mandate_id,),
        ).fetchall()
        count = 0
        for r in rows:
            if r["verdict"] == "block":
                count += 1
            else:
                break
        return count

    def freeze_mandate(
        self,
        mandate_id: str,
        reason: str = "",
        consecutive_blocks: int = 0,
    ) -> None:
        """Freeze a mandate via circuit breaker after repeated failures."""
        with self._lock:
            with self._immediate() as cur:
                cur.execute(
                    """
                    INSERT INTO frozen_mandates (mandate_id, reason, consecutive_blocks, frozen_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(mandate_id) DO UPDATE SET
                        reason = excluded.reason,
                        consecutive_blocks = excluded.consecutive_blocks,
                        frozen_at = excluded.frozen_at
                    """,
                    (mandate_id, reason, consecutive_blocks, _now_iso()),
                )

    def is_frozen(self, mandate_id: str) -> bool:
        """Return True if the mandate is currently frozen by the circuit breaker."""
        row = self._conn.execute(
            "SELECT 1 FROM frozen_mandates WHERE mandate_id = ?",
            (mandate_id,),
        ).fetchone()
        return row is not None

    def unfreeze_mandate(self, mandate_id: str) -> None:
        """Unfreeze a mandate, resetting its circuit breaker state."""
        with self._lock:
            with self._immediate() as cur:
                cur.execute(
                    "DELETE FROM frozen_mandates WHERE mandate_id = ?",
                    (mandate_id,),
                )

    def list_recent_spends(self, mandate_id: str) -> list[dict[str, Any]]:
        """Return list of spend ledger records for a mandate in chronological order."""
        rows = self._conn.execute(
            """
            SELECT mandate_id, decision_id, amount_minor, currency,
                   payee, memo, idempotency_key, recorded_at
            FROM spend_ledger
            WHERE mandate_id = ?
            ORDER BY id ASC
            """,
            (mandate_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def total_spent(self, mandate_id: str) -> int:
        """Return total minor units spent under *mandate_id* (0 if none)."""
        row = self._conn.execute(
            "SELECT COALESCE(SUM(amount_minor), 0) AS total FROM spend_ledger WHERE mandate_id = ?",
            (mandate_id,),
        ).fetchone()
        return int(row["total"])

    # ------------------------------------------------------------------
    # Pending approvals
    # ------------------------------------------------------------------

    def save_pending_approval(
        self,
        approval_id: str,
        decision_id: str,
        mandate_id: str,
        amount_minor: int,
        currency: str,
        payee: str,
        memo: str,
    ) -> None:
        """Record an escalated payment pending human approval."""
        with self._lock:
            with self._immediate() as cur:
                cur.execute(
                    """
                    INSERT INTO pending_approvals
                        (id, decision_id, mandate_id, amount_minor, currency,
                         payee, memo, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        approval_id,
                        decision_id,
                        mandate_id,
                        amount_minor,
                        currency,
                        payee,
                        memo,
                        _now_iso(),
                    ),
                )

    def resolve_pending_approval(self, approval_id: str, resolution: str) -> None:
        """Mark a pending approval as resolved (approved / rejected)."""
        with self._lock:
            with self._immediate() as cur:
                cur.execute(
                    """
                    UPDATE pending_approvals
                    SET resolved_at = ?, resolution = ?
                    WHERE id = ?
                    """,
                    (_now_iso(), resolution, approval_id),
                )

    def list_pending_approvals(self, mandate_id: str | None = None) -> list[dict[str, Any]]:
        """Return all unresolved pending approvals, optionally filtered by mandate."""
        if mandate_id:
            rows = self._conn.execute(
                "SELECT * FROM pending_approvals "
                "WHERE resolved_at IS NULL AND mandate_id = ? ORDER BY created_at",
                (mandate_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM pending_approvals WHERE resolved_at IS NULL ORDER BY created_at"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_pending_approval(self, approval_id: str) -> dict[str, Any] | None:
        """Return a pending approval record by ID, or None if not found."""
        row = self._conn.execute(
            "SELECT * FROM pending_approvals WHERE id = ?", (approval_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_decisions(
        self, limit: int = 50, offset: int = 0, mandate_id: str | None = None
    ) -> list[Decision]:
        """Return decisions in reverse chronological order (newest first)."""
        if mandate_id:
            rows = self._conn.execute(
                """
                SELECT json_blob FROM decisions
                WHERE mandate_id = ?
                ORDER BY rowid DESC
                LIMIT ? OFFSET ?
                """,
                (mandate_id, limit, offset),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT json_blob FROM decisions
                ORDER BY rowid DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return [Decision.model_validate_json(r["json_blob"]) for r in rows]

    def count_decisions(self, mandate_id: str | None = None) -> int:
        """Return total count of decisions in the audit log."""
        if mandate_id:
            row = self._conn.execute(
                "SELECT COUNT(*) AS total FROM decisions WHERE mandate_id = ?",
                (mandate_id,),
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) AS total FROM decisions").fetchone()
        return int(row["total"]) if row else 0

    def list_audit_rows(self) -> list[dict[str, Any]]:
        """Return all raw decision records for cryptographic audit chain inspection."""
        rows = self._conn.execute(
            """
            SELECT id, mandate_id, verdict, prev_hash, hash, created_at
            FROM decisions
            ORDER BY rowid ASC
            """
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()

    def reset(self) -> None:
        """Drop all rows from all tables (useful in tests and seed scripts)."""
        with self._lock:
            with self._immediate() as cur:
                for table in (
                    "spend_ledger",
                    "pending_approvals",
                    "decisions",
                    "revocations",
                    "mandates",
                ):
                    cur.execute(f"DELETE FROM {table}")  # noqa: S608


# ---------------------------------------------------------------------------
# Module-level convenience instance (DB_PATH from environment)
# ---------------------------------------------------------------------------


def open_store(db_path: str | None = None) -> MandateStore:
    """Create and return a new ``MandateStore``.

    Parameters
    ----------
    db_path:
        Override path.  Defaults to ``DB_PATH`` env var or ``":memory:"``.
    """
    return MandateStore(db_path=db_path or _DEFAULT_DB_PATH)
