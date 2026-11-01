"""
tests/test_mandate_store.py

Tests for gateway.mandate (signing / verification) and gateway.store
(persistence, hash-chained decisions, atomic budget reservation).

Fixtures
--------
- ``signing_env``: patches MANDATE_SIGNING_KEY before importing gateway.mandate.
- ``store``: fresh in-memory MandateStore per test.
- ``signed_mandate``: a valid, signed Mandate for reuse.

Invariants verified
-------------------
- Changing ANY field of a signed mandate fails verify().
- Wrong key fails verify().
- Expired mandate is detectable via is_expired().
- Revocation is recorded and is_revoked() returns True.
- Two threads racing to spend the last cents: exactly one succeeds.
- Tampering with any decision log row is detected by verify_chain().
"""

from __future__ import annotations

import os
import threading
from datetime import UTC, datetime, timedelta

import pytest

# ---------------------------------------------------------------------------
# Environment bootstrap — must happen before importing gateway.mandate
# because it reads MANDATE_SIGNING_KEY at module level.
# ---------------------------------------------------------------------------

VALID_KEY = "a" * 32  # exactly 32 chars — minimum accepted

os.environ.setdefault("MANDATE_SIGNING_KEY", VALID_KEY)

from gateway.contract import Decision, Mandate, RuleResult, Verdict  # noqa: E402
from gateway.mandate import is_expired, sign, verify  # noqa: E402
from gateway.store import MandateStore  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FUTURE = datetime.now(UTC) + timedelta(days=30)
_PAST = datetime.now(UTC) - timedelta(seconds=1)


def _make_draft(
    *,
    mandate_id: str = "m-001",
    max_amount_minor: int = 10000,
    expires_at: datetime = _FUTURE,
    allowed_payees: list[str] | None = None,
) -> Mandate:
    return Mandate(
        id=mandate_id,
        purpose="Pay approved vendors for tooling.",
        max_amount_minor=max_amount_minor,
        currency="USD",
        allowed_payees=allowed_payees or ["vendor@example.com"],
        expires_at=expires_at,
        signature="placeholder",
    )


def _make_decision(
    decision_id: str = "d-001",
    verdict: Verdict = Verdict.APPROVE,
) -> Decision:
    return Decision(
        id=decision_id,
        verdict=verdict,
        rule_results=[RuleResult(name="budget_limit", passed=True, detail="ok")],
        judge_reason=None,
        created_at=datetime.now(UTC),
    )


@pytest.fixture()
def store() -> MandateStore:
    """Fresh in-memory store per test."""
    return MandateStore(db_path=":memory:")


@pytest.fixture()
def signed_mandate() -> Mandate:
    return sign(_make_draft())


# ===========================================================================
# mandate.py — signing and verification
# ===========================================================================


class TestMandateSigning:
    def test_sign_produces_valid_mandate(self) -> None:
        draft = _make_draft()
        m = sign(draft)
        assert m.signature != "placeholder"
        assert len(m.signature) == 64  # HMAC-SHA256 hex digest

    def test_verify_accepts_correctly_signed_mandate(self, signed_mandate: Mandate) -> None:
        assert verify(signed_mandate) is True

    def test_changing_id_fails_verification(self, signed_mandate: Mandate) -> None:
        tampered = signed_mandate.model_copy(update={"id": "evil-id"})
        assert verify(tampered) is False

    def test_changing_purpose_fails_verification(self, signed_mandate: Mandate) -> None:
        tampered = signed_mandate.model_copy(update={"purpose": "Pay anyone anything."})
        assert verify(tampered) is False

    def test_changing_max_amount_fails_verification(self, signed_mandate: Mandate) -> None:
        tampered = signed_mandate.model_copy(update={"max_amount_minor": 999_999_999})
        assert verify(tampered) is False

    def test_changing_currency_fails_verification(self, signed_mandate: Mandate) -> None:
        tampered = signed_mandate.model_copy(update={"currency": "EUR"})
        assert verify(tampered) is False

    def test_changing_allowed_payees_fails_verification(self, signed_mandate: Mandate) -> None:
        tampered = signed_mandate.model_copy(update={"allowed_payees": ["evil@hacker.com"]})
        assert verify(tampered) is False

    def test_changing_expires_at_fails_verification(self, signed_mandate: Mandate) -> None:
        new_expiry = _FUTURE + timedelta(days=365)
        tampered = signed_mandate.model_copy(update={"expires_at": new_expiry})
        assert verify(tampered) is False

    def test_wrong_key_fails_verification(self, signed_mandate: Mandate) -> None:
        """Simulate a different key environment — sign with one key, verify env has another."""
        import hashlib
        import hmac
        import json

        wrong_key = b"b" * 32

        # Recompute signature with wrong key
        data = signed_mandate.model_dump(mode="json")
        data.pop("signature", None)
        payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        wrong_sig = hmac.new(wrong_key, payload, hashlib.sha256).hexdigest()

        tampered = signed_mandate.model_copy(update={"signature": wrong_sig})
        # verify() uses the module-level _SIGNING_KEY (VALID_KEY), not wrong_key
        assert verify(tampered) is False

    def test_corrupted_signature_string_fails(self, signed_mandate: Mandate) -> None:
        tampered = signed_mandate.model_copy(update={"signature": "deadbeef" * 8})
        assert verify(tampered) is False

    def test_sign_is_deterministic(self) -> None:
        draft = _make_draft()
        m1 = sign(draft)
        m2 = sign(draft)
        assert m1.signature == m2.signature

    def test_different_mandates_produce_different_signatures(self) -> None:
        m1 = sign(_make_draft(max_amount_minor=100))
        m2 = sign(_make_draft(max_amount_minor=200))
        assert m1.signature != m2.signature


class TestMandateExpiry:
    def test_future_mandate_is_not_expired(self) -> None:
        m = sign(_make_draft(expires_at=_FUTURE))
        assert is_expired(m) is False

    def test_past_mandate_is_expired(self) -> None:
        m = sign(_make_draft(expires_at=_PAST))
        assert is_expired(m) is True


# ===========================================================================
# store.py — persistence
# ===========================================================================


class TestMandatePersistence:
    def test_save_and_load_mandate(self, store: MandateStore, signed_mandate: Mandate) -> None:
        store.save_mandate(signed_mandate)
        loaded = store.load_mandate(signed_mandate.id)
        assert loaded is not None
        assert loaded.id == signed_mandate.id
        assert loaded.signature == signed_mandate.signature

    def test_load_nonexistent_returns_none(self, store: MandateStore) -> None:
        assert store.load_mandate("does-not-exist") is None

    def test_is_revoked_false_by_default(
        self, store: MandateStore, signed_mandate: Mandate
    ) -> None:
        store.save_mandate(signed_mandate)
        assert store.is_revoked(signed_mandate.id) is False

    def test_revoke_mandate_marks_revoked(
        self, store: MandateStore, signed_mandate: Mandate
    ) -> None:
        store.save_mandate(signed_mandate)
        store.revoke_mandate(signed_mandate.id, reason="Test revocation")
        assert store.is_revoked(signed_mandate.id) is True

    def test_revoked_mandate_excluded_from_reserve_spend(
        self, store: MandateStore, signed_mandate: Mandate
    ) -> None:
        store.save_mandate(signed_mandate)
        store.revoke_mandate(signed_mandate.id)
        with pytest.raises(ValueError, match="not found or has been revoked"):
            store.reserve_spend(
                mandate_id=signed_mandate.id,
                decision_id="d-x",
                amount_minor=100,
                currency="USD",
            )

    def test_reset_clears_all_tables(self, store: MandateStore, signed_mandate: Mandate) -> None:
        store.save_mandate(signed_mandate)
        store.save_decision(_make_decision(), mandate_id=signed_mandate.id)
        store.reset()
        assert store.load_mandate(signed_mandate.id) is None
        assert store.verify_chain() is None  # empty chain is intact


# ===========================================================================
# store.py — decision hash chain
# ===========================================================================


class TestDecisionHashChain:
    def _populate_chain(
        self, store: MandateStore, mandate: Mandate, count: int = 3
    ) -> list[Decision]:
        decisions = [_make_decision(f"d-{i}") for i in range(count)]
        for d in decisions:
            store.save_decision(d, mandate_id=mandate.id)
        return decisions

    def test_intact_chain_returns_none(self, store: MandateStore, signed_mandate: Mandate) -> None:
        store.save_mandate(signed_mandate)
        self._populate_chain(store, signed_mandate, 5)
        assert store.verify_chain() is None

    def test_empty_chain_returns_none(self, store: MandateStore) -> None:
        assert store.verify_chain() is None

    def test_tampered_json_blob_detected(
        self, store: MandateStore, signed_mandate: Mandate
    ) -> None:
        store.save_mandate(signed_mandate)
        self._populate_chain(store, signed_mandate, 3)

        # Directly mutate the second row's json_blob to simulate tampering.
        store._conn.execute(
            "UPDATE decisions SET json_blob = json_blob || 'TAMPERED' WHERE id = 'd-1'"
        )
        store._conn.commit()

        broken_id = store.verify_chain()
        assert broken_id == "d-1"

    def test_tampered_hash_detected(self, store: MandateStore, signed_mandate: Mandate) -> None:
        store.save_mandate(signed_mandate)
        self._populate_chain(store, signed_mandate, 3)

        # Corrupt the stored hash of row d-0 — this breaks both d-0 (wrong
        # hash) and d-1 (prev_hash mismatch). The first broken row is d-0.
        store._conn.execute(
            "UPDATE decisions SET hash = 'deadbeef' || substr(hash, 9) WHERE id = 'd-0'"
        )
        store._conn.commit()

        broken_id = store.verify_chain()
        assert broken_id == "d-0"

    def test_tampered_prev_hash_detected(
        self, store: MandateStore, signed_mandate: Mandate
    ) -> None:
        store.save_mandate(signed_mandate)
        self._populate_chain(store, signed_mandate, 3)

        # Tamper with d-1's prev_hash — chain link from d-0 → d-1 breaks.
        store._conn.execute(
            "UPDATE decisions SET prev_hash = 'aaaa' || substr(prev_hash, 5) WHERE id = 'd-1'"
        )
        store._conn.commit()

        broken_id = store.verify_chain()
        assert broken_id == "d-1"

    def test_chain_reports_first_broken_row(
        self, store: MandateStore, signed_mandate: Mandate
    ) -> None:
        """Tamper the LAST row; verify_chain reports only that one."""
        store.save_mandate(signed_mandate)
        self._populate_chain(store, signed_mandate, 4)

        store._conn.execute("UPDATE decisions SET json_blob = json_blob || 'X' WHERE id = 'd-3'")
        store._conn.commit()

        assert store.verify_chain() == "d-3"


# ===========================================================================
# store.py — atomic budget reservation
# ===========================================================================


class TestReserveSpend:
    def test_basic_reservation_succeeds(self, store: MandateStore, signed_mandate: Mandate) -> None:
        store.save_mandate(signed_mandate)
        ok = store.reserve_spend("m-001", "d-001", 500, "USD")
        assert ok is True
        assert store.total_spent("m-001") == 500

    def test_reservation_fails_when_budget_exhausted(
        self, store: MandateStore, signed_mandate: Mandate
    ) -> None:
        # signed_mandate has max_amount_minor = 10000
        store.save_mandate(signed_mandate)
        assert store.reserve_spend("m-001", "d-001", 10000, "USD") is True
        assert store.reserve_spend("m-001", "d-002", 1, "USD") is False
        assert store.total_spent("m-001") == 10000

    def test_reservation_fails_for_oversized_single_payment(
        self, store: MandateStore, signed_mandate: Mandate
    ) -> None:
        store.save_mandate(signed_mandate)
        assert store.reserve_spend("m-001", "d-001", 99999, "USD") is False
        assert store.total_spent("m-001") == 0

    def test_currency_mismatch_raises(self, store: MandateStore, signed_mandate: Mandate) -> None:
        store.save_mandate(signed_mandate)
        with pytest.raises(RuntimeError, match="Currency mismatch"):
            store.reserve_spend("m-001", "d-001", 100, "EUR")

    def test_negative_amount_raises(self, store: MandateStore, signed_mandate: Mandate) -> None:
        store.save_mandate(signed_mandate)
        with pytest.raises(ValueError, match="must be positive"):
            store.reserve_spend("m-001", "d-001", -1, "USD")

    def test_zero_amount_raises(self, store: MandateStore, signed_mandate: Mandate) -> None:
        store.save_mandate(signed_mandate)
        with pytest.raises(ValueError, match="must be positive"):
            store.reserve_spend("m-001", "d-001", 0, "USD")

    def test_missing_mandate_raises(self, store: MandateStore) -> None:
        with pytest.raises(ValueError, match="not found"):
            store.reserve_spend("ghost", "d-001", 100, "USD")

    def test_concurrent_race_exactly_one_succeeds(self) -> None:
        """Two threads race to spend the last 100 cents — exactly one wins.

        Each thread uses its own MandateStore (own connection + own lock).
        They race at the SQLite BEGIN IMMEDIATE layer: one blocks until the
        other commits, then sees the budget gone and returns False.
        """
        import os as _os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        # Bootstrap: use one store to create the schema and mandate.
        bootstrap = MandateStore(db_path=db_path)
        mandate = sign(_make_draft(mandate_id="m-race", max_amount_minor=100))
        bootstrap.save_mandate(mandate)
        bootstrap.close()

        results: list[bool] = []
        errors: list[Exception] = []
        barrier = threading.Barrier(2)

        def attempt(decision_id: str) -> None:
            # Each thread owns its own store (independent connection + lock).
            s = MandateStore(db_path=db_path)
            barrier.wait()  # both threads start simultaneously
            try:
                ok = s.reserve_spend(mandate.id, decision_id, 100, "USD")
                results.append(ok)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
            finally:
                s.close()

        t1 = threading.Thread(target=attempt, args=("d-race-1",))
        t2 = threading.Thread(target=attempt, args=("d-race-2",))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        assert not errors, f"Unexpected exceptions during race: {errors}"
        assert len(results) == 2
        # Exactly one True (success) and one False (budget exhausted)
        assert results.count(True) == 1
        assert results.count(False) == 1

        # Verify via a fresh store
        verifier = MandateStore(db_path=db_path)
        assert verifier.total_spent(mandate.id) == 100
        verifier.close()

        _os.unlink(db_path)

    def test_multiple_sequential_spends_accumulate(
        self, store: MandateStore, signed_mandate: Mandate
    ) -> None:
        store.save_mandate(signed_mandate)
        assert store.reserve_spend("m-001", "d-001", 3000, "USD") is True
        assert store.reserve_spend("m-001", "d-002", 3000, "USD") is True
        assert store.reserve_spend("m-001", "d-003", 3000, "USD") is True
        assert store.total_spent("m-001") == 9000
        # One cent more than remaining 1000 → fails
        assert store.reserve_spend("m-001", "d-004", 1001, "USD") is False
        # Exactly the remaining 1000 → succeeds
        assert store.reserve_spend("m-001", "d-005", 1000, "USD") is True
        assert store.total_spent("m-001") == 10000


# ===========================================================================
# store.py — pending approvals
# ===========================================================================


class TestPendingApprovals:
    def test_save_and_list_pending(self, store: MandateStore, signed_mandate: Mandate) -> None:
        store.save_mandate(signed_mandate)
        decision = _make_decision(verdict=Verdict.ESCALATE)
        store.save_decision(decision, signed_mandate.id)
        store.save_pending_approval(
            approval_id="pa-001",
            decision_id=decision.id,
            mandate_id=signed_mandate.id,
            amount_minor=5000,
            currency="USD",
            payee="vendor@example.com",
            memo="API subscription",
        )
        pending = store.list_pending_approvals()
        assert len(pending) == 1
        assert pending[0]["id"] == "pa-001"

    def test_resolve_pending_removes_from_list(
        self, store: MandateStore, signed_mandate: Mandate
    ) -> None:
        store.save_mandate(signed_mandate)
        decision = _make_decision(verdict=Verdict.ESCALATE)
        store.save_decision(decision, signed_mandate.id)
        store.save_pending_approval(
            approval_id="pa-002",
            decision_id=decision.id,
            mandate_id=signed_mandate.id,
            amount_minor=1000,
            currency="USD",
            payee="vendor@example.com",
            memo="Tooling",
        )
        store.resolve_pending_approval("pa-002", "approved")
        assert store.list_pending_approvals() == []
