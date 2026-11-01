"""
gateway.mandate

Mandate signing and verification using HMAC-SHA256.

Canonical form: sorted-key, compact JSON (no spaces), UTF-8 bytes, with the
``signature`` field excluded.  A mandate is signed by computing:

    sig = HMAC-SHA256(MANDATE_SIGNING_KEY, canonical_bytes).hexdigest()

Verification uses ``hmac.compare_digest`` to prevent timing attacks.

Startup guard: the module raises ``RuntimeError`` at import time if
``MANDATE_SIGNING_KEY`` is missing or shorter than 32 bytes.

Invariants
----------
- No FastAPI / MCP imports.
- No float usage.
- No secrets printed or logged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from gateway.contract import Mandate

# ---------------------------------------------------------------------------
# Startup key guard
# ---------------------------------------------------------------------------

_RAW_KEY: str = os.environ.get("MANDATE_SIGNING_KEY", "")

if not _RAW_KEY:
    raise RuntimeError(
        "MANDATE_SIGNING_KEY environment variable is not set. "
        "MandateGate cannot start without a signing key."
    )

if len(_RAW_KEY) < 32:
    raise RuntimeError(
        f"MANDATE_SIGNING_KEY is too short ({len(_RAW_KEY)} chars). "
        "Minimum length is 32 characters."
    )

# Keep the encoded key in memory; never log or expose the raw string.
_SIGNING_KEY: bytes = _RAW_KEY.encode("utf-8")

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_EXCLUDE_FIELDS: frozenset[str] = frozenset({"signature"})


def _canonical_bytes(data: dict[str, Any]) -> bytes:
    """Return deterministic, compact, UTF-8 JSON bytes with sorted keys.

    The ``signature`` field is excluded before serialisation so the same
    canonical form is produced whether or not the mandate is already signed.
    """
    filtered = {k: v for k, v in data.items() if k not in _EXCLUDE_FIELDS}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _compute_hmac(payload: bytes) -> str:
    """Compute HMAC-SHA256 over *payload* using the module signing key."""
    return hmac.new(_SIGNING_KEY, payload, hashlib.sha256).hexdigest()


def canonical_dict(mandate: Mandate) -> dict[str, Any]:
    """Return the mandate as a plain dict, suitable for canonical serialisation.

    Datetime objects are converted to ISO 8601 strings so the JSON is
    deterministic across platforms.
    """
    raw = mandate.model_dump(mode="json")
    # Pydantic mode="json" already serialises datetimes to ISO strings.
    return raw


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sign(mandate_draft: Mandate) -> Mandate:
    """Compute a fresh HMAC-SHA256 signature and return a new signed Mandate.

    The *mandate_draft* may already carry a placeholder or empty signature
    field (Pydantic requires the field); it is ignored during signing.

    Returns a new ``Mandate`` instance (immutable) with the computed signature.
    """
    data = canonical_dict(mandate_draft)
    payload = _canonical_bytes(data)
    sig = _compute_hmac(payload)
    # Pydantic Mandate is frozen; construct a fresh copy with the real sig.
    return mandate_draft.model_copy(update={"signature": sig})


def verify(mandate: Mandate) -> bool:
    """Return ``True`` if the mandate's HMAC-SHA256 signature is valid.

    Uses ``hmac.compare_digest`` to prevent timing side-channel attacks.
    Returns ``False`` (never raises) on any verification failure so callers
    can cleanly map the result to BLOCK without exception handling overhead.
    """
    try:
        data = canonical_dict(mandate)
        payload = _canonical_bytes(data)
        expected = _compute_hmac(payload)
        return hmac.compare_digest(expected, mandate.signature)
    except Exception:  # noqa: BLE001
        return False


def is_expired(mandate: Mandate) -> bool:
    """Return ``True`` if the mandate's expiry has passed (UTC now)."""
    from datetime import UTC, datetime

    return datetime.now(UTC) >= mandate.expires_at
