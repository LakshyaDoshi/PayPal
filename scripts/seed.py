#!/usr/bin/env python3
"""
scripts/seed.py

Create a demo mandate, sign it, persist it to the store, and print a
sanitized summary.  Also resets all tables first so the database starts
from a known-clean state.

Usage
-----
    MANDATE_SIGNING_KEY=<32+ char key> DB_PATH=data/mandategate.db \
        python scripts/seed.py

Environment variables (all loaded from .env if present)
--------------------------------------------------------
MANDATE_SIGNING_KEY   Required. Min 32 chars.
DB_PATH               Optional. Defaults to data/mandategate.db.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Bootstrap: load .env before importing gateway modules that read env at import
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_ENV_FILE = _REPO_ROOT / ".env"

if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if not _line or _line.startswith("#") or "=" not in _line:
            continue
        _key, _, _val = _line.partition("=")
        _key = _key.strip()
        _val = _val.strip().strip('"').strip("'")
        if _key not in os.environ:
            os.environ[_key] = _val

# Ensure gateway package is importable when running as a script.
_GATEWAY_PKG = _REPO_ROOT / "apps" / "gateway"
if str(_GATEWAY_PKG) not in sys.path:
    sys.path.insert(0, str(_GATEWAY_PKG))

# Set a default DB_PATH so the store doesn't use :memory:
if "DB_PATH" not in os.environ:
    _DATA_DIR = _REPO_ROOT / "data"
    _DATA_DIR.mkdir(exist_ok=True)
    os.environ["DB_PATH"] = str(_DATA_DIR / "mandategate.db")

# ---------------------------------------------------------------------------
# Now import gateway modules (they read env at import time)
# ---------------------------------------------------------------------------

from gateway.contract import Mandate  # noqa: E402
from gateway.mandate import sign  # noqa: E402
from gateway.store import open_store  # noqa: E402

# ---------------------------------------------------------------------------
# Demo mandate definition
# ---------------------------------------------------------------------------

_DEMO_MANDATE_ID = "demo-mandate-001"

_DEMO_MANDATE_DRAFT = Mandate(
    id=_DEMO_MANDATE_ID,
    purpose=(
        "Pay up to $500 USD to approved software vendors for API subscriptions "
        "and SaaS tooling during Q4 2026. No single payment may exceed $250."
    ),
    max_amount_minor=50000,  # $500.00 in cents
    currency="USD",
    allowed_payees=[
        "vendor-api@example.com",
        "saas-billing@toolco.example",
    ],
    expires_at=datetime.now(UTC) + timedelta(days=90),
    approval_threshold_minor=25000,  # payments over $250 need human approval
    max_payments_per_window=10,
    window_seconds=86400,  # 10 payments per day
    signature="placeholder",  # will be replaced by sign()
)


def run() -> None:
    print("=== MandateGate Seed Script ===\n")

    store = open_store()

    # Reset all tables.
    print("Resetting database tables...")
    store.reset()
    print("  ✓ All tables cleared.\n")

    # Sign the demo mandate.
    print("Signing demo mandate...")
    mandate: Mandate = sign(_DEMO_MANDATE_DRAFT)
    print(f"  ✓ Mandate '{mandate.id}' signed.")
    print(f"    Signature (first 16 chars): {mandate.signature[:16]}...\n")

    # Persist to store.
    print("Persisting mandate to store...")
    store.save_mandate(mandate)
    print(f"  ✓ Saved to: {store._db_path}\n")

    # Verify round-trip.
    loaded = store.load_mandate(_DEMO_MANDATE_ID)
    assert loaded is not None, "Round-trip load returned None!"
    assert loaded.signature == mandate.signature, "Signature mismatch after load!"
    print("  ✓ Round-trip load verified.\n")

    # Print sanitized summary.
    print("=== Demo Mandate Summary ===")
    print(f"  ID              : {mandate.id}")
    print(f"  Purpose         : {mandate.purpose[:80]}...")
    print(f"  Max amount      : {mandate.max_amount_minor} minor units ({mandate.currency})")
    print(f"  Allowed payees  : {', '.join(mandate.allowed_payees)}")
    print(f"  Expires at      : {mandate.expires_at.isoformat()}")
    print(f"  Threshold       : {mandate.approval_threshold_minor} minor units")
    print(
        f"  Velocity limit  : {mandate.max_payments_per_window} payments / "
        f"{mandate.window_seconds}s"
    )
    print(f"  DB path         : {store._db_path}")
    print("\nSeed complete. ✓")

    store.close()


if __name__ == "__main__":
    run()
