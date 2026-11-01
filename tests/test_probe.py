"""
tests/test_probe.py

Unit tests for scripts/paypal_probe.py components and diagnostic parsing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import respx

from scripts.paypal_probe import PayPalProbe, extract_debug_id, load_env_file

SANDBOX_URL = "https://api-m.sandbox.paypal.com"


def test_extract_debug_id() -> None:
    mock_resp = type(
        "MockResp",
        (),
        {"headers": {"Paypal-Debug-Id": "header_debug_id_123"}},
    )()
    assert extract_debug_id(mock_resp) == "header_debug_id_123"  # type: ignore[arg-type]
    assert extract_debug_id(None, {"debug_id": "body_debug_id_456"}) == "body_debug_id_456"
    assert extract_debug_id(None, None) == "N/A"


def test_load_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# Comment line\nPAYPAL_CLIENT_ID=test_id\nPAYPAL_CLIENT_SECRET='test_sec'\n",
        encoding="utf-8",
    )
    loaded = load_env_file(env_file)
    assert loaded["PAYPAL_CLIENT_ID"] == "test_id"
    assert loaded["PAYPAL_CLIENT_SECRET"] == "test_sec"


@pytest.mark.asyncio
@respx.mock
async def test_probe_runs_steps_with_mocks() -> None:
    # 1. Token
    respx.post(f"{SANDBOX_URL}/v1/oauth2/token").respond(
        status_code=200,
        json={"access_token": "probe_token_123", "expires_in": 3600},
        headers={"Paypal-Debug-Id": "token_dbg"},
    )
    # 2. Orders
    respx.post(f"{SANDBOX_URL}/v2/checkout/orders").respond(
        status_code=201,
        json={
            "id": "ORD-PROBE-1",
            "status": "CREATED",
            "links": [{"href": "https://approve", "rel": "payer-action"}],
        },
        headers={"Paypal-Debug-Id": "ord_dbg"},
    )
    # 3. Payouts
    respx.post(f"{SANDBOX_URL}/v1/payments/payouts").respond(
        status_code=201,
        json={"batch_header": {"payout_batch_id": "BATCH-1", "batch_status": "SUCCESS"}},
        headers={"Paypal-Debug-Id": "pay_dbg"},
    )
    # 4. Invoicing
    respx.post(f"{SANDBOX_URL}/v2/invoicing/invoices").respond(
        status_code=201,
        json={"id": "INV-1", "href": "https://invoices/INV-1"},
        headers={"Paypal-Debug-Id": "inv_create_dbg"},
    )
    respx.post(f"{SANDBOX_URL}/v2/invoicing/invoices/INV-1/send").respond(
        status_code=204,
        headers={"Paypal-Debug-Id": "inv_send_dbg"},
    )

    probe = PayPalProbe(
        client_id="cid",
        client_secret="csec",
        base_url=SANDBOX_URL,
        receiver_email="receiver@example.com",
    )

    await probe.run_probe()

    assert len(probe.results) == 4
    assert probe.results[0]["status"] == "PASS"
    assert probe.results[1]["status"] == "PASS"
    assert "BUYER APPROVAL REQUIRED" in probe.results[1]["cause"]
    assert probe.results[2]["status"] == "PASS"
    assert "ZERO BROWSER STEPS NEEDED" in probe.results[2]["cause"]
    assert probe.results[3]["status"] == "PASS"
