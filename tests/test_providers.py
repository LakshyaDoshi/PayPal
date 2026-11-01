"""
tests/test_providers.py

Unit test suite for MandateGate payment provider layer using respx to mock PayPal API.
Covers FakeProvider, PayPalProvider (token caching, timeout, debug IDs, Orders, Payouts, Invoicing).
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import respx
from gateway.providers.base import (
    PaymentProvider,
    PaymentStatus,
    ProviderAuthError,
    ProviderConnectionError,
    ProviderError,
    ProviderTimeoutError,
)
from gateway.providers.fake import FakeProvider
from gateway.providers.paypal import PayPalProvider

SANDBOX_URL = "https://api-m.sandbox.paypal.com"


# ============================================================================
# FakeProvider Tests
# ============================================================================


@pytest.mark.asyncio
async def test_fake_provider_satisfies_protocol() -> None:
    fake = FakeProvider()
    assert isinstance(fake, PaymentProvider)


@pytest.mark.asyncio
async def test_fake_provider_successful_operations() -> None:
    fake = FakeProvider()

    # Order
    order_res = await fake.create_order(
        amount_minor=1500,
        currency="USD",
        payee="vendor@example.com",
        memo="Testing fake order",
        idempotency_key="idemp_1",
    )
    assert order_res.provider_reference == "fake_ord_idemp_1"
    assert order_res.status == PaymentStatus.CREATED
    assert order_res.debug_id == "dbg_fake_idemp_1"
    assert "https://sandbox.fake.paypal.com" in (order_res.approval_url or "")

    # Payout
    payout_res = await fake.send_payout(
        amount_minor=2000,
        currency="USD",
        receiver_email="receiver@example.com",
        memo="Testing fake payout",
        idempotency_key="idemp_2",
    )
    assert payout_res.provider_reference == "fake_payout_batch_idemp_2"
    assert payout_res.status == PaymentStatus.COMPLETED

    # Invoice
    inv_res = await fake.pay_invoice(
        invoice_id="inv_999",
        amount_minor=500,
        currency="USD",
        idempotency_key="idemp_3",
    )
    assert inv_res.provider_reference == "fake_inv_pay_inv_999"
    assert inv_res.status == PaymentStatus.COMPLETED

    assert len(fake.calls) == 3
    assert fake.calls[0]["method"] == "create_order"
    assert fake.calls[1]["method"] == "send_payout"
    assert fake.calls[2]["method"] == "pay_invoice"


@pytest.mark.asyncio
async def test_fake_provider_simulated_failures() -> None:
    fake = FakeProvider(should_fail=True)
    with pytest.raises(ProviderError, match="Simulated failure"):
        await fake.create_order(
            amount_minor=1000,
            currency="USD",
            payee="vendor@example.com",
            memo="Fail test",
            idempotency_key="fail_1",
        )


# ============================================================================
# PayPalProvider Tests
# ============================================================================


def test_paypal_provider_rejects_live_url() -> None:
    with pytest.raises(ValueError, match="SANDBOX ONLY"):
        PayPalProvider(
            client_id="id",
            client_secret="secret",
            base_url="https://api-m.paypal.com",
        )


@pytest.mark.asyncio
@respx.mock
async def test_paypal_provider_token_caching_and_concurrency() -> None:
    token_route = respx.post(f"{SANDBOX_URL}/v1/oauth2/token").respond(
        status_code=200,
        json={"access_token": "mock_access_token_123", "expires_in": 3600},
        headers={"Paypal-Debug-Id": "token_dbg_001"},
    )

    provider = PayPalProvider(
        client_id="client_id_val",
        client_secret="client_secret_val",
        base_url=SANDBOX_URL,
    )

    # Initial call acquires token
    token1 = await provider.get_valid_access_token()
    assert token1 == "mock_access_token_123"
    assert token_route.call_count == 1

    # Second immediate call reuses cached token (no network hit)
    token2 = await provider.get_valid_access_token()
    assert token2 == "mock_access_token_123"
    assert token_route.call_count == 1

    # Concurrent token fetches share single lock/fetch
    tokens = await asyncio.gather(
        provider.get_valid_access_token(),
        provider.get_valid_access_token(),
        provider.get_valid_access_token(),
    )
    assert all(t == "mock_access_token_123" for t in tokens)
    assert token_route.call_count == 1

    await provider.close()


@pytest.mark.asyncio
@respx.mock
async def test_paypal_provider_create_order_success() -> None:
    respx.post(f"{SANDBOX_URL}/v1/oauth2/token").respond(
        status_code=200,
        json={"access_token": "token_abc", "expires_in": 3600},
        headers={"Paypal-Debug-Id": "dbg_token"},
    )

    order_mock_response = {
        "id": "ORD-123456789",
        "status": "CREATED",
        "links": [
            {
                "href": "https://www.sandbox.paypal.com/checkoutnow?token=ORD-123456789",
                "rel": "payer-action",
                "method": "GET",
            }
        ],
    }

    order_route = respx.post(f"{SANDBOX_URL}/v2/checkout/orders").respond(
        status_code=201,
        json=order_mock_response,
        headers={"Paypal-Debug-Id": "dbg_order_create_99"},
    )

    provider = PayPalProvider(
        client_id="cid",
        client_secret="sec",
        base_url=SANDBOX_URL,
    )

    result = await provider.create_order(
        amount_minor=1250,  # $12.50
        currency="USD",
        payee="merchant@example.com",
        memo="Compute credit purchase",
        idempotency_key="key_ord_1",
    )

    assert result.provider_reference == "ORD-123456789"
    assert result.status == PaymentStatus.CREATED
    assert result.debug_id == "dbg_order_create_99"
    assert "https://www.sandbox.paypal.com/checkoutnow" in (result.approval_url or "")

    # Validate that float was NOT sent; exact minor unit conversion verified
    sent_payload = json.loads(order_route.calls.last.request.read().decode("utf-8"))
    assert sent_payload["purchase_units"][0]["amount"]["value"] == "12.50"
    assert sent_payload["purchase_units"][0]["amount"]["currency_code"] == "USD"
    assert order_route.calls.last.request.headers.get("PayPal-Request-Id") == "key_ord_1"

    await provider.close()


@pytest.mark.asyncio
@respx.mock
async def test_paypal_provider_send_payout_success() -> None:
    respx.post(f"{SANDBOX_URL}/v1/oauth2/token").respond(
        status_code=200,
        json={"access_token": "token_abc", "expires_in": 3600},
    )

    payout_mock_response = {
        "batch_header": {
            "payout_batch_id": "BATCH-PAYOUT-999",
            "batch_status": "SUCCESS",
        }
    }

    payout_route = respx.post(f"{SANDBOX_URL}/v1/payments/payouts").respond(
        status_code=201,
        json=payout_mock_response,
        headers={"Paypal-Debug-Id": "dbg_payout_77"},
    )

    provider = PayPalProvider(
        client_id="cid",
        client_secret="sec",
        base_url=SANDBOX_URL,
    )

    result = await provider.send_payout(
        amount_minor=5000,  # $50.00
        currency="USD",
        receiver_email="receiver@sandbox.com",
        memo="Agent service fee",
        idempotency_key="key_pay_1",
    )

    assert result.provider_reference == "BATCH-PAYOUT-999"
    assert result.status == PaymentStatus.COMPLETED
    assert result.debug_id == "dbg_payout_77"

    sent_body = json.loads(payout_route.calls.last.request.read().decode("utf-8"))
    assert sent_body["items"][0]["amount"]["value"] == "50.00"
    assert sent_body["items"][0]["amount"]["currency"] == "USD"
    assert sent_body["items"][0]["receiver"] == "receiver@sandbox.com"

    await provider.close()


@pytest.mark.asyncio
@respx.mock
async def test_paypal_provider_captures_debug_id_on_failure() -> None:
    respx.post(f"{SANDBOX_URL}/v1/oauth2/token").respond(
        status_code=200,
        json={"access_token": "token_abc", "expires_in": 3600},
    )

    error_response = {
        "name": "FEATURE_NOT_ENABLED_FOR_MERCHANT",
        "message": "User is not allowed to pay using this payment method.",
        "debug_id": "dbg_fail_error_payload",
    }

    respx.post(f"{SANDBOX_URL}/v1/payments/payouts").respond(
        status_code=403,
        json=error_response,
        headers={"Paypal-Debug-Id": "dbg_fail_header_123"},
    )

    provider = PayPalProvider(
        client_id="cid",
        client_secret="sec",
        base_url=SANDBOX_URL,
    )

    with pytest.raises(ProviderError) as exc_info:
        await provider.send_payout(
            amount_minor=1000,
            currency="USD",
            receiver_email="rec@example.com",
            memo="Test fail",
            idempotency_key="key_err_1",
        )

    err = exc_info.value
    assert err.status_code == 403
    assert err.debug_id == "dbg_fail_header_123"
    assert "FEATURE_NOT_ENABLED_FOR_MERCHANT" in str(err)

    await provider.close()


@pytest.mark.asyncio
@respx.mock
async def test_paypal_provider_handles_timeout() -> None:
    respx.post(f"{SANDBOX_URL}/v1/oauth2/token").respond(
        status_code=200,
        json={"access_token": "token_abc", "expires_in": 3600},
    )

    respx.post(f"{SANDBOX_URL}/v2/checkout/orders").mock(
        side_effect=httpx.TimeoutException("Upstream timeout")
    )

    provider = PayPalProvider(
        client_id="cid",
        client_secret="sec",
        base_url=SANDBOX_URL,
    )

    with pytest.raises(ProviderTimeoutError, match="Timeout calling PayPal"):
        await provider.create_order(
            amount_minor=1000,
            currency="USD",
            payee="merchant@example.com",
            memo="Timeout test",
            idempotency_key="timeout_key",
        )

    await provider.close()


@pytest.mark.asyncio
@respx.mock
async def test_paypal_provider_handles_connection_error() -> None:
    respx.post(f"{SANDBOX_URL}/v1/oauth2/token").mock(side_effect=httpx.ConnectError("DNS failure"))

    provider = PayPalProvider(
        client_id="cid",
        client_secret="sec",
        base_url=SANDBOX_URL,
    )

    with pytest.raises(ProviderConnectionError, match="Connection failure"):
        await provider.get_valid_access_token()

    await provider.close()


@pytest.mark.asyncio
@respx.mock
async def test_paypal_provider_auth_failure() -> None:
    respx.post(f"{SANDBOX_URL}/v1/oauth2/token").respond(
        status_code=401,
        json={"error": "invalid_client", "error_description": "Client Authentication failed"},
        headers={"Paypal-Debug-Id": "auth_fail_debug_id"},
    )

    provider = PayPalProvider(
        client_id="bad_id",
        client_secret="bad_secret",
        base_url=SANDBOX_URL,
    )

    with pytest.raises(ProviderAuthError) as exc_info:
        await provider.get_valid_access_token()

    err = exc_info.value
    assert err.status_code == 401
    assert err.debug_id == "auth_fail_debug_id"

    await provider.close()
