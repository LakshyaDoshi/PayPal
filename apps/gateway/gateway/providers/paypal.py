"""
gateway.providers.paypal

Production-grade PayPal Sandbox provider implementation using httpx.
Features:
- OAuth client-credentials flow with thread-safe in-memory caching and proactive refresh.
- Enforced request timeouts on every upstream network call.
- PayPal-Debug-Id header capture on all responses and errors.
- Strict minor unit formatting (cents to string via integer division, NO float arithmetic).
- Fail-closed error handling mapping to typed ProviderError hierarchy.
- Zero secret logging and sanitized diagnostic traces.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from gateway.providers.base import (
    PaymentProvider,
    PaymentStatus,
    ProviderAuthError,
    ProviderConnectionError,
    ProviderError,
    ProviderPaymentResult,
    ProviderTimeoutError,
)

logger = logging.getLogger("gateway.providers.paypal")

SANDBOX_BASE_URL = "https://api-m.sandbox.paypal.com"
LIVE_BASE_URL = "https://api-m.paypal.com"
DEFAULT_TIMEOUT_SECONDS = 15.0
EXPIRY_BUFFER_SECONDS = 120.0


def _minor_units_to_decimal_str(amount_minor: int) -> str:
    """
    Format integer minor units (cents) to a PayPal 2-decimal string.
    Strictly uses integer arithmetic without floating-point conversion.
    """
    if not isinstance(amount_minor, int) or isinstance(amount_minor, bool):
        raise TypeError(f"amount_minor must be an integer, got {type(amount_minor).__name__}")
    if amount_minor <= 0:
        raise ValueError(f"amount_minor must be strictly positive, got {amount_minor}")

    dollars, cents = divmod(amount_minor, 100)
    return f"{dollars}.{cents:02d}"


def _extract_debug_id(
    response: httpx.Response | None, body_data: dict[str, Any] | None = None
) -> str | None:
    """Safely extracts Paypal-Debug-Id from HTTP headers or response body."""
    if response is not None:
        header_val = response.headers.get("paypal-debug-id") or response.headers.get(
            "Paypal-Debug-Id"
        )
        if header_val:
            return header_val.strip()

    if body_data and isinstance(body_data, dict):
        body_val = body_data.get("debug_id") or body_data.get("Paypal-Debug-Id")
        if body_val:
            return str(body_val).strip()

    return None


class PayPalProvider(PaymentProvider):
    """
    PayPal Sandbox Payment Provider.
    Implements OAuth2 token caching, Orders v2, and Payouts v1.
    """

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        base_url: str = SANDBOX_BASE_URL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        clean_base = base_url.rstrip("/")
        if clean_base == LIVE_BASE_URL or "api-m.paypal.com" in clean_base:
            raise ValueError(
                "MandateGate is restricted to SANDBOX ONLY. Live PayPal endpoints are forbidden."
            )

        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = clean_base
        self.timeout = httpx.Timeout(timeout_seconds)

        # In-memory OAuth2 token cache
        self._access_token: str | None = None
        self._token_expires_at: datetime | None = None
        self._token_lock = asyncio.Lock()

        # Shared or custom HTTP client
        self._client = client

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None and not self._client.is_closed:
            return self._client
        self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client

    async def close(self) -> None:
        """Close underlying HTTP client connections."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def get_valid_access_token(self, *, force_refresh: bool = False) -> str:
        """
        Retrieves a valid OAuth2 access token, refreshing if near expiration.
        Thread-safe under async concurrency via token lock.
        """
        async with self._token_lock:
            now = datetime.now(UTC)
            if (
                not force_refresh
                and self._access_token is not None
                and self._token_expires_at is not None
                and now < (self._token_expires_at - timedelta(seconds=EXPIRY_BUFFER_SECONDS))
            ):
                return self._access_token

            # Request new token via client_credentials
            client = await self._get_client()
            token_url = f"{self.base_url}/v1/oauth2/token"

            try:
                resp = await client.post(
                    token_url,
                    auth=(self.client_id, self.client_secret),
                    data={"grant_type": "client_credentials"},
                    headers={"Accept": "application/json"},
                )
            except httpx.TimeoutException as exc:
                raise ProviderTimeoutError(
                    f"Timeout fetching PayPal OAuth token from {token_url}",
                    status_code=None,
                    debug_id=None,
                ) from exc
            except httpx.RequestError as exc:
                raise ProviderConnectionError(
                    f"Connection failure fetching PayPal OAuth token: {exc}",
                    status_code=None,
                    debug_id=None,
                ) from exc

            debug_id = _extract_debug_id(resp)

            if resp.status_code != 200:
                logger.error(
                    "PayPal OAuth token fetch failed [status=%s, debug_id=%s]",
                    resp.status_code,
                    debug_id,
                )
                raise ProviderAuthError(
                    f"PayPal OAuth authorization failed with HTTP {resp.status_code}",
                    status_code=resp.status_code,
                    debug_id=debug_id,
                )

            try:
                payload = resp.json()
            except Exception as exc:
                raise ProviderAuthError(
                    "Malformed JSON in PayPal token response",
                    status_code=resp.status_code,
                    debug_id=debug_id,
                ) from exc

            access_token = payload.get("access_token")
            expires_in = payload.get("expires_in", 32400)

            if not access_token:
                raise ProviderAuthError(
                    "PayPal token response missing access_token",
                    status_code=resp.status_code,
                    debug_id=debug_id,
                )

            self._access_token = access_token
            self._token_expires_at = now + timedelta(seconds=int(expires_in))

            logger.info(
                "Acquired fresh PayPal OAuth token [expires_in=%ss, debug_id=%s]",
                expires_in,
                debug_id,
            )
            return self._access_token

    async def _send_authenticated_request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> tuple[httpx.Response, dict[str, Any]]:
        """
        Sends an authenticated HTTP request with token injection, timeout guard,
        and automatic retry on 401 token expiration.
        """
        token = await self.get_valid_access_token()
        client = await self._get_client()

        req_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if headers:
            req_headers.update(headers)

        url = f"{self.base_url}{path}"

        try:
            resp = await client.request(
                method=method,
                url=url,
                headers=req_headers,
                json=json_body,
            )
        except httpx.TimeoutException as exc:
            raise ProviderTimeoutError(
                f"Timeout calling PayPal {method} {path}",
                status_code=None,
                debug_id=None,
            ) from exc
        except httpx.RequestError as exc:
            raise ProviderConnectionError(
                f"Connection error calling PayPal {method} {path}: {exc}",
                status_code=None,
                debug_id=None,
            ) from exc

        # If token expired on upstream service, refresh and retry once
        if resp.status_code == 401:
            debug_id = _extract_debug_id(resp)
            logger.warning(
                "PayPal returned 401 Unauthorized [debug_id=%s]; refreshing token...",
                debug_id,
            )
            fresh_token = await self.get_valid_access_token(force_refresh=True)
            req_headers["Authorization"] = f"Bearer {fresh_token}"

            try:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=req_headers,
                    json=json_body,
                )
            except httpx.TimeoutException as exc:
                raise ProviderTimeoutError(
                    f"Timeout calling PayPal {method} {path} on retry",
                    status_code=None,
                    debug_id=None,
                ) from exc
            except httpx.RequestError as exc:
                raise ProviderConnectionError(
                    f"Connection error calling PayPal {method} {path} on retry: {exc}",
                    status_code=None,
                    debug_id=None,
                ) from exc

        # Parse JSON payload safely
        try:
            body_data = resp.json() if resp.content else {}
        except Exception:
            body_data = {}

        return resp, body_data

    async def create_order(
        self,
        *,
        amount_minor: int,
        currency: str,
        payee: str,
        memo: str,
        idempotency_key: str,
    ) -> ProviderPaymentResult:
        """
        Create a PayPal Order v2 with intent=CAPTURE.
        Note: Unless payment source is vaulted, Orders require buyer approval.
        """
        decimal_val = _minor_units_to_decimal_str(amount_minor)

        payload = {
            "intent": "CAPTURE",
            "purchase_units": [
                {
                    "reference_id": idempotency_key,
                    "description": memo[:127],
                    "amount": {
                        "currency_code": currency.upper(),
                        "value": decimal_val,
                    },
                    "payee": {
                        "email_address": payee,
                    },
                }
            ],
        }

        headers = {
            "PayPal-Request-Id": idempotency_key,
        }

        resp, data = await self._send_authenticated_request(
            "POST",
            "/v2/checkout/orders",
            headers=headers,
            json_body=payload,
        )

        debug_id = _extract_debug_id(resp, data)
        status_code = resp.status_code

        logger.info(
            "PayPal Orders create returned [status=%s, debug_id=%s]",
            status_code,
            debug_id,
        )

        if status_code == 401:
            raise ProviderAuthError(
                "PayPal authentication failed with HTTP 401 Unauthorized.",
                status_code=status_code,
                debug_id=debug_id,
            )

        if status_code not in (200, 201):
            error_name = data.get("name") or "ORDER_CREATION_FAILED"
            error_msg = data.get("message") or resp.text
            raise ProviderError(
                f"PayPal order creation failed ({error_name}): {error_msg}",
                status_code=status_code,
                debug_id=debug_id,
                details=data,
            )

        order_id = data.get("id") or ""
        if not order_id:
            raise ProviderError(
                "PayPal order response is malformed: missing 'id'.",
                status_code=status_code,
                debug_id=debug_id,
                details=data,
            )
        raw_status = data.get("status", "CREATED").upper()

        status_mapping = {
            "CREATED": PaymentStatus.CREATED,
            "SAVED": PaymentStatus.PENDING,
            "APPROVED": PaymentStatus.APPROVED,
            "COMPLETED": PaymentStatus.COMPLETED,
            "VOIDED": PaymentStatus.FAILED,
        }
        normalized_status = status_mapping.get(raw_status, PaymentStatus.PENDING)

        # Extract buyer approval link if present
        approval_url: str | None = None
        for link in data.get("links", []):
            if link.get("rel") in ("payer-action", "approve"):
                approval_url = link.get("href")
                break

        return ProviderPaymentResult(
            provider_reference=order_id,
            status=normalized_status,
            debug_id=debug_id,
            approval_url=approval_url,
            raw_details={
                "order_status": raw_status,
                "amount_minor": amount_minor,
                "currency": currency,
            },
        )

    async def send_payout(
        self,
        *,
        amount_minor: int,
        currency: str,
        receiver_email: str,
        memo: str,
        idempotency_key: str,
    ) -> ProviderPaymentResult:
        """
        Disburse funds to a recipient via PayPal Batch Payouts v1.
        Merchant-initiated payment that does NOT require buyer browser approval.
        """
        decimal_val = _minor_units_to_decimal_str(amount_minor)

        # Batch ID must be unique per payout batch
        batch_id = f"mg_batch_{idempotency_key[:20]}"

        payload = {
            "sender_batch_header": {
                "sender_batch_id": batch_id,
                "email_subject": "MandateGate Agent Payout",
                "email_message": memo[:250],
            },
            "items": [
                {
                    "recipient_type": "EMAIL",
                    "amount": {
                        "value": decimal_val,
                        "currency": currency.upper(),
                    },
                    "note": memo[:128],
                    "sender_item_id": idempotency_key,
                    "receiver": receiver_email,
                }
            ],
        }

        resp, data = await self._send_authenticated_request(
            "POST",
            "/v1/payments/payouts",
            headers={"PayPal-Request-Id": idempotency_key},
            json_body=payload,
        )

        debug_id = _extract_debug_id(resp, data)
        status_code = resp.status_code

        logger.info(
            "PayPal Payouts returned [status=%s, debug_id=%s]",
            status_code,
            debug_id,
        )

        if status_code == 401:
            raise ProviderAuthError(
                "PayPal authentication failed with HTTP 401 Unauthorized.",
                status_code=status_code,
                debug_id=debug_id,
            )

        if status_code not in (200, 201):
            error_name = data.get("name") or "PAYOUT_FAILED"
            error_msg = data.get("message") or resp.text
            raise ProviderError(
                f"PayPal payout failed ({error_name}): {error_msg}",
                status_code=status_code,
                debug_id=debug_id,
                details=data,
            )

        batch_header = data.get("batch_header", {})
        payout_batch_id = batch_header.get("payout_batch_id") or ""
        if not payout_batch_id:
            raise ProviderError(
                "PayPal payout response is malformed: missing 'payout_batch_id'.",
                status_code=status_code,
                debug_id=debug_id,
                details=data,
            )
        batch_status = batch_header.get("batch_status", "PENDING").upper()

        status_mapping = {
            "PENDING": PaymentStatus.PENDING,
            "PROCESSING": PaymentStatus.PENDING,
            "SUCCESS": PaymentStatus.COMPLETED,
            "CANCELED": PaymentStatus.FAILED,
            "DENIED": PaymentStatus.FAILED,
        }
        normalized_status = status_mapping.get(batch_status, PaymentStatus.PENDING)

        return ProviderPaymentResult(
            provider_reference=payout_batch_id,
            status=normalized_status,
            debug_id=debug_id,
            approval_url=None,
            raw_details={
                "batch_status": batch_status,
                "amount_minor": amount_minor,
                "currency": currency,
                "receiver": receiver_email,
            },
        )

    async def pay_invoice(
        self,
        *,
        invoice_id: str,
        amount_minor: int,
        currency: str,
        idempotency_key: str,
    ) -> ProviderPaymentResult:
        """
        Record or execute external payment for a PayPal invoice.
        PayPal Invoicing v2: /v2/invoicing/invoices/{invoice_id}/payments
        """
        decimal_val = _minor_units_to_decimal_str(amount_minor)

        payload = {
            "method": "OTHER",
            "amount": {
                "currency_code": currency.upper(),
                "value": decimal_val,
            },
            "payment_type": "EXTERNAL",
            "note": "Payment recorded via MandateGate autonomous agent",
        }

        resp, data = await self._send_authenticated_request(
            "POST",
            f"/v2/invoicing/invoices/{invoice_id}/payments",
            headers={"PayPal-Request-Id": idempotency_key},
            json_body=payload,
        )

        debug_id = _extract_debug_id(resp, data)
        status_code = resp.status_code

        logger.info(
            "PayPal Invoice payment returned [status=%s, debug_id=%s]",
            status_code,
            debug_id,
        )

        if status_code == 401:
            raise ProviderAuthError(
                "PayPal authentication failed with HTTP 401 Unauthorized.",
                status_code=status_code,
                debug_id=debug_id,
            )

        if status_code not in (200, 201):
            error_name = data.get("name") or "INVOICE_PAYMENT_FAILED"
            error_msg = data.get("message") or resp.text
            raise ProviderError(
                f"PayPal invoice payment failed ({error_name}): {error_msg}",
                status_code=status_code,
                debug_id=debug_id,
                details=data,
            )

        payment_id = data.get("payment_id")
        if not payment_id:
            raise ProviderError(
                "PayPal invoice payment response is malformed: missing 'payment_id'.",
                status_code=status_code,
                debug_id=debug_id,
                details=data,
            )
        return ProviderPaymentResult(
            provider_reference=payment_id,
            status=PaymentStatus.COMPLETED,
            debug_id=debug_id,
            approval_url=None,
            raw_details={"invoice_id": invoice_id, "amount_minor": amount_minor},
        )
