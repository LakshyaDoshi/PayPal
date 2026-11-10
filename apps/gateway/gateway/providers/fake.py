"""
gateway.providers.fake

Deterministic mock payment provider for unit testing and local development.
Maintains an in-memory audit log of provider calls and allows simulated failure injection.
"""

from __future__ import annotations

from typing import Any

from gateway.providers.base import (
    PaymentProvider,
    PaymentStatus,
    ProviderError,
    ProviderPaymentResult,
)


class FakeProvider(PaymentProvider):
    """Deterministic in-memory payment provider for testing."""

    def __init__(
        self,
        *,
        should_fail: bool = False,
        fail_error: Exception | None = None,
        error_to_raise: Exception | None = None,
    ) -> None:
        self.fail_error = error_to_raise if error_to_raise is not None else fail_error
        self.should_fail = should_fail or (self.fail_error is not None)
        self.calls: list[dict[str, Any]] = []

    @property
    def call_count(self) -> int:
        """Total number of method invocations recorded."""
        return len(self.calls)

    def reset(self) -> None:
        """Clear recorded invocation history."""
        self.calls.clear()

    def _record_and_check_fail(self, method: str, kwargs: dict[str, Any]) -> None:
        self.calls.append({"method": method, **kwargs})
        if self.should_fail:
            if self.fail_error:
                raise self.fail_error
            raise ProviderError(
                f"Simulated failure in FakeProvider.{method}",
                status_code=500,
                debug_id="fake_debug_id",
            )

    async def create_order(
        self,
        *,
        amount_minor: int,
        currency: str,
        payee: str,
        memo: str,
        idempotency_key: str,
    ) -> ProviderPaymentResult:
        kwargs = {
            "amount_minor": amount_minor,
            "currency": currency,
            "payee": payee,
            "memo": memo,
            "idempotency_key": idempotency_key,
        }
        self._record_and_check_fail("create_order", kwargs)

        return ProviderPaymentResult(
            provider_reference=f"fake_ord_{idempotency_key}",
            status=PaymentStatus.CREATED,
            debug_id=f"dbg_fake_{idempotency_key}",
            approval_url=f"https://sandbox.fake.paypal.com/checkout?id=fake_ord_{idempotency_key}",
            raw_details={"mock": True, "amount_minor": amount_minor, "currency": currency},
        )

    async def pay_invoice(
        self,
        *,
        invoice_id: str,
        amount_minor: int,
        currency: str,
        idempotency_key: str,
    ) -> ProviderPaymentResult:
        kwargs = {
            "invoice_id": invoice_id,
            "amount_minor": amount_minor,
            "currency": currency,
            "idempotency_key": idempotency_key,
        }
        self._record_and_check_fail("pay_invoice", kwargs)

        return ProviderPaymentResult(
            provider_reference=f"fake_inv_pay_{invoice_id}",
            status=PaymentStatus.COMPLETED,
            debug_id=f"dbg_inv_{idempotency_key}",
            raw_details={"mock": True, "invoice_id": invoice_id},
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
        kwargs = {
            "amount_minor": amount_minor,
            "currency": currency,
            "receiver_email": receiver_email,
            "memo": memo,
            "idempotency_key": idempotency_key,
        }
        self._record_and_check_fail("send_payout", kwargs)

        return ProviderPaymentResult(
            provider_reference=f"fake_payout_batch_{idempotency_key}",
            status=PaymentStatus.COMPLETED,
            debug_id=f"dbg_payout_{idempotency_key}",
            raw_details={"mock": True, "receiver": receiver_email},
        )
