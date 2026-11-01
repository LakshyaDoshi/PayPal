"""
gateway.providers.base

Protocol definitions and result models for MandateGate payment providers.
Decoupled from transport and web frameworks.
All monetary amounts are represented as integer minor units (cents).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class PaymentStatus(StrEnum):
    """Normalized lifecycle state of a provider transaction."""

    CREATED = "created"
    PENDING = "pending"
    APPROVED = "approved"
    COMPLETED = "completed"
    FAILED = "failed"


class ProviderPaymentResult(BaseModel):
    """Typed result returned by payment provider operations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_reference: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Provider-side identifier (e.g. PayPal Order ID, Payout Batch ID).",
    )
    status: PaymentStatus = Field(
        ...,
        description="Current normalized status of the transaction.",
    )
    debug_id: str | None = Field(
        default=None,
        max_length=128,
        description="Upstream diagnostic tracing ID (e.g. Paypal-Debug-Id).",
    )
    approval_url: str | None = Field(
        default=None,
        description="Optional redirect URL if the transaction requires buyer approval.",
    )
    raw_details: dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized non-sensitive diagnostic response attributes.",
    )


class ProviderError(Exception):
    """Base exception for payment provider operations. Fails closed."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        debug_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.debug_id = debug_id
        self.details = details or {}


class ProviderAuthError(ProviderError):
    """Authentication or OAuth token acquisition failure."""


class ProviderTimeoutError(ProviderError):
    """Upstream provider request timeout."""


class ProviderConnectionError(ProviderError):
    """Network connection failure communicating with provider."""


@runtime_checkable
class PaymentProvider(Protocol):
    """Protocol implemented by all payment gateways and mock providers."""

    async def create_order(
        self,
        *,
        amount_minor: int,
        currency: str,
        payee: str,
        memo: str,
        idempotency_key: str,
    ) -> ProviderPaymentResult:
        """Create a payment order."""
        ...

    async def pay_invoice(
        self,
        *,
        invoice_id: str,
        amount_minor: int,
        currency: str,
        idempotency_key: str,
    ) -> ProviderPaymentResult:
        """Pay or mark paid an invoice."""
        ...

    async def send_payout(
        self,
        *,
        amount_minor: int,
        currency: str,
        receiver_email: str,
        memo: str,
        idempotency_key: str,
    ) -> ProviderPaymentResult:
        """Disburse funds directly to a recipient."""
        ...
