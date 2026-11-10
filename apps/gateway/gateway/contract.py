"""
gateway.contract

Shared Pydantic v2 domain models and contracts for MandateGate.
All monetary amounts are strictly represented as integer minor units (cents).
Floating-point numbers are strictly forbidden.

Invariants:
- Integer minor units only (no float).
- ISO 4217 currency validation.
- Bounded string lengths on all fields.
- Forbid extra fields.
- UTC datetimes only.
- Pure Python & Pydantic (no FastAPI or MCP framework leakage).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

# ISO 4217 3-letter currency regex (uppercase alphabetic)
ISO_4217_REGEX = re.compile(r"^[A-Z]{3}$")

# Recognized common ISO currency codes for additional validation
COMMON_ISO_CURRENCIES = {
    "USD",
    "EUR",
    "GBP",
    "CAD",
    "AUD",
    "JPY",
    "CHF",
    "CNY",
    "INR",
    "NZD",
    "SGD",
    "HKD",
    "SEK",
    "NOK",
    "DKK",
    "PLN",
    "BRL",
    "MXN",
    "ILS",
    "ZAR",
}


def _validate_currency(v: str) -> str:
    """Validates that a currency code is a valid 3-letter uppercase ISO 4217 string."""
    v_upper = v.strip().upper()
    if not ISO_4217_REGEX.match(v_upper):
        raise ValueError(
            f"Invalid currency code '{v}'. Must be a 3-letter uppercase ISO 4217 code (e.g. 'USD')."
        )
    return v_upper


def _reject_float_for_money(v: Any, field_name: str) -> Any:
    """Strictly reject floating-point numbers for financial amounts."""
    if isinstance(v, float):
        raise ValueError(
            f"Floating-point values are strictly prohibited for {field_name}. "
            "Use integer minor units (e.g. cents) exclusively."
        )
    return v


def _ensure_utc_datetime(v: Any) -> datetime:
    """Validates that a datetime is timezone-aware and normalized to UTC."""
    if isinstance(v, str):
        # Let Pydantic parse string first if called in before validator, or parse manually
        try:
            # Replace trailing 'Z' if present for standard fromisoformat compatibility
            clean_str = v.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_str)
        except Exception as e:
            raise ValueError(f"Invalid ISO 8601 datetime format: {e}") from e
    elif isinstance(v, datetime):
        dt = v
    else:
        raise ValueError("Value must be a valid ISO 8601 datetime string or datetime object.")

    if dt.tzinfo is None:
        raise ValueError(
            "Datetime must be timezone-aware (UTC). Naive datetimes are not permitted."
        )
    return dt.astimezone(UTC)


class Verdict(StrEnum):
    """Decision verdict produced by the MandateGate policy engine."""

    APPROVE = "approve"
    BLOCK = "block"
    ESCALATE = "escalate"


class RuleResult(BaseModel):
    """Result of a single deterministic mandate policy or security rule check."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Identifier of the rule executed (e.g. 'budget_limit', 'payee_allowlist').",
    )
    passed: bool = Field(
        ...,
        description="Whether the rule evaluation succeeded.",
    )
    detail: str = Field(
        default="",
        max_length=1000,
        description="Diagnostic explanation or context regarding the evaluation outcome.",
    )


class Mandate(BaseModel):
    """
    Authorized spending policy defining constraints for agent payments.
    Amounts must be integer minor units (e.g. USD cents).
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Unique identifier for the mandate.",
    )
    purpose: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="The user's original task text and authorization scope.",
    )
    max_amount_minor: int = Field(
        ...,
        gt=0,
        description="Total lifetime spending cap allowed by this mandate in minor units (cents).",
    )
    currency: str = Field(
        ...,
        min_length=3,
        max_length=3,
        description="3-letter ISO 4217 currency code (e.g. 'USD').",
    )
    allowed_payees: list[str] = Field(
        ...,
        min_length=1,
        description="List of permitted payee identifiers (emails or merchant IDs).",
    )
    expires_at: datetime = Field(
        ...,
        description="UTC expiration timestamp of the mandate.",
    )
    approval_threshold_minor: int | None = Field(
        default=None,
        gt=0,
        description="Optional minor threshold requiring human review.",
    )
    max_payments_per_window: int | None = Field(
        default=None,
        gt=0,
        description="Optional maximum count of payments allowed in a velocity window.",
    )
    window_seconds: int | None = Field(
        default=None,
        gt=0,
        description="Optional duration of velocity window in seconds.",
    )
    signature: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Cryptographic signature guaranteeing mandate integrity.",
    )

    @field_validator("max_amount_minor", "approval_threshold_minor", mode="before")
    @classmethod
    def check_non_float_amounts(cls, v: Any, info: Any) -> Any:
        return _reject_float_for_money(v, info.field_name)

    @field_validator("currency", mode="before")
    @classmethod
    def check_currency(cls, v: str) -> str:
        return _validate_currency(v)

    @field_validator("expires_at", mode="before")
    @classmethod
    def check_utc_expiry(cls, v: Any) -> datetime:
        return _ensure_utc_datetime(v)

    @field_validator("allowed_payees", mode="after")
    @classmethod
    def check_payees(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("allowed_payees must contain at least one payee.")
        cleaned: list[str] = []
        for payee in v:
            p_strip = payee.strip()
            if not p_strip:
                raise ValueError("Payee identifier cannot be empty or whitespace.")
            if len(p_strip) > 255:
                raise ValueError("Payee identifier exceeds maximum length of 255 characters.")
            cleaned.append(p_strip)
        return cleaned

    @model_validator(mode="after")
    def validate_mandate_invariants(self) -> Mandate:
        # 1. Approval threshold must not exceed maximum mandate amount
        if (
            self.approval_threshold_minor is not None
            and self.approval_threshold_minor > self.max_amount_minor
        ):
            raise ValueError(
                f"approval_threshold_minor ({self.approval_threshold_minor}) cannot exceed "
                f"max_amount_minor ({self.max_amount_minor})."
            )

        # 2. Velocity window pairing invariant
        has_max = self.max_payments_per_window is not None
        has_window = self.window_seconds is not None
        if has_max != has_window:
            raise ValueError("max_payments_per_window and window_seconds must both be provided.")

        return self


class PaymentRequest(BaseModel):
    """
    Request initiated by an AI agent to execute a payment against an authorized mandate.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    mandate_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Identifier of the mandate authorizing this transaction.",
    )
    payee: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Target recipient identifier (email or merchant ID).",
    )
    amount_minor: int = Field(
        ...,
        gt=0,
        description="Transaction amount in integer minor units (e.g. cents).",
    )
    currency: str = Field(
        ...,
        min_length=3,
        max_length=3,
        description="3-letter ISO 4217 currency code (e.g. 'USD').",
    )
    memo: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Human-readable justification or item description.",
    )
    idempotency_key: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Unique request key to guarantee idempotent execution and prevent replays.",
    )

    @field_validator("amount_minor", mode="before")
    @classmethod
    def check_non_float_amount(cls, v: Any, info: Any) -> Any:
        return _reject_float_for_money(v, info.field_name)

    @field_validator("currency", mode="before")
    @classmethod
    def check_currency(cls, v: str) -> str:
        return _validate_currency(v)

    @field_validator("payee", mode="after")
    @classmethod
    def sanitize_payee(cls, v: str) -> str:
        v_strip = v.strip()
        if not v_strip:
            raise ValueError("payee cannot be empty or whitespace.")
        return v_strip


def build_decision_explanation(
    verdict: Verdict,
    rule_results: list[RuleResult],
    judge_reason: str | None = None,
) -> str:
    """Build a plain-English explanation of a decision from rule results and judge reason."""
    if verdict == Verdict.APPROVE:
        return (
            "Payment approved: all deterministic mandate policies passed "
            "and advisory safety judge raised no objections."
        )

    failed_rules = [r for r in rule_results if not r.passed]
    details: list[str] = [f"{r.name}: {r.detail}" for r in failed_rules]
    if judge_reason:
        details.append(f"judge: {judge_reason}")

    reasons_str = "; ".join(details) if details else "security policy requirements not met"

    if verdict == Verdict.ESCALATE:
        return f"Payment held for human approval: {reasons_str}."

    return f"Payment blocked: {reasons_str}."


class Decision(BaseModel):
    """
    Audit record and enforcement verdict produced for a PaymentRequest.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Unique decision event identifier.",
    )
    verdict: Verdict = Field(
        ...,
        description="Outcome of the evaluation: approve, block, or escalate.",
    )
    rule_results: list[RuleResult] = Field(
        default_factory=list,
        description="Individual rule execution results that determined this verdict.",
    )
    judge_reason: str | None = Field(
        default=None,
        max_length=2000,
        description="Optional explanation provided by the LLM safety judge.",
    )
    explanation: str = Field(
        default="",
        max_length=2000,
        description="Plain-English explanation built from rule results and judge reason.",
    )
    created_at: datetime = Field(
        ...,
        description="UTC timestamp when the decision was rendered.",
    )

    @field_validator("created_at", mode="before")
    @classmethod
    def check_utc_timestamp(cls, v: Any) -> datetime:
        return _ensure_utc_datetime(v)

    @model_validator(mode="after")
    def ensure_explanation(self) -> Decision:
        if not self.explanation:
            auto_exp = build_decision_explanation(
                self.verdict, self.rule_results, self.judge_reason
            )
            object.__setattr__(self, "explanation", auto_exp)
        return self
