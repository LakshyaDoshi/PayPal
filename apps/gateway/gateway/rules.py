"""
gateway.rules

Pure deterministic rule engine for MandateGate.
Approval for payments can ONLY originate from this engine.

Safety Invariants:
1. Pure business logic: MUST NOT import FastAPI, Starlette, or MCP.
2. All monetary amounts are integer minor units (never float).
3. FAIL CLOSED: Any check failure results in BLOCK or ESCALATE.
4. APPROVE is returned if and only if EVERY rule explicitly passes.
5. Payee normalization: Unicode NFKC, strip whitespace, casefold. Exact match only.
6. Evaluates:
   - signature_valid
   - not_revoked
   - not_expired
   - currency_matches
   - amount_positive_and_bounded
   - within_budget
   - payee_allowed
   - velocity
   - duplicate
   - needs_human (triggers ESCALATE instead of APPROVE)
"""

from __future__ import annotations

import unicodedata
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field

from gateway.contract import Mandate, PaymentRequest, RuleResult, Verdict
from gateway.mandate import verify


class HistoricalPayment(BaseModel):
    """Record of a previously approved payment for velocity and duplicate tracking."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    payee: str = Field(..., min_length=1, max_length=255)
    amount_minor: int = Field(..., gt=0)
    currency: str = Field(..., min_length=3, max_length=3)
    memo: str = Field(..., min_length=1, max_length=500)
    idempotency_key: str = Field(..., min_length=1, max_length=128)
    created_at: datetime = Field(...)


class RuleContext(BaseModel):
    """Execution context supplied to the deterministic rule engine."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    now: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Current UTC timestamp.",
    )
    revoked: bool = Field(
        default=False,
        description="Whether the mandate has been explicitly revoked.",
    )
    spend_so_far: int = Field(
        default=0,
        ge=0,
        description="Cumulative amount in minor units approved and spent so far.",
    )
    recent_approved_payments: list[HistoricalPayment] = Field(
        default_factory=list,
        description="Historical approved payments for velocity and duplicate detection.",
    )
    duplicate_window_seconds: int = Field(
        default=86400,
        gt=0,
        description="Fallback duplicate window in seconds if mandate window is unset.",
    )


def normalize_payee(payee: str) -> str:
    """Normalize a payee string using Unicode NFKC, strip, and casefold.

    Guarantees exact matching regardless of whitespace padding, letter casing,
    or Unicode fullwidth / compatibility representations.
    """
    return unicodedata.normalize("NFKC", payee).strip().casefold()


# ---------------------------------------------------------------------------
# Individual Rule Evaluators
# ---------------------------------------------------------------------------


def check_signature_valid(mandate: Mandate) -> RuleResult:
    """Verify mandate cryptographic HMAC-SHA256 signature."""
    is_valid = verify(mandate)
    if is_valid:
        return RuleResult(
            name="signature_valid",
            passed=True,
            detail="Mandate cryptographic signature is valid.",
        )
    return RuleResult(
        name="signature_valid",
        passed=False,
        detail="Mandate cryptographic signature is invalid or tampered.",
    )


def check_not_revoked(mandate_id: str, ctx: RuleContext) -> RuleResult:
    """Verify mandate has not been explicitly revoked."""
    if ctx.revoked:
        return RuleResult(
            name="not_revoked",
            passed=False,
            detail=f"Mandate '{mandate_id}' has been revoked.",
        )
    return RuleResult(
        name="not_revoked",
        passed=True,
        detail="Mandate is active and not revoked.",
    )


def check_not_expired(mandate: Mandate, ctx: RuleContext) -> RuleResult:
    """Verify mandate expiration has not passed."""
    if ctx.now >= mandate.expires_at:
        return RuleResult(
            name="not_expired",
            passed=False,
            detail=(
                f"Mandate expired at {mandate.expires_at.isoformat()} "
                f"(current time {ctx.now.isoformat()})."
            ),
        )
    return RuleResult(
        name="not_expired",
        passed=True,
        detail="Mandate is within valid timeframe.",
    )


def check_currency_matches(request: PaymentRequest, mandate: Mandate) -> RuleResult:
    """Verify transaction currency exactly matches the mandate currency."""
    if request.currency.upper() == mandate.currency.upper():
        return RuleResult(
            name="currency_matches",
            passed=True,
            detail=f"Currency matches mandate ({request.currency.upper()}).",
        )
    return RuleResult(
        name="currency_matches",
        passed=False,
        detail=(
            f"Currency mismatch: request has {request.currency.upper()}, "
            f"mandate requires {mandate.currency.upper()}."
        ),
    )


def check_amount_positive_and_bounded(request: PaymentRequest, mandate: Mandate) -> RuleResult:
    """Verify amount is strictly positive and within the maximum single-mandate cap."""
    if request.amount_minor <= 0:
        return RuleResult(
            name="amount_positive_and_bounded",
            passed=False,
            detail=f"Amount must be strictly positive, got {request.amount_minor}.",
        )
    if request.amount_minor > mandate.max_amount_minor:
        return RuleResult(
            name="amount_positive_and_bounded",
            passed=False,
            detail=(
                f"Amount {request.amount_minor} exceeds mandate max cap {mandate.max_amount_minor}."
            ),
        )
    return RuleResult(
        name="amount_positive_and_bounded",
        passed=True,
        detail=f"Amount {request.amount_minor} is positive and bounded by mandate cap.",
    )


def check_within_budget(request: PaymentRequest, mandate: Mandate, ctx: RuleContext) -> RuleResult:
    """Verify requested amount does not exceed the remaining cumulative budget."""
    remaining_budget = mandate.max_amount_minor - ctx.spend_so_far
    if request.amount_minor <= remaining_budget:
        return RuleResult(
            name="within_budget",
            passed=True,
            detail=(
                f"Amount {request.amount_minor} is within remaining budget "
                f"{remaining_budget} (spent so far: {ctx.spend_so_far})."
            ),
        )
    return RuleResult(
        name="within_budget",
        passed=False,
        detail=(
            f"Amount {request.amount_minor} exceeds remaining budget {remaining_budget} "
            f"(spent: {ctx.spend_so_far}, cap: {mandate.max_amount_minor})."
        ),
    )


def check_payee_allowed(request: PaymentRequest, mandate: Mandate) -> RuleResult:
    """Verify payee is explicitly on the allowlist using strict NFKC normalization."""
    normalized_target = normalize_payee(request.payee)
    normalized_allowlist = {normalize_payee(p) for p in mandate.allowed_payees}

    if normalized_target in normalized_allowlist:
        return RuleResult(
            name="payee_allowed",
            passed=True,
            detail=f"Payee '{request.payee}' is authorized.",
        )
    return RuleResult(
        name="payee_allowed",
        passed=False,
        detail=f"Payee '{request.payee}' is not on the authorized allowlist.",
    )


def check_velocity(mandate: Mandate, ctx: RuleContext) -> RuleResult:
    """Verify count of payments does not exceed max_payments_per_window."""
    if mandate.max_payments_per_window is None or mandate.window_seconds is None:
        return RuleResult(
            name="velocity",
            passed=True,
            detail="No velocity limit configured on mandate.",
        )

    cutoff = ctx.now - timedelta(seconds=mandate.window_seconds)
    count = sum(1 for p in ctx.recent_approved_payments if p.created_at >= cutoff)

    if count < mandate.max_payments_per_window:
        return RuleResult(
            name="velocity",
            passed=True,
            detail=(
                f"Velocity within limit: {count}/{mandate.max_payments_per_window} "
                f"payments in {mandate.window_seconds}s window."
            ),
        )
    return RuleResult(
        name="velocity",
        passed=False,
        detail=(
            f"Velocity limit reached: {count}/{mandate.max_payments_per_window} "
            f"payments in {mandate.window_seconds}s window."
        ),
    )


def check_duplicate(request: PaymentRequest, mandate: Mandate, ctx: RuleContext) -> RuleResult:
    """Verify request is not a duplicate transaction or replayed idempotency key in window."""
    window_seconds = (
        mandate.window_seconds
        if mandate.window_seconds is not None
        else ctx.duplicate_window_seconds
    )
    cutoff = ctx.now - timedelta(seconds=window_seconds)
    norm_req_payee = normalize_payee(request.payee)

    for p in ctx.recent_approved_payments:
        if p.created_at >= cutoff:
            if p.idempotency_key == request.idempotency_key:
                return RuleResult(
                    name="duplicate",
                    passed=False,
                    detail=f"Replayed idempotency key '{request.idempotency_key}' in window.",
                )
            if (
                normalize_payee(p.payee) == norm_req_payee
                and p.amount_minor == request.amount_minor
                and p.memo.strip() == request.memo.strip()
            ):
                return RuleResult(
                    name="duplicate",
                    passed=False,
                    detail="Duplicate payment: identical payee, amount, and memo in window.",
                )

    return RuleResult(
        name="duplicate",
        passed=True,
        detail="No duplicate transaction detected in window.",
    )


def check_needs_human(request: PaymentRequest, mandate: Mandate) -> RuleResult:
    """Verify if transaction requires human sign-off based on approval threshold.

    When amount exceeds approval_threshold_minor, this rule fails, signaling
    that the final overall decision must be ESCALATE rather than APPROVE.
    """
    if mandate.approval_threshold_minor is None:
        return RuleResult(
            name="needs_human",
            passed=True,
            detail="No approval threshold configured on mandate.",
        )

    if request.amount_minor > mandate.approval_threshold_minor:
        return RuleResult(
            name="needs_human",
            passed=False,
            detail=(
                f"Amount {request.amount_minor} exceeds approval threshold "
                f"{mandate.approval_threshold_minor}; human escalation required."
            ),
        )

    return RuleResult(
        name="needs_human",
        passed=True,
        detail=(
            f"Amount {request.amount_minor} is within approval threshold "
            f"{mandate.approval_threshold_minor}."
        ),
    )


# ---------------------------------------------------------------------------
# Core Rule Engine Public Interface
# ---------------------------------------------------------------------------


def evaluate(
    request: PaymentRequest,
    mandate: Mandate,
    ctx: RuleContext,
) -> list[RuleResult]:
    """Execute all deterministic rules against the payment request and mandate.

    Returns the ordered list of RuleResult evaluations.
    """
    return [
        check_signature_valid(mandate),
        check_not_revoked(mandate.id, ctx),
        check_not_expired(mandate, ctx),
        check_currency_matches(request, mandate),
        check_amount_positive_and_bounded(request, mandate),
        check_within_budget(request, mandate, ctx),
        check_payee_allowed(request, mandate),
        check_velocity(mandate, ctx),
        check_duplicate(request, mandate, ctx),
        check_needs_human(request, mandate),
    ]


def overall(results: list[RuleResult]) -> Verdict:
    """Determine the final outcome from rule evaluation results.

    Safety Invariants:
    - If ANY blocking rule fails (any rule other than needs_human), return Verdict.BLOCK.
    - If needs_human fails and all other rules pass, return Verdict.ESCALATE.
    - An APPROVE decision may ONLY originate from here when EVERY rule has passed.
    - If results is empty, return Verdict.BLOCK (fail closed).
    """
    if not results:
        return Verdict.BLOCK

    # Check for blocking rule failures
    blocking_failures = [r for r in results if not r.passed and r.name != "needs_human"]
    if blocking_failures:
        return Verdict.BLOCK

    # Check for human escalation requirement
    escalation_needed = any(not r.passed and r.name == "needs_human" for r in results)
    if escalation_needed:
        return Verdict.ESCALATE

    # Every rule must have passed for APPROVE
    if all(r.passed for r in results):
        return Verdict.APPROVE

    return Verdict.BLOCK
