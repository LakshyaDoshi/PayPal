"""
tests/test_contract.py

Comprehensive test suite verifying Pydantic v2 domain model invariants
and validation edge cases for MandateGate contract models.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from gateway.contract import (
    Decision,
    Mandate,
    PaymentRequest,
    RuleResult,
    Verdict,
)
from pydantic import ValidationError


@pytest.fixture
def valid_mandate_payload() -> dict:
    return {
        "id": "man_123456",
        "purpose": "Purchase cloud compute instances for benchmarking",
        "max_amount_minor": 10000,  # $100.00
        "currency": "USD",
        "allowed_payees": ["aws@amazon.com", "billing@cloud.google.com"],
        "expires_at": "2026-12-31T23:59:59Z",
        "approval_threshold_minor": 5000,  # $50.00
        "max_payments_per_window": 5,
        "window_seconds": 3600,
        "signature": "sig_ed25519_abcdef0123456789",
    }


@pytest.fixture
def valid_payment_payload() -> dict:
    return {
        "mandate_id": "man_123456",
        "payee": "aws@amazon.com",
        "amount_minor": 2500,  # $25.00
        "currency": "USD",
        "memo": "EC2 c6i.xlarge hourly compute",
        "idempotency_key": "idemp_step_98765",
    }


# ============================================================================
# Mandate Model Tests
# ============================================================================


def test_mandate_valid_creation(valid_mandate_payload: dict) -> None:
    mandate = Mandate(**valid_mandate_payload)
    assert mandate.id == "man_123456"
    assert mandate.max_amount_minor == 10000
    assert mandate.currency == "USD"
    assert len(mandate.allowed_payees) == 2
    assert mandate.expires_at.tzinfo == UTC
    assert mandate.approval_threshold_minor == 5000
    assert mandate.max_payments_per_window == 5
    assert mandate.window_seconds == 3600


def test_mandate_valid_without_optionals(valid_mandate_payload: dict) -> None:
    del valid_mandate_payload["approval_threshold_minor"]
    del valid_mandate_payload["max_payments_per_window"]
    del valid_mandate_payload["window_seconds"]
    mandate = Mandate(**valid_mandate_payload)
    assert mandate.approval_threshold_minor is None
    assert mandate.max_payments_per_window is None
    assert mandate.window_seconds is None


def test_mandate_rejects_float_max_amount(valid_mandate_payload: dict) -> None:
    valid_mandate_payload["max_amount_minor"] = 100.50
    with pytest.raises(ValidationError, match="Floating-point values are strictly prohibited"):
        Mandate(**valid_mandate_payload)


def test_mandate_rejects_zero_or_negative_amount(valid_mandate_payload: dict) -> None:
    valid_mandate_payload["max_amount_minor"] = 0
    with pytest.raises(ValidationError):
        Mandate(**valid_mandate_payload)

    valid_mandate_payload["max_amount_minor"] = -100
    with pytest.raises(ValidationError):
        Mandate(**valid_mandate_payload)


def test_mandate_rejects_float_approval_threshold(valid_mandate_payload: dict) -> None:
    valid_mandate_payload["approval_threshold_minor"] = 49.99
    with pytest.raises(ValidationError, match="Floating-point values are strictly prohibited"):
        Mandate(**valid_mandate_payload)


def test_mandate_rejects_approval_threshold_exceeding_max(valid_mandate_payload: dict) -> None:
    valid_mandate_payload["max_amount_minor"] = 5000
    valid_mandate_payload["approval_threshold_minor"] = 5001
    with pytest.raises(ValidationError, match="cannot exceed max_amount_minor"):
        Mandate(**valid_mandate_payload)


def test_mandate_rejects_asymmetric_velocity_window(valid_mandate_payload: dict) -> None:
    valid_mandate_payload["max_payments_per_window"] = 5
    valid_mandate_payload["window_seconds"] = None
    with pytest.raises(ValidationError, match="must both be provided"):
        Mandate(**valid_mandate_payload)

    valid_mandate_payload["max_payments_per_window"] = None
    valid_mandate_payload["window_seconds"] = 3600
    with pytest.raises(ValidationError, match="must both be provided"):
        Mandate(**valid_mandate_payload)


def test_mandate_currency_normalization_and_validation(valid_mandate_payload: dict) -> None:
    valid_mandate_payload["currency"] = "usd"
    mandate = Mandate(**valid_mandate_payload)
    assert mandate.currency == "USD"

    valid_mandate_payload["currency"] = "US"  # too short
    with pytest.raises(ValidationError, match="Must be a 3-letter uppercase ISO 4217 code"):
        Mandate(**valid_mandate_payload)

    valid_mandate_payload["currency"] = "USDD"  # too long
    with pytest.raises(ValidationError):
        Mandate(**valid_mandate_payload)

    valid_mandate_payload["currency"] = "U$D"  # non-alpha
    with pytest.raises(ValidationError):
        Mandate(**valid_mandate_payload)


def test_mandate_rejects_naive_datetime(valid_mandate_payload: dict) -> None:
    valid_mandate_payload["expires_at"] = datetime(2026, 12, 31, 23, 59, 59)
    with pytest.raises(ValidationError, match="Datetime must be timezone-aware"):
        Mandate(**valid_mandate_payload)


def test_mandate_rejects_empty_allowed_payees(valid_mandate_payload: dict) -> None:
    valid_mandate_payload["allowed_payees"] = []
    with pytest.raises(ValidationError):
        Mandate(**valid_mandate_payload)

    valid_mandate_payload["allowed_payees"] = ["   "]
    with pytest.raises(ValidationError, match="cannot be empty or whitespace"):
        Mandate(**valid_mandate_payload)


def test_mandate_forbids_extra_fields(valid_mandate_payload: dict) -> None:
    valid_mandate_payload["unauthorized_field"] = "malicious_injection"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Mandate(**valid_mandate_payload)


# ============================================================================
# PaymentRequest Model Tests
# ============================================================================


def test_payment_request_valid_creation(valid_payment_payload: dict) -> None:
    req = PaymentRequest(**valid_payment_payload)
    assert req.mandate_id == "man_123456"
    assert req.payee == "aws@amazon.com"
    assert req.amount_minor == 2500
    assert req.currency == "USD"
    assert req.memo == "EC2 c6i.xlarge hourly compute"
    assert req.idempotency_key == "idemp_step_98765"


def test_payment_request_rejects_float_amount(valid_payment_payload: dict) -> None:
    valid_payment_payload["amount_minor"] = 25.50
    with pytest.raises(ValidationError, match="Floating-point values are strictly prohibited"):
        PaymentRequest(**valid_payment_payload)


def test_payment_request_rejects_zero_or_negative_amount(valid_payment_payload: dict) -> None:
    valid_payment_payload["amount_minor"] = 0
    with pytest.raises(ValidationError):
        PaymentRequest(**valid_payment_payload)

    valid_payment_payload["amount_minor"] = -50
    with pytest.raises(ValidationError):
        PaymentRequest(**valid_payment_payload)


def test_payment_request_rejects_empty_strings(valid_payment_payload: dict) -> None:
    valid_payment_payload["memo"] = ""
    with pytest.raises(ValidationError):
        PaymentRequest(**valid_payment_payload)

    valid_payment_payload["memo"] = "Valid memo"
    valid_payment_payload["payee"] = "   "
    with pytest.raises(ValidationError, match="payee cannot be empty or whitespace"):
        PaymentRequest(**valid_payment_payload)

    valid_payment_payload["payee"] = "valid@payee.com"
    valid_payment_payload["idempotency_key"] = ""
    with pytest.raises(ValidationError):
        PaymentRequest(**valid_payment_payload)


def test_payment_request_forbids_extra_fields(valid_payment_payload: dict) -> None:
    valid_payment_payload["extra_meta"] = "tampered_data"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        PaymentRequest(**valid_payment_payload)


# ============================================================================
# RuleResult Model Tests
# ============================================================================


def test_rule_result_valid_creation() -> None:
    res = RuleResult(name="budget_check", passed=True, detail="Amount 2500 is within 10000 cap")
    assert res.name == "budget_check"
    assert res.passed is True
    assert "2500 is within" in res.detail


def test_rule_result_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RuleResult(name="check", passed=False, detail="failed", extra="forbidden")  # type: ignore[call-arg]


# ============================================================================
# Decision Model Tests
# ============================================================================


def test_decision_valid_creation() -> None:
    rule1 = RuleResult(name="budget_check", passed=True, detail="Within budget")
    rule2 = RuleResult(name="payee_allowlist", passed=True, detail="Payee authorized")
    decision = Decision(
        id="dec_001",
        verdict=Verdict.APPROVE,
        rule_results=[rule1, rule2],
        judge_reason=None,
        created_at=datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC),
    )
    assert decision.id == "dec_001"
    assert decision.verdict == Verdict.APPROVE
    assert len(decision.rule_results) == 2
    assert decision.created_at.tzinfo == UTC


def test_decision_string_verdict_coercion() -> None:
    decision = Decision(
        id="dec_002",
        verdict="block",  # type: ignore[arg-type]
        rule_results=[RuleResult(name="budget_check", passed=False, detail="Limit exceeded")],
        judge_reason="Suspicious velocity spike detected",
        created_at="2026-11-01T12:30:00Z",
    )
    assert decision.verdict == Verdict.BLOCK
    assert decision.judge_reason == "Suspicious velocity spike detected"


def test_decision_rejects_invalid_verdict() -> None:
    with pytest.raises(ValidationError):
        Decision(
            id="dec_003",
            verdict="invalid_status",  # type: ignore[arg-type]
            created_at=datetime.now(UTC),
        )


def test_decision_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Decision(
            id="dec_004",
            verdict=Verdict.ESCALATE,
            created_at=datetime.now(UTC),
            extra_payload="injected",  # type: ignore[call-arg]
        )
