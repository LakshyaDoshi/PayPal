"""
tests/test_rules.py

Table-driven tests for gateway.rules deterministic rule engine.
Validates:
- Every rule: pass, fail, exactly-at-limit, one cent over.
- Expired by exactly one second.
- Wrong currency.
- Whitespace, case, and Unicode-lookalike payees.
- Negative, zero, and huge amounts.
- Replayed idempotency key inside and outside velocity window.
- needs_human threshold escalation.
- Comprehensive invariant: No code path returns APPROVE when any rule fails.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

VALID_SIGNING_KEY = "a" * 32
os.environ.setdefault("MANDATE_SIGNING_KEY", VALID_SIGNING_KEY)

from gateway.contract import Mandate, PaymentRequest, RuleResult, Verdict  # noqa: E402
from gateway.mandate import sign  # noqa: E402
from gateway.rules import (  # noqa: E402
    HistoricalPayment,
    RuleContext,
    check_amount_positive_and_bounded,
    check_currency_matches,
    check_duplicate,
    check_needs_human,
    check_not_expired,
    check_not_revoked,
    check_payee_allowed,
    check_signature_valid,
    check_velocity,
    check_within_budget,
    evaluate,
    normalize_payee,
    overall,
)

# ---------------------------------------------------------------------------
# Test Helpers & Standard Fixtures
# ---------------------------------------------------------------------------

BASE_NOW = datetime(2026, 11, 2, 12, 0, 0, tzinfo=UTC)
BASE_EXPIRY = BASE_NOW + timedelta(days=30)


def make_mandate(
    *,
    mandate_id: str = "m-test",
    max_amount_minor: int = 10000,
    currency: str = "USD",
    allowed_payees: list[str] | None = None,
    expires_at: datetime = BASE_EXPIRY,
    approval_threshold_minor: int | None = None,
    max_payments_per_window: int | None = None,
    window_seconds: int | None = None,
) -> Mandate:
    """Helper creating a cryptographically signed test mandate."""
    draft = Mandate(
        id=mandate_id,
        purpose="Authorized spending for software subscriptions and infrastructure.",
        max_amount_minor=max_amount_minor,
        currency=currency,
        allowed_payees=allowed_payees or ["vendor@example.com"],
        expires_at=expires_at,
        approval_threshold_minor=approval_threshold_minor,
        max_payments_per_window=max_payments_per_window,
        window_seconds=window_seconds,
        signature="placeholder",
    )
    return sign(draft)


def make_request(
    *,
    mandate_id: str = "m-test",
    payee: str = "vendor@example.com",
    amount_minor: int = 1000,
    currency: str = "USD",
    memo: str = "Monthly API subscription",
    idempotency_key: str = "idemp-001",
) -> PaymentRequest:
    """Helper creating a valid PaymentRequest."""
    return PaymentRequest(
        mandate_id=mandate_id,
        payee=payee,
        amount_minor=amount_minor,
        currency=currency,
        memo=memo,
        idempotency_key=idempotency_key,
    )


# ===========================================================================
# 1. signature_valid
# ===========================================================================


class TestSignatureValid:
    def test_signature_valid_passes(self) -> None:
        mandate = make_mandate()
        result = check_signature_valid(mandate)
        assert result.name == "signature_valid"
        assert result.passed is True

    def test_signature_tampered_fails(self) -> None:
        mandate = make_mandate()
        tampered = mandate.model_copy(update={"signature": "deadbeef" * 8})
        result = check_signature_valid(tampered)
        assert result.passed is False


# ===========================================================================
# 2. not_revoked
# ===========================================================================


class TestNotRevoked:
    @pytest.mark.parametrize(
        ("revoked", "expected"),
        [
            (False, True),
            (True, False),
        ],
    )
    def test_not_revoked(self, revoked: bool, expected: bool) -> None:
        ctx = RuleContext(now=BASE_NOW, revoked=revoked)
        result = check_not_revoked("m-test", ctx)
        assert result.name == "not_revoked"
        assert result.passed is expected


# ===========================================================================
# 3. not_expired (including expired by 1 second)
# ===========================================================================


class TestNotExpired:
    @pytest.mark.parametrize(
        ("offset_seconds", "expected_pass"),
        [
            (-3600, True),  # 1 hour before expiry
            (-1, True),  # 1 second before expiry
            (0, False),  # exactly at expiry timestamp
            (1, False),  # expired by 1 second
            (3600, False),  # 1 hour after expiry
        ],
    )
    def test_not_expired_table(self, offset_seconds: int, expected_pass: bool) -> None:
        expiry = BASE_NOW
        mandate = make_mandate(expires_at=expiry)
        eval_time = expiry + timedelta(seconds=offset_seconds)
        ctx = RuleContext(now=eval_time)

        result = check_not_expired(mandate, ctx)
        assert result.name == "not_expired"
        assert result.passed is expected_pass


# ===========================================================================
# 4. currency_matches
# ===========================================================================


class TestCurrencyMatches:
    @pytest.mark.parametrize(
        ("req_currency", "mandate_currency", "expected"),
        [
            ("USD", "USD", True),
            ("EUR", "EUR", True),
            ("GBP", "USD", False),  # Wrong currency
            ("USD", "EUR", False),  # Wrong currency
        ],
    )
    def test_currency_matches_table(
        self, req_currency: str, mandate_currency: str, expected: bool
    ) -> None:
        mandate = make_mandate(currency=mandate_currency)
        req = make_request(currency=req_currency)
        result = check_currency_matches(req, mandate)
        assert result.name == "currency_matches"
        assert result.passed is expected


# ===========================================================================
# 5. amount_positive_and_bounded (limit, 1 cent over, negative, huge)
# ===========================================================================


class TestAmountPositiveAndBounded:
    @pytest.mark.parametrize(
        ("amount_minor", "max_cap", "expected"),
        [
            (1, 10000, True),  # minimum positive 1 cent
            (5000, 10000, True),  # mid range
            (10000, 10000, True),  # exactly at limit
            (10001, 10000, False),  # one cent over limit
            (999999999, 10000, False),  # huge amount
            (0, 10000, False),  # zero amount
            (-1, 10000, False),  # negative amount
            (-5000, 10000, False),  # large negative amount
        ],
    )
    def test_amount_positive_and_bounded_table(
        self, amount_minor: int, max_cap: int, expected: bool
    ) -> None:
        mandate = make_mandate(max_amount_minor=max_cap)
        # Bypass Pydantic request validation for raw test if testing negative/zero directly
        req = PaymentRequest.model_construct(
            mandate_id=mandate.id,
            payee="vendor@example.com",
            amount_minor=amount_minor,
            currency="USD",
            memo="Test",
            idempotency_key="idemp",
        )
        result = check_amount_positive_and_bounded(req, mandate)
        assert result.name == "amount_positive_and_bounded"
        assert result.passed is expected


# ===========================================================================
# 6. within_budget (cumulative, limit, 1 cent over)
# ===========================================================================


class TestWithinBudget:
    @pytest.mark.parametrize(
        ("spend_so_far", "requested", "max_cap", "expected"),
        [
            (0, 5000, 10000, True),  # fresh mandate
            (5000, 5000, 10000, True),  # exactly at remaining budget
            (5000, 5001, 10000, False),  # one cent over remaining
            (9999, 1, 10000, True),  # exactly last cent
            (9999, 2, 10000, False),  # one cent over remaining
            (10000, 1, 10000, False),  # budget fully exhausted
            (11000, 1, 10000, False),  # already over-budget
        ],
    )
    def test_within_budget_table(
        self, spend_so_far: int, requested: int, max_cap: int, expected: bool
    ) -> None:
        mandate = make_mandate(max_amount_minor=max_cap)
        req = make_request(amount_minor=requested)
        ctx = RuleContext(now=BASE_NOW, spend_so_far=spend_so_far)

        result = check_within_budget(req, mandate, ctx)
        assert result.name == "within_budget"
        assert result.passed is expected


# ===========================================================================
# 7. payee_allowed (whitespace, case, NFKC Unicode, prefix/sub attacks)
# ===========================================================================


class TestPayeeAllowed:
    @pytest.mark.parametrize(
        ("allowlist", "req_payee", "expected"),
        [
            (["vendor@example.com"], "vendor@example.com", True),
            (["vendor@example.com"], "  vendor@example.com  ", True),  # whitespace stripped
            (["vendor@example.com"], "VENDOR@EXAMPLE.COM", True),  # casefold match
            (["vendor@example.com"], "Vendor@Example.Com", True),  # mixed case
            # Fullwidth Latin Unicode NFKC normalization
            (["vendor@example.com"], "\uff56\uff45\uff4e\uff44\uff4f\uff52@example.com", True),
            # Prefix attack: must fail (no prefix matching)
            (["vendor@example.com"], "vendor@example.com.attacker.org", False),
            # Substring attack: must fail (no substring matching)
            (["vendor@example.com"], "vendor@example", False),
            # Cyrillic lookalike 'а' (U+0430) vs Latin 'a' (U+0061): must fail
            (["vendor@example.com"], "vendor@ex\u0430mple.com", False),
            # Unrelated payee
            (["vendor@example.com"], "hacker@evil.com", False),
        ],
    )
    def test_payee_allowed_table(
        self, allowlist: list[str], req_payee: str, expected: bool
    ) -> None:
        mandate = make_mandate(allowed_payees=allowlist)
        req = make_request(payee=req_payee)
        result = check_payee_allowed(req, mandate)
        assert result.name == "payee_allowed"
        assert result.passed is expected

    def test_normalize_payee_helper(self) -> None:
        assert normalize_payee("  ABC@DEF.COM  ") == "abc@def.com"
        assert normalize_payee("\uff48\uff45\uff4c\uff4c\uff4f") == "hello"


# ===========================================================================
# 8. velocity (limit, within window, outside window)
# ===========================================================================


class TestVelocity:
    @pytest.mark.parametrize(
        ("recent_counts_in_window", "max_allowed", "expected"),
        [
            (0, 3, True),  # 0 recent payments
            (1, 3, True),  # 1 recent payment
            (2, 3, True),  # 2 recent payments (this is 3rd, within max 3)
            (3, 3, False),  # 3 recent payments (attempting 4th, exceeds max 3)
            (5, 3, False),  # already over limit
        ],
    )
    def test_velocity_table(
        self, recent_counts_in_window: int, max_allowed: int, expected: bool
    ) -> None:
        window_sec = 3600
        mandate = make_mandate(
            max_payments_per_window=max_allowed,
            window_seconds=window_sec,
        )

        history: list[HistoricalPayment] = []
        for i in range(recent_counts_in_window):
            history.append(
                HistoricalPayment(
                    payee="vendor@example.com",
                    amount_minor=100,
                    currency="USD",
                    memo=f"memo-{i}",
                    idempotency_key=f"hist-{i}",
                    created_at=BASE_NOW - timedelta(seconds=i * 60),  # inside window
                )
            )

        ctx = RuleContext(now=BASE_NOW, recent_approved_payments=history)
        result = check_velocity(mandate, ctx)
        assert result.name == "velocity"
        assert result.passed is expected

    def test_velocity_ignores_payments_outside_window(self) -> None:
        window_sec = 300  # 5 minutes
        mandate = make_mandate(max_payments_per_window=2, window_seconds=window_sec)

        history = [
            HistoricalPayment(
                payee="vendor@example.com",
                amount_minor=100,
                currency="USD",
                memo="old-1",
                idempotency_key="old-1",
                created_at=BASE_NOW - timedelta(seconds=600),  # 10m ago (outside window)
            ),
            HistoricalPayment(
                payee="vendor@example.com",
                amount_minor=100,
                currency="USD",
                memo="old-2",
                idempotency_key="old-2",
                created_at=BASE_NOW - timedelta(seconds=400),  # 6m ago (outside window)
            ),
        ]
        ctx = RuleContext(now=BASE_NOW, recent_approved_payments=history)
        result = check_velocity(mandate, ctx)
        assert result.passed is True


# ===========================================================================
# 9. duplicate (replayed idempotency, identical payee+amount+memo)
# ===========================================================================


class TestDuplicate:
    def test_replayed_idempotency_key_inside_window_fails(self) -> None:
        mandate = make_mandate(max_payments_per_window=10, window_seconds=3600)
        req = make_request(idempotency_key="replayed-key")
        history = [
            HistoricalPayment(
                payee="different@example.com",
                amount_minor=9999,
                currency="USD",
                memo="Different memo",
                idempotency_key="replayed-key",
                created_at=BASE_NOW - timedelta(minutes=10),
            )
        ]
        ctx = RuleContext(now=BASE_NOW, recent_approved_payments=history)
        result = check_duplicate(req, mandate, ctx)
        assert result.name == "duplicate"
        assert result.passed is False

    def test_replayed_idempotency_key_outside_window_passes(self) -> None:
        mandate = make_mandate(max_payments_per_window=10, window_seconds=3600)
        req = make_request(idempotency_key="replayed-key")
        history = [
            HistoricalPayment(
                payee="vendor@example.com",
                amount_minor=1000,
                currency="USD",
                memo="Past payment",
                idempotency_key="replayed-key",
                created_at=BASE_NOW - timedelta(hours=2),  # outside 1-hour window
            )
        ]
        ctx = RuleContext(now=BASE_NOW, recent_approved_payments=history)
        result = check_duplicate(req, mandate, ctx)
        assert result.passed is True

    def test_identical_payee_amount_memo_inside_window_fails(self) -> None:
        mandate = make_mandate(max_payments_per_window=10, window_seconds=3600)
        req = make_request(
            payee="vendor@example.com",
            amount_minor=2500,
            memo="License renewal",
            idempotency_key="new-key-123",
        )
        history = [
            HistoricalPayment(
                payee="  VENDOR@EXAMPLE.COM  ",  # normalized duplicate
                amount_minor=2500,
                currency="USD",
                memo="License renewal",
                idempotency_key="old-key-456",
                created_at=BASE_NOW - timedelta(minutes=5),
            )
        ]
        ctx = RuleContext(now=BASE_NOW, recent_approved_payments=history)
        result = check_duplicate(req, mandate, ctx)
        assert result.passed is False

    def test_different_memo_same_payee_amount_passes(self) -> None:
        mandate = make_mandate(max_payments_per_window=10, window_seconds=3600)
        req = make_request(payee="vendor@example.com", amount_minor=2500, memo="Invoice A")
        history = [
            HistoricalPayment(
                payee="vendor@example.com",
                amount_minor=2500,
                currency="USD",
                memo="Invoice B",
                idempotency_key="key-old",
                created_at=BASE_NOW - timedelta(minutes=5),
            )
        ]
        ctx = RuleContext(now=BASE_NOW, recent_approved_payments=history)
        result = check_duplicate(req, mandate, ctx)
        assert result.passed is True


# ===========================================================================
# 10. needs_human (threshold escalation)
# ===========================================================================


class TestNeedsHuman:
    @pytest.mark.parametrize(
        ("amount_minor", "threshold_minor", "expected_pass"),
        [
            (1000, 5000, True),  # well below threshold
            (5000, 5000, True),  # exactly at threshold
            (5001, 5000, False),  # one cent over threshold (escalates)
            (10000, 5000, False),  # well above threshold (escalates)
            (999999, None, True),  # no threshold configured on mandate
        ],
    )
    def test_needs_human_table(
        self, amount_minor: int, threshold_minor: int | None, expected_pass: bool
    ) -> None:
        mandate = make_mandate(
            max_amount_minor=1000000,
            approval_threshold_minor=threshold_minor,
        )
        req = make_request(amount_minor=amount_minor)
        result = check_needs_human(req, mandate)
        assert result.name == "needs_human"
        assert result.passed is expected_pass


# ===========================================================================
# 11. overall verdict & comprehensive invariant:
#     NO code path returns APPROVE when any rule failed
# ===========================================================================


class TestOverallVerdict:
    def test_all_rules_passing_returns_approve(self) -> None:
        mandate = make_mandate()
        req = make_request()
        ctx = RuleContext(now=BASE_NOW)

        results = evaluate(req, mandate, ctx)
        assert len(results) == 10
        assert all(r.passed for r in results)
        assert overall(results) == Verdict.APPROVE

    def test_needs_human_failure_returns_escalate(self) -> None:
        """When needs_human fails and all other 9 rules pass, verdict is ESCALATE."""
        mandate = make_mandate(approval_threshold_minor=500)
        req = make_request(amount_minor=501)  # 1 cent over threshold
        ctx = RuleContext(now=BASE_NOW)

        results = evaluate(req, mandate, ctx)
        failed_rules = [r for r in results if not r.passed]
        assert len(failed_rules) == 1
        assert failed_rules[0].name == "needs_human"
        assert overall(results) == Verdict.ESCALATE

    def test_needs_human_and_blocking_failure_returns_block(self) -> None:
        """Security invariant: If both needs_human and a security rule fail, BLOCK."""
        mandate = make_mandate(approval_threshold_minor=500)
        req = make_request(amount_minor=501, currency="EUR")  # threshold and currency fail
        ctx = RuleContext(now=BASE_NOW)

        results = evaluate(req, mandate, ctx)
        assert overall(results) == Verdict.BLOCK

    def test_empty_results_fails_closed_to_block(self) -> None:
        assert overall([]) == Verdict.BLOCK

    @pytest.mark.parametrize(
        "failing_rule_name",
        [
            "signature_valid",
            "not_revoked",
            "not_expired",
            "currency_matches",
            "amount_positive_and_bounded",
            "within_budget",
            "payee_allowed",
            "velocity",
            "duplicate",
            "needs_human",
        ],
    )
    def test_invariant_no_code_path_returns_approve_when_any_rule_failed(
        self, failing_rule_name: str
    ) -> None:
        """INVARIANT PROOF: For EVERY rule, if that rule fails, APPROVE is NEVER returned."""
        mandate = make_mandate(
            approval_threshold_minor=5000,
            max_payments_per_window=5,
            window_seconds=3600,
        )
        req = make_request(amount_minor=1000)
        ctx = RuleContext(now=BASE_NOW)

        # Baseline: all pass
        results = evaluate(req, mandate, ctx)
        assert all(r.passed for r in results)
        assert overall(results) == Verdict.APPROVE

        # Artificially fail exactly one rule
        mutated_results: list[RuleResult] = []
        for r in results:
            if r.name == failing_rule_name:
                mutated_results.append(
                    RuleResult(name=r.name, passed=False, detail="Simulated failure")
                )
            else:
                mutated_results.append(r)

        verdict = overall(mutated_results)
        # CRITICAL ASSERTION: APPROVE can NEVER be returned
        assert verdict != Verdict.APPROVE
        assert verdict in (Verdict.BLOCK, Verdict.ESCALATE)
        if failing_rule_name == "needs_human":
            assert verdict == Verdict.ESCALATE
        else:
            assert verdict == Verdict.BLOCK
