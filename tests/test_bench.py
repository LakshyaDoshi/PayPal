"""
tests.test_bench
================

Unit tests for the benchmark runner:
- Pydantic dataset validation (BenchCase, MandateFixture, RequestFixture)
- Metric math in isolation (compute_metrics)
- Dataset loader (load_cases)
- Markdown/JSON output rendering (smoke)

Invariants:
- No network calls; no PayPal provider.
- Integer minor units only; no float.
- Signing key must be set in environment.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Ensure signing key is present (mandate module validates on import)
# ---------------------------------------------------------------------------
os.environ.setdefault("MANDATE_SIGNING_KEY", "a" * 32)

from datetime import UTC, datetime  # noqa: E402

from pydantic import ValidationError  # noqa: E402

from bench.runner import (  # noqa: E402  (after env setup)
    BenchCase,
    MandateFixture,
    Metrics,
    RequestFixture,
    RunResult,
    compute_metrics,
    load_cases,
    render_json,
    render_markdown,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FUTURE_EXPIRY = "2099-12-31T00:00:00+00:00"


def _make_fixture(
    *,
    mandate_id: str = "m-test",
    max_amount: int = 10000,
    approval_threshold: int | None = None,
) -> tuple[MandateFixture, RequestFixture]:
    mf = MandateFixture(
        id=mandate_id,
        purpose="Test purpose",
        max_amount_minor=max_amount,
        currency="USD",
        allowed_payees=["shop@example.com"],
        expires_at=FUTURE_EXPIRY,
        approval_threshold_minor=approval_threshold,
    )
    rf = RequestFixture(
        mandate_id=mandate_id,
        payee="shop@example.com",
        amount_minor=1000,
        currency="USD",
        memo="Test memo",
        idempotency_key="idem-test-001",
    )
    return mf, rf


def _make_case(
    *,
    case_id: str = "c-001",
    label: str = "benign",
    category: str = "other",
    split: str = "test",
    expected_verdict: str = "approve",
    mandate_id: str = "m-test",
    max_amount: int = 10000,
    approval_threshold: int | None = None,
) -> BenchCase:
    mf, rf = _make_fixture(
        mandate_id=mandate_id,
        max_amount=max_amount,
        approval_threshold=approval_threshold,
    )
    return BenchCase(
        id=case_id,
        label=label,
        category=category,
        split=split,
        mandate_fixture=mf,
        request=rf,
        expected_verdict=expected_verdict,
    )


def _make_result(
    *,
    case_id: str = "c-001",
    label: str = "benign",
    category: str = "other",
    split: str = "test",
    expected: str = "approve",
    actual: list[str] | None = None,
) -> RunResult:
    if actual is None:
        actual = [expected]
    return RunResult(
        case_id=case_id,
        label=label,
        category=category,
        split=split,
        expected_verdict=expected,
        actual_verdicts=actual,
    )


# ---------------------------------------------------------------------------
# BenchCase / Pydantic validation tests
# ---------------------------------------------------------------------------


class TestBenchCaseValidation:
    def test_valid_benign_case_accepted(self) -> None:
        case = _make_case(label="benign", category="other", expected_verdict="approve")
        assert case.label == "benign"
        assert case.expected_verdict == "approve"

    def test_valid_malicious_case_accepted(self) -> None:
        case = _make_case(label="malicious", category="injection", expected_verdict="block")
        assert case.label == "malicious"

    def test_invalid_label_rejected(self) -> None:
        mf, rf = _make_fixture()
        with pytest.raises(ValidationError):
            BenchCase(
                id="bad",
                label="suspicious",  # type: ignore[arg-type]
                category="other",
                split="test",
                mandate_fixture=mf,
                request=rf,
                expected_verdict="block",
            )

    def test_invalid_category_rejected(self) -> None:
        mf, rf = _make_fixture()
        with pytest.raises(ValidationError):
            BenchCase(
                id="bad",
                label="benign",
                category="money_laundering",  # type: ignore[arg-type]
                split="test",
                mandate_fixture=mf,
                request=rf,
                expected_verdict="approve",
            )

    def test_float_amount_rejected_in_mandate_fixture(self) -> None:
        with pytest.raises(ValidationError):
            MandateFixture(
                id="m-bad",
                purpose="Test",
                max_amount_minor=100.0,  # type: ignore[arg-type]  # float — forbidden
                currency="USD",
                allowed_payees=["shop@example.com"],
                expires_at=FUTURE_EXPIRY,
            )

    def test_float_amount_rejected_in_request_fixture(self) -> None:
        with pytest.raises(ValidationError):
            RequestFixture(
                mandate_id="m-bad",
                payee="shop@example.com",
                amount_minor=10.5,  # type: ignore[arg-type]  # float — forbidden
                currency="USD",
                memo="Test",
                idempotency_key="idem-bad",
            )

    def test_all_valid_splits_accepted(self) -> None:
        for split in ("dev", "test"):
            case = _make_case(split=split)
            assert case.split == split

    def test_all_valid_categories_accepted(self) -> None:
        for cat in ("injection", "payee_swap", "spend_loop", "over_budget", "expired", "other"):
            case = _make_case(category=cat)
            assert case.category == cat

    def test_all_valid_verdicts_accepted(self) -> None:
        for v in ("approve", "block", "escalate"):
            case = _make_case(expected_verdict=v)
            assert case.expected_verdict == v


# ---------------------------------------------------------------------------
# RunResult property tests
# ---------------------------------------------------------------------------


class TestRunResult:
    def test_final_verdict_uses_first_run(self) -> None:
        r = _make_result(actual=["approve", "block"])
        assert r.final_verdict == "approve"

    def test_matched_true_when_expected_equals_actual(self) -> None:
        r = _make_result(expected="block", actual=["block"])
        assert r.matched is True

    def test_matched_false_when_mismatch(self) -> None:
        r = _make_result(expected="block", actual=["approve"])
        assert r.matched is False

    def test_has_disagreement_false_when_deterministic(self) -> None:
        r = _make_result(actual=["approve", "approve", "approve"])
        assert r.has_disagreement is False

    def test_has_disagreement_true_when_varying(self) -> None:
        r = _make_result(actual=["approve", "block"])
        assert r.has_disagreement is True

    def test_distinct_verdicts_set(self) -> None:
        r = _make_result(actual=["approve", "block", "approve"])
        assert r.distinct_verdicts == {"approve", "block"}


# ---------------------------------------------------------------------------
# Attack catch rate tests
# ---------------------------------------------------------------------------


class TestAttackCatchRate:
    def test_attack_catch_rate_all_blocked(self) -> None:
        results = [
            _make_result(label="malicious", expected="block", actual=["block"]),
            _make_result(label="malicious", case_id="c-002", expected="block", actual=["block"]),
        ]
        m = compute_metrics(results)
        assert m.attack_catch_rate == 1.0

    def test_attack_catch_rate_all_approved_zero(self) -> None:
        results = [
            _make_result(label="malicious", expected="block", actual=["approve"]),
            _make_result(label="malicious", case_id="c-002", expected="block", actual=["approve"]),
        ]
        m = compute_metrics(results)
        assert m.attack_catch_rate == 0.0

    def test_attack_catch_rate_one_approved_reduces_rate(self) -> None:
        results = [
            _make_result(label="malicious", expected="block", actual=["block"]),
            _make_result(label="malicious", case_id="c-002", expected="block", actual=["approve"]),
        ]
        m = compute_metrics(results)
        assert m.attack_catch_rate == pytest.approx(0.5)

    def test_attack_catch_rate_zero_malicious_returns_zero(self) -> None:
        results = [
            _make_result(label="benign", expected="approve", actual=["approve"]),
        ]
        m = compute_metrics(results)
        assert m.attack_catch_rate == 0.0

    def test_escalate_counts_as_caught(self) -> None:
        """Malicious that is escalated (not approved) is caught."""
        results = [
            _make_result(label="malicious", expected="escalate", actual=["escalate"]),
        ]
        m = compute_metrics(results)
        assert m.attack_catch_rate == 1.0


# ---------------------------------------------------------------------------
# False block rate tests
# ---------------------------------------------------------------------------


class TestFalseBlockRate:
    def test_false_block_rate_zero_when_all_benign_pass(self) -> None:
        results = [
            _make_result(label="benign", expected="approve", actual=["approve"]),
            _make_result(label="benign", case_id="c-002", expected="approve", actual=["approve"]),
        ]
        m = compute_metrics(results)
        assert m.false_block_rate == 0.0

    def test_false_block_rate_half_when_half_blocked(self) -> None:
        results = [
            _make_result(label="benign", expected="approve", actual=["block"]),
            _make_result(label="benign", case_id="c-002", expected="approve", actual=["approve"]),
        ]
        m = compute_metrics(results)
        assert m.false_block_rate == pytest.approx(0.5)

    def test_false_block_rate_one_when_all_benign_blocked(self) -> None:
        results = [
            _make_result(label="benign", expected="approve", actual=["block"]),
        ]
        m = compute_metrics(results)
        assert m.false_block_rate == 1.0

    def test_false_block_rate_zero_when_no_benign(self) -> None:
        results = [
            _make_result(label="malicious", expected="block", actual=["block"]),
        ]
        m = compute_metrics(results)
        assert m.false_block_rate == 0.0

    def test_escalate_not_counted_as_false_block(self) -> None:
        """A benign case that escalates is NOT a false block."""
        results = [
            _make_result(label="benign", expected="escalate", actual=["escalate"]),
        ]
        m = compute_metrics(results)
        assert m.false_block_rate == 0.0


# ---------------------------------------------------------------------------
# Escalation rate tests
# ---------------------------------------------------------------------------


class TestEscalationRate:
    def test_escalation_rate_zero_when_none_escalated(self) -> None:
        results = [
            _make_result(actual=["approve"]),
            _make_result(case_id="c-002", actual=["block"]),
        ]
        m = compute_metrics(results)
        assert m.escalation_rate == 0.0

    def test_escalation_rate_calculation(self) -> None:
        results = [
            _make_result(actual=["approve"]),
            _make_result(case_id="c-002", actual=["escalate"]),
            _make_result(case_id="c-003", actual=["escalate"]),
            _make_result(case_id="c-004", actual=["block"]),
        ]
        m = compute_metrics(results)
        assert m.escalation_rate == pytest.approx(0.5)

    def test_escalation_rate_one_when_all_escalated(self) -> None:
        results = [
            _make_result(actual=["escalate"]),
            _make_result(case_id="c-002", actual=["escalate"]),
        ]
        m = compute_metrics(results)
        assert m.escalation_rate == 1.0


# ---------------------------------------------------------------------------
# Disagreement rate tests
# ---------------------------------------------------------------------------


class TestDisagreementRate:
    def test_disagreement_rate_zero_when_deterministic(self) -> None:
        results = [
            _make_result(actual=["approve", "approve", "approve"]),
            _make_result(case_id="c-002", actual=["block", "block"]),
        ]
        m = compute_metrics(results)
        assert m.disagreement_rate == 0.0

    def test_disagreement_rate_nonzero_when_varying(self) -> None:
        results = [
            _make_result(actual=["approve", "block"]),  # disagrees
            _make_result(case_id="c-002", actual=["block", "block"]),  # agrees
        ]
        m = compute_metrics(results)
        assert m.disagreement_rate == pytest.approx(0.5)

    def test_disagreement_rate_one_when_all_vary(self) -> None:
        results = [
            _make_result(actual=["approve", "block"]),
            _make_result(case_id="c-002", actual=["escalate", "approve"]),
        ]
        m = compute_metrics(results)
        assert m.disagreement_rate == 1.0

    def test_disagreement_rate_single_repeat_always_zero(self) -> None:
        """With one repeat, there cannot be disagreement."""
        results = [
            _make_result(actual=["approve"]),
            _make_result(case_id="c-002", actual=["block"]),
        ]
        m = compute_metrics(results)
        assert m.disagreement_rate == 0.0


# ---------------------------------------------------------------------------
# Per-category stats tests
# ---------------------------------------------------------------------------


class TestCategoryStats:
    def test_per_category_counts_malicious_caught(self) -> None:
        results = [
            _make_result(label="malicious", category="injection", actual=["block"]),
            _make_result(
                label="malicious", case_id="c-002", category="injection", actual=["approve"]
            ),
        ]
        m = compute_metrics(results)
        assert m.by_category["injection"].total == 2
        assert m.by_category["injection"].caught == 1

    def test_per_category_counts_benign_false_blocked(self) -> None:
        results = [
            _make_result(label="benign", category="other", actual=["block"]),
            _make_result(label="benign", case_id="c-002", category="other", actual=["approve"]),
        ]
        m = compute_metrics(results)
        assert m.by_category["other"].false_blocked == 1

    def test_per_category_escalated_count(self) -> None:
        results = [
            _make_result(category="over_budget", actual=["escalate"]),
            _make_result(case_id="c-002", category="over_budget", actual=["approve"]),
        ]
        m = compute_metrics(results)
        assert m.by_category["over_budget"].escalated == 1


# ---------------------------------------------------------------------------
# load_cases tests
# ---------------------------------------------------------------------------


class TestLoadCases:
    def _write_jsonl(self, lines: list[str], suffix: str = ".jsonl") -> str:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        ) as fh:
            fh.write("\n".join(lines) + "\n")
            return fh.name

    def test_load_valid_starter_cases(self) -> None:
        """All 10 starter cases in bench/cases.jsonl must load cleanly."""
        cases_path = Path(__file__).parent.parent / "bench" / "cases.jsonl"
        cases, bad = load_cases(cases_path)
        assert bad == [], f"Unexpected bad lines: {bad}"
        assert len(cases) == 10

    def test_load_cases_validates_bad_json_line(self) -> None:
        path = self._write_jsonl(["NOT_VALID_JSON{{{"])
        cases, bad = load_cases(path)
        assert len(cases) == 0
        assert len(bad) == 1
        assert bad[0][0] == 1
        assert "Invalid JSON" in bad[0][1]

    def test_load_cases_validates_missing_field(self) -> None:
        line = json.dumps({"id": "x", "label": "benign"})  # missing many required fields
        path = self._write_jsonl([line])
        cases, bad = load_cases(path)
        assert len(bad) == 1
        assert "Validation error" in bad[0][1]

    def test_load_cases_reports_multiple_bad_lines(self) -> None:
        lines = ["BAD_JSON", json.dumps({"id": "also_bad"})]
        path = self._write_jsonl(lines)
        _, bad = load_cases(path)
        assert len(bad) == 2

    def test_load_cases_skips_blank_lines(self) -> None:
        mf, rf = _make_fixture()
        good_case = {
            "id": "c-valid",
            "label": "benign",
            "category": "other",
            "split": "test",
            "mandate_fixture": mf.model_dump(),
            "request": rf.model_dump(),
            "expected_verdict": "approve",
            "notes": "",
        }
        path = self._write_jsonl(["", json.dumps(good_case), "   "])
        cases, bad = load_cases(path)
        assert len(cases) == 1
        assert len(bad) == 0

    def test_load_cases_float_amount_in_mandate_is_rejected(self) -> None:
        bad_case = {
            "id": "c-float",
            "label": "benign",
            "category": "other",
            "split": "test",
            "mandate_fixture": {
                "id": "m-float",
                "purpose": "Test",
                "max_amount_minor": 100.0,  # float — forbidden
                "currency": "USD",
                "allowed_payees": ["shop@example.com"],
                "expires_at": FUTURE_EXPIRY,
            },
            "request": {
                "mandate_id": "m-float",
                "payee": "shop@example.com",
                "amount_minor": 100,
                "currency": "USD",
                "memo": "Test",
                "idempotency_key": "idem-float",
            },
            "expected_verdict": "approve",
        }
        path = self._write_jsonl([json.dumps(bad_case)])
        cases, bad = load_cases(path)
        assert len(bad) == 1
        assert len(cases) == 0

    def test_load_cases_accepts_all_starter_cases(self) -> None:
        cases_path = Path(__file__).parent.parent / "bench" / "cases.jsonl"
        cases, bad = load_cases(cases_path)
        assert len(bad) == 0
        assert all(c.split in ("dev", "test") for c in cases)
        assert all(c.label in ("malicious", "benign") for c in cases)


# ---------------------------------------------------------------------------
# Rendering smoke tests
# ---------------------------------------------------------------------------


class TestRendering:
    def _make_sample_metrics(self) -> tuple[list[RunResult], Metrics]:
        results = [
            _make_result(label="malicious", category="injection", actual=["block"]),
            _make_result(label="benign", case_id="c-002", category="other", actual=["approve"]),
        ]
        m = compute_metrics(results)
        return results, m

    def test_render_markdown_contains_headline_metrics(self) -> None:
        results, m = self._make_sample_metrics()
        md = render_markdown(results, m, "combined", "test", 1, datetime.now(UTC))
        assert "Attack Catch Rate" in md
        assert "False Block Rate" in md
        assert "Escalation Rate" in md

    def test_render_markdown_contains_case_table(self) -> None:
        results, m = self._make_sample_metrics()
        md = render_markdown(results, m, "rules_only", "test", 1, datetime.now(UTC))
        assert "c-001" in md
        assert "c-002" in md

    def test_render_json_is_valid_json(self) -> None:
        results, m = self._make_sample_metrics()
        raw = render_json(results, m, "combined", "test", 1, datetime.now(UTC))
        data = json.loads(raw)
        assert "metrics" in data
        assert "cases" in data

    def test_render_json_attack_catch_rate_in_metrics(self) -> None:
        results, m = self._make_sample_metrics()
        raw = render_json(results, m, "combined", "test", 1, datetime.now(UTC))
        data = json.loads(raw)
        assert "attack_catch_rate" in data["metrics"]

    def test_render_json_no_floats_for_money(self) -> None:
        """Ensure no float monetary values leak into JSON output."""
        results, m = self._make_sample_metrics()
        raw = render_json(results, m, "combined", "test", 1, datetime.now(UTC))
        data = json.loads(raw)
        for case_data in data["cases"]:
            # No monetary fields in runner output — just verdicts and IDs
            assert "amount_minor" not in case_data or isinstance(case_data.get("amount_minor"), int)

    def test_render_markdown_disagreement_section_with_repeats(self) -> None:
        results = [
            _make_result(actual=["approve", "block"]),  # disagrees
        ]
        m = compute_metrics(results)
        md = render_markdown(results, m, "judge_only", "test", 2, datetime.now(UTC))
        assert "Judge Variance" in md
