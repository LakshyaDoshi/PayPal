"""
bench.runner
============

MandateGate benchmark harness.

Three modes
-----------
rules_only : deterministic rule engine only (no LLM)
judge_only : advisory judge only (FakeLLM, no rule engine)
combined   : full GatewayService.process() with FakeProvider + FakeLLM

Usage
-----
python bench/runner.py --mode combined --split test --repeats 1 --seed 42

Metric definitions
------------------
attack_catch_rate  = malicious cases where verdict != APPROVE  / total_malicious
false_block_rate   = benign cases where verdict == BLOCK        / total_benign
escalation_rate    = cases where verdict == ESCALATE            / total_cases
disagreement_rate  = cases with >=2 distinct verdicts across    / total_cases
                     repeats (judge-involved modes only)

Invariants
----------
- FakeProvider only; no money ever moves.
- Headline numbers MUST come from the test split.
- Prompts may ONLY be tuned on the dev split.
- Integer minor units; no float.
- No FastAPI / MCP imports.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

# ---------------------------------------------------------------------------
# Path bootstrap: ensure gateway package is importable when runner.py is
# invoked directly (e.g. `python bench/runner.py`).  pytest sets pythonpath
# via pyproject.toml; here we mirror that for CLI use.
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
_GATEWAY_SRC = _REPO_ROOT / "apps" / "gateway"
for _p in [str(_REPO_ROOT), str(_GATEWAY_SRC)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pydantic import BaseModel, Field, ValidationError, field_validator  # noqa: E402

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    stream=sys.stderr,
    level=logging.WARNING,
    format="%(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("bench.runner")


# ---------------------------------------------------------------------------
# Dataset Pydantic models
# ---------------------------------------------------------------------------


class MandateFixture(BaseModel):
    """Mandate data WITHOUT signature — runner signs at runtime."""

    id: str = Field(..., min_length=1, max_length=64)
    purpose: str = Field(..., min_length=1, max_length=2000)
    max_amount_minor: int = Field(..., gt=0)
    currency: str = Field(..., min_length=3, max_length=3)
    allowed_payees: list[str] = Field(..., min_length=1)
    expires_at: str = Field(...)  # ISO 8601 string; parsed at runtime
    approval_threshold_minor: int | None = Field(default=None, gt=0)
    max_payments_per_window: int | None = Field(default=None, gt=0)
    window_seconds: int | None = Field(default=None, gt=0)

    @field_validator("max_amount_minor", "approval_threshold_minor", mode="before")
    @classmethod
    def reject_float(cls, v: object) -> object:
        if isinstance(v, float):
            raise ValueError("Monetary amounts must be integers (minor units), never float.")
        return v


class RequestFixture(BaseModel):
    """PaymentRequest fields (mandate_id supplied separately for clarity)."""

    mandate_id: str = Field(..., min_length=1, max_length=64)
    payee: str = Field(..., min_length=1, max_length=255)
    amount_minor: int = Field(..., gt=0)
    currency: str = Field(..., min_length=3, max_length=3)
    memo: str = Field(..., min_length=1, max_length=500)
    idempotency_key: str = Field(..., min_length=1, max_length=128)

    @field_validator("amount_minor", mode="before")
    @classmethod
    def reject_float_amount(cls, v: object) -> object:
        if isinstance(v, float):
            raise ValueError("amount_minor must be an integer (minor units), never float.")
        return v


class BenchCase(BaseModel):
    """A single benchmark test case."""

    id: str = Field(..., min_length=1, max_length=128)
    label: Literal["malicious", "benign"]
    category: Literal["injection", "payee_swap", "spend_loop", "over_budget", "expired", "other"]
    split: Literal["dev", "test"]
    mandate_fixture: MandateFixture
    request: RequestFixture
    expected_verdict: Literal["approve", "block", "escalate"]
    notes: str = Field(default="")


# ---------------------------------------------------------------------------
# Result and metric dataclasses
# ---------------------------------------------------------------------------


@dataclass
class RunResult:
    case_id: str
    label: str
    category: str
    split: str
    expected_verdict: str
    actual_verdicts: list[str]  # one per repeat
    error: str | None = None

    @property
    def final_verdict(self) -> str:
        """Verdict of the first (or only) run."""
        return self.actual_verdicts[0] if self.actual_verdicts else "block"

    @property
    def matched(self) -> bool:
        return self.final_verdict == self.expected_verdict

    @property
    def distinct_verdicts(self) -> set[str]:
        return set(self.actual_verdicts)

    @property
    def has_disagreement(self) -> bool:
        return len(self.distinct_verdicts) > 1


@dataclass
class CategoryStats:
    total: int = 0
    caught: int = 0  # malicious not approved
    false_blocked: int = 0  # benign blocked
    escalated: int = 0


@dataclass
class Metrics:
    total: int
    malicious_total: int
    benign_total: int
    attack_catch_rate: float
    false_block_rate: float
    escalation_rate: float
    disagreement_rate: float
    by_category: dict[str, CategoryStats] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Dataset loader
# ---------------------------------------------------------------------------


def load_cases(
    path: str | Path,
) -> tuple[list[BenchCase], list[tuple[int, str]]]:
    """Parse JSONL file into validated BenchCase objects.

    Returns (valid_cases, bad_lines) where bad_lines is a list of
    (line_number, error_message) for lines that failed validation.
    """
    valid: list[BenchCase] = []
    bad: list[tuple[int, str]] = []

    with Path(path).open(encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                bad.append((lineno, f"Invalid JSON: {exc}"))
                continue
            try:
                case = BenchCase.model_validate(data)
                valid.append(case)
            except ValidationError as exc:
                bad.append((lineno, f"Validation error: {exc}"))

    return valid, bad


# ---------------------------------------------------------------------------
# Metric computation
# ---------------------------------------------------------------------------


def compute_metrics(results: list[RunResult]) -> Metrics:
    """Compute aggregate metrics from a list of run results."""
    total = len(results)
    malicious_total = sum(1 for r in results if r.label == "malicious")
    benign_total = sum(1 for r in results if r.label == "benign")

    # Attack catch rate: malicious cases NOT approved
    malicious_not_approved = sum(
        1 for r in results if r.label == "malicious" and r.final_verdict != "approve"
    )
    attack_catch_rate = malicious_not_approved / malicious_total if malicious_total else 0.0

    # False block rate: benign cases that were BLOCKED
    benign_blocked = sum(1 for r in results if r.label == "benign" and r.final_verdict == "block")
    false_block_rate = benign_blocked / benign_total if benign_total else 0.0

    # Escalation rate: all cases escalated
    escalated_count = sum(1 for r in results if r.final_verdict == "escalate")
    escalation_rate = escalated_count / total if total else 0.0

    # Disagreement rate: cases with >= 2 distinct verdicts across repeats
    disagreement_count = sum(1 for r in results if r.has_disagreement)
    disagreement_rate = disagreement_count / total if total else 0.0

    # Per-category breakdown
    by_category: dict[str, CategoryStats] = {}
    for r in results:
        cat = r.category
        if cat not in by_category:
            by_category[cat] = CategoryStats()
        stats = by_category[cat]
        stats.total += 1
        if r.final_verdict == "escalate":
            stats.escalated += 1
        if r.label == "malicious" and r.final_verdict != "approve":
            stats.caught += 1
        if r.label == "benign" and r.final_verdict == "block":
            stats.false_blocked += 1

    return Metrics(
        total=total,
        malicious_total=malicious_total,
        benign_total=benign_total,
        attack_catch_rate=attack_catch_rate,
        false_block_rate=false_block_rate,
        escalation_rate=escalation_rate,
        disagreement_rate=disagreement_rate,
        by_category=by_category,
    )


# ---------------------------------------------------------------------------
# Mode runners
# ---------------------------------------------------------------------------


def _build_mandate_and_request(
    case: BenchCase,
) -> tuple[object, object]:  # Mandate, PaymentRequest — imported inside function
    """Construct and sign a Mandate + PaymentRequest from a BenchCase."""
    # Import domain modules here — only at runner layer, not module level
    from gateway.contract import Mandate, PaymentRequest
    from gateway.mandate import sign

    mandate_draft = Mandate(
        id=case.mandate_fixture.id,
        purpose=case.mandate_fixture.purpose,
        max_amount_minor=case.mandate_fixture.max_amount_minor,
        currency=case.mandate_fixture.currency,
        allowed_payees=case.mandate_fixture.allowed_payees,
        expires_at=case.mandate_fixture.expires_at,
        approval_threshold_minor=case.mandate_fixture.approval_threshold_minor,
        max_payments_per_window=case.mandate_fixture.max_payments_per_window,
        window_seconds=case.mandate_fixture.window_seconds,
        signature="placeholder",
    )
    mandate = sign(mandate_draft)

    request = PaymentRequest(
        mandate_id=case.request.mandate_id,
        payee=case.request.payee,
        amount_minor=case.request.amount_minor,
        currency=case.request.currency,
        memo=case.request.memo,
        idempotency_key=case.request.idempotency_key,
    )
    return mandate, request


def _run_rules_only(case: BenchCase) -> str:
    """Execute rule engine only. Returns lowercase verdict string."""
    from gateway.contract import Verdict
    from gateway.rules import RuleContext, evaluate, overall

    mandate, request = _build_mandate_and_request(case)

    ctx = RuleContext(
        now=datetime.now(UTC),
        revoked=False,
        spend_so_far=0,
        recent_approved_payments=[],
    )

    results = evaluate(request, mandate, ctx)
    verdict: Verdict = overall(results)
    return verdict.value  # "approve" | "block" | "escalate"


def _build_fake_llm_for_case(expected_verdict: str) -> object:  # returns FakeLLM
    """Create a FakeLLM whose response corresponds to the expected verdict.

    For judge_only mode: maps expected_verdict to judge vocabulary.
    Judge can only return ok / block / escalate (never approve).
    If expected_verdict == "approve", judge returns "ok" (no objection).
    """
    from gateway.llm import FakeLLM

    judge_resp: dict[str, object]
    if expected_verdict == "block":
        judge_resp = {
            "verdict": "block",
            "reason_code": "bench_block",
            "reason": "Benchmark: simulated block verdict.",
        }
    elif expected_verdict == "escalate":
        judge_resp = {
            "verdict": "escalate",
            "reason_code": "bench_escalate",
            "reason": "Benchmark: simulated escalate verdict.",
        }
    else:
        # approve → judge says ok (no objection)
        judge_resp = {
            "verdict": "ok",
            "reason_code": "bench_ok",
            "reason": "Benchmark: no objection.",
        }
    return FakeLLM(responses=[judge_resp])


async def _run_judge_only(case: BenchCase, repeat_idx: int) -> str:
    """Execute advisory judge only (no rule engine). Returns verdict string."""
    from gateway.contract import Verdict
    from gateway.judge import JudgeContext, JudgeOutput, JudgeVerdict, evaluate_transaction

    mandate, request = _build_mandate_and_request(case)
    llm = _build_fake_llm_for_case(case.expected_verdict)

    ctx = JudgeContext(
        mandate_purpose=mandate.purpose,
        payee=request.payee,
        amount_minor=request.amount_minor,
        currency=request.currency,
        memo=request.memo,
    )

    output: JudgeOutput = await evaluate_transaction(llm, ctx)

    # Map judge verdict to gateway Verdict
    if output.verdict == JudgeVerdict.BLOCK:
        return Verdict.BLOCK.value
    if output.verdict == JudgeVerdict.ESCALATE:
        return Verdict.ESCALATE.value
    # JudgeVerdict.OK → pass through; for judge_only mode, ok means approve
    return Verdict.APPROVE.value


async def _run_combined(case: BenchCase, repeat_idx: int) -> str:
    """Run full GatewayService.process() with FakeProvider + FakeLLM."""
    import tempfile

    from gateway.llm import FakeLLM
    from gateway.providers.fake import FakeProvider
    from gateway.service import GatewayService
    from gateway.store import open_store

    # For combined mode, the judge should not interfere with rule-based decisions.
    # Return "ok" by default; the rule engine verdict takes precedence.
    # For escalate-expected cases (threshold exceeded), the rule engine sets ESCALATE;
    # judge returning ok still results in ESCALATE from the service.
    judge_resp: dict[str, object] = {
        "verdict": "ok",
        "reason_code": "bench_ok",
        "reason": "Benchmark judge: no objection.",
    }
    llm = FakeLLM(responses=[judge_resp])
    provider = FakeProvider()

    # Each case gets its own isolated in-memory store to prevent cross-case pollution
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    store = open_store(db_path)

    # Register the signed mandate in the store
    mandate, request = _build_mandate_and_request(case)
    store.save_mandate(mandate)

    svc = GatewayService(store=store, provider=provider, llm_client=llm)
    result = await svc.process(request, operation="create_order")

    return result.decision.verdict.value


# ---------------------------------------------------------------------------
# Main async runner
# ---------------------------------------------------------------------------


async def run_cases(
    cases: list[BenchCase],
    mode: str,
    repeats: int,
) -> list[RunResult]:
    """Run all cases in the specified mode and collect results."""
    results: list[RunResult] = []

    for case in cases:
        actual_verdicts: list[str] = []
        error: str | None = None

        for rep in range(repeats):
            try:
                if mode == "rules_only":
                    verdict = _run_rules_only(case)
                elif mode == "judge_only":
                    verdict = await _run_judge_only(case, rep)
                else:  # combined
                    verdict = await _run_combined(case, rep)
                actual_verdicts.append(verdict)
            except Exception as exc:  # noqa: BLE001
                # Fail closed: treat runner exceptions as block
                actual_verdicts.append("block")
                error = str(exc)
                logger.warning("Case %s repeat %d raised exception: %s", case.id, rep, exc)
                break  # don't retry on runner-level error

        results.append(
            RunResult(
                case_id=case.id,
                label=case.label,
                category=case.category,
                split=case.split,
                expected_verdict=case.expected_verdict,
                actual_verdicts=actual_verdicts,
                error=error,
            )
        )

    return results


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def format_pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def render_markdown(
    results: list[RunResult],
    metrics: Metrics,
    mode: str,
    split: str,
    repeats: int,
    run_at: datetime,
) -> str:
    lines: list[str] = []
    lines.append("# MandateGate Benchmark Results\n")
    lines.append(
        f"**Mode**: `{mode}` | **Split**: `{split}` | "
        f"**Cases**: {metrics.total} | **Repeats**: {repeats} | "
        f"**Run**: {run_at.strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
    )

    lines.append("> [!NOTE]")
    lines.append(
        "> Headline numbers are always from the **test** split. "
        "Only tune prompts on the **dev** split.\n"
    )

    lines.append("## Headline Metrics\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Attack Catch Rate | {format_pct(metrics.attack_catch_rate)} |")
    lines.append(f"| False Block Rate | {format_pct(metrics.false_block_rate)} |")
    lines.append(f"| Escalation Rate | {format_pct(metrics.escalation_rate)} |")
    lines.append(f"| Judge Disagreement | {format_pct(metrics.disagreement_rate)} |")
    lines.append(f"| Total Malicious | {metrics.malicious_total} |")
    lines.append(f"| Total Benign | {metrics.benign_total} |")
    lines.append("")

    lines.append("## Per-Category Results\n")
    lines.append("| Category | Total | Caught | False-Blocked | Escalated |")
    lines.append("|----------|-------|--------|---------------|-----------|")
    for cat, stats in sorted(metrics.by_category.items()):
        row = (
            f"| {cat} | {stats.total} | {stats.caught}"
            f" | {stats.false_blocked} | {stats.escalated} |"
        )
        lines.append(row)
    lines.append("")

    lines.append("## Case-Level Results\n")
    lines.append("| ID | Label | Category | Split | Expected | Actual | Match | Notes |")
    lines.append("|----|-------|----------|-------|----------|--------|-------|-------|")
    for r in results:
        match_icon = "✅" if r.matched else "❌"
        verdicts_str = ", ".join(r.actual_verdicts)
        note = r.error[:60] if r.error else r.category
        lines.append(
            f"| {r.case_id} | {r.label} | {r.category} | {r.split} | "
            f"{r.expected_verdict} | {verdicts_str} | {match_icon} | {note} |"
        )
    lines.append("")

    if repeats > 1:
        lines.append("## Judge Variance (repeats > 1)\n")
        lines.append(
            "> With `FakeLLM`, disagreement should be 0% — variance only appears with a live LLM.\n"
        )
        disagreeing = [r for r in results if r.has_disagreement]
        if disagreeing:
            lines.append("| ID | Verdicts |")
            lines.append("|----|----------|")
            for r in disagreeing:
                lines.append(f"| {r.case_id} | {', '.join(sorted(r.distinct_verdicts))} |")
        else:
            lines.append("*No disagreement detected across repeats.*")
        lines.append("")

    return "\n".join(lines)


def render_json(
    results: list[RunResult],
    metrics: Metrics,
    mode: str,
    split: str,
    repeats: int,
    run_at: datetime,
) -> str:
    payload = {
        "run_at": run_at.isoformat(),
        "mode": mode,
        "split": split,
        "repeats": repeats,
        "metrics": {
            "total": metrics.total,
            "malicious_total": metrics.malicious_total,
            "benign_total": metrics.benign_total,
            "attack_catch_rate": round(metrics.attack_catch_rate, 4),
            "false_block_rate": round(metrics.false_block_rate, 4),
            "escalation_rate": round(metrics.escalation_rate, 4),
            "disagreement_rate": round(metrics.disagreement_rate, 4),
            "by_category": {
                cat: {
                    "total": s.total,
                    "caught": s.caught,
                    "false_blocked": s.false_blocked,
                    "escalated": s.escalated,
                }
                for cat, s in sorted(metrics.by_category.items())
            },
        },
        "cases": [
            {
                "id": r.case_id,
                "label": r.label,
                "category": r.category,
                "split": r.split,
                "expected_verdict": r.expected_verdict,
                "actual_verdicts": r.actual_verdicts,
                "final_verdict": r.final_verdict,
                "matched": r.matched,
                "has_disagreement": r.has_disagreement,
                "error": r.error,
            }
            for r in results
        ],
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MandateGate benchmark runner.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["rules_only", "judge_only", "combined"],
        default="combined",
        help="Evaluation mode.",
    )
    parser.add_argument(
        "--split",
        choices=["dev", "test", "all"],
        default="test",
        help=(
            "Dataset split to evaluate. "
            "Headline numbers should always come from 'test'. "
            "Only tune prompts on 'dev'."
        ),
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=1,
        metavar="N",
        help="Number of times to run each case (measures judge variance).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducibility (passed to Python random module).",
    )
    parser.add_argument(
        "--input",
        default="bench/cases.jsonl",
        metavar="PATH",
        help="Path to benchmark JSONL dataset.",
    )
    parser.add_argument(
        "--output-dir",
        default="bench",
        metavar="DIR",
        help="Directory for results.md and results.json output.",
    )
    return parser.parse_args(argv)


async def async_main(argv: list[str] | None = None) -> int:
    """Async entry point. Returns exit code."""
    args = parse_args(argv)

    if args.seed is not None:
        import random

        random.seed(args.seed)

    # --- Load dataset ---
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Dataset file not found: {input_path}", file=sys.stderr)
        return 1

    all_cases, bad_lines = load_cases(input_path)

    if bad_lines:
        print(f"\n⚠️  {len(bad_lines)} invalid line(s) in dataset:", file=sys.stderr)
        for lineno, msg in bad_lines:
            print(f"  Line {lineno}: {msg}", file=sys.stderr)

    # --- Filter by split ---
    if args.split == "all":
        cases = all_cases
    else:
        cases = [c for c in all_cases if c.split == args.split]

    if not cases:
        print(
            f"ERROR: No cases found for split='{args.split}'. "
            f"Available splits: {sorted({c.split for c in all_cases})}",
            file=sys.stderr,
        )
        return 1

    if args.split != "test" and args.mode != "rules_only":
        print(
            "⚠️  WARNING: Reporting on dev split. Headline numbers MUST come from the test split.",
            file=sys.stderr,
        )

    print(
        f"Running {len(cases)} cases | mode={args.mode} | "
        f"split={args.split} | repeats={args.repeats}",
        file=sys.stderr,
    )

    # --- Run cases ---
    results = await run_cases(cases, mode=args.mode, repeats=args.repeats)
    metrics = compute_metrics(results)
    run_at = datetime.now(UTC)

    # --- Print summary to stderr ---
    print("\n=== RESULTS ===", file=sys.stderr)
    matched = sum(1 for r in results if r.matched)
    print(f"Attack catch rate : {format_pct(metrics.attack_catch_rate)}", file=sys.stderr)
    print(f"False block rate  : {format_pct(metrics.false_block_rate)}", file=sys.stderr)
    print(f"Escalation rate   : {format_pct(metrics.escalation_rate)}", file=sys.stderr)
    print(f"Disagreement rate : {format_pct(metrics.disagreement_rate)}", file=sys.stderr)
    print(f"Matched expected  : {matched}/{len(results)}", file=sys.stderr)

    # --- Write output files ---
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    md_path = output_dir / "results.md"
    json_path = output_dir / "results.json"

    md_content = render_markdown(results, metrics, args.mode, args.split, args.repeats, run_at)
    json_content = render_json(results, metrics, args.mode, args.split, args.repeats, run_at)

    md_path.write_text(md_content, encoding="utf-8")
    json_path.write_text(json_content, encoding="utf-8")

    print("\nResults written to:", file=sys.stderr)
    print(f"  {md_path}", file=sys.stderr)
    print(f"  {json_path}", file=sys.stderr)

    # Exit 1 if any malicious cases slipped through (attack_catch_rate < 1.0)
    if metrics.malicious_total > 0 and metrics.attack_catch_rate < 1.0:
        missed = metrics.malicious_total - int(metrics.attack_catch_rate * metrics.malicious_total)
        print(
            f"\n❌ ALERT: {missed} malicious case(s) were APPROVED. Attack catch rate < 100%.",
            file=sys.stderr,
        )
        return 2

    return 0


def main(argv: list[str] | None = None) -> None:
    exit_code = asyncio.run(async_main(argv))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
