"""
gateway.service

Core gateway orchestrator mediating agent payment requests, deterministic
mandate policies, advisory AI safety evaluations, persistence, and payment providers.

Core Invariants:
1. Agent NEVER supplies signatures or limits (only mandate_id and payment details).
2. Mandates are loaded securely by id and verified.
3. Rule engine executes first; advisory AI Safety Judge executes ONLY if all rules pass.
4. APPROVE: Atomically reserves spend in SQLite, then calls PaymentProvider.
5. ESCALATE: Creates pending approval record in SQLite; NEVER calls provider.
6. BLOCK: Logs failure diagnostic; NEVER calls provider.
7. Every outcome writes a hash-chained decision audit row.
8. FAIL CLOSED: Any unhandled exception defaults to BLOCK.
9. No imports of FastAPI or MCP.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from gateway.contract import Decision, PaymentRequest, RuleResult, Verdict
from gateway.judge import JudgeContext, JudgeVerdict, evaluate_transaction
from gateway.llm import LLMClient
from gateway.providers.base import PaymentProvider, ProviderPaymentResult
from gateway.rules import HistoricalPayment, RuleContext, evaluate, overall
from gateway.store import MandateStore

logger = logging.getLogger("gateway.service")


class GatewayResult(BaseModel):
    """Result of processing a payment request through MandateGate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Decision = Field(..., description="Audit decision with verdict and rule traces.")
    provider_result: ProviderPaymentResult | None = Field(
        default=None,
        description="Provider transaction result if payment was approved and executed.",
    )

    @property
    def verdict(self) -> Verdict:
        """Convenience property for accessing the decision verdict."""
        return self.decision.verdict


class GatewayService:
    """Core payment gateway service coordinating policies, safety judge, and providers."""

    def __init__(
        self,
        store: MandateStore,
        provider: PaymentProvider,
        llm_client: LLMClient,
    ) -> None:
        self.store = store
        self.provider = provider
        self.llm_client = llm_client

    async def process(
        self,
        request: PaymentRequest,
        operation: str = "create_order",
    ) -> GatewayResult:
        """Process an agent payment request from authorization through execution.

        Fails closed on any unexpected error or exception.
        """
        decision_id = f"dec_{uuid4().hex[:16]}"
        created_at = datetime.now(UTC)

        try:
            # 1. Load mandate by ID (agent never supplies signature or limits)
            mandate = self.store.load_mandate(request.mandate_id)
            if mandate is None:
                logger.warning(
                    "Mandate '%s' not found. Failing closed to BLOCK.",
                    request.mandate_id,
                )
                missing_rule = RuleResult(
                    name="mandate_exists",
                    passed=False,
                    detail=f"Mandate '{request.mandate_id}' not found.",
                )
                decision = Decision(
                    id=decision_id,
                    verdict=Verdict.BLOCK,
                    rule_results=[missing_rule],
                    judge_reason=None,
                    created_at=created_at,
                )
                self.store.save_decision(decision, mandate_id=request.mandate_id)
                return GatewayResult(decision=decision, provider_result=None)

            # 2. Build execution context from persistent state
            history_dicts = self.store.list_recent_spends(request.mandate_id)
            history: list[HistoricalPayment] = []
            for h in history_dicts:
                try:
                    history.append(
                        HistoricalPayment(
                            payee=h.get("payee") or "unknown",
                            amount_minor=h["amount_minor"],
                            currency=h["currency"],
                            memo=h.get("memo") or "",
                            idempotency_key=h.get("idempotency_key") or "",
                            created_at=datetime.fromisoformat(h["recorded_at"]),
                        )
                    )
                except Exception:
                    continue

            is_revoked = self.store.is_revoked(request.mandate_id)
            spend_so_far = self.store.total_spent(request.mandate_id)
            ctx = RuleContext(
                now=created_at,
                revoked=is_revoked,
                spend_so_far=spend_so_far,
                recent_approved_payments=history,
            )

            # 3. Deterministic rule engine evaluation
            rule_results = evaluate(request, mandate, ctx)
            rule_verdict = overall(rule_results)

            # 4. Handle immediate blocking rule failures
            if rule_verdict == Verdict.BLOCK:
                failed_names = [r.name for r in rule_results if not r.passed]
                logger.warning(
                    "Payment blocked by deterministic rules (%s) for mandate '%s'.",
                    ", ".join(failed_names),
                    mandate.id,
                )
                decision = Decision(
                    id=decision_id,
                    verdict=Verdict.BLOCK,
                    rule_results=rule_results,
                    judge_reason=None,
                    created_at=created_at,
                )
                self.store.save_decision(decision, mandate_id=mandate.id)
                return GatewayResult(decision=decision, provider_result=None)

            # 5. Handle rule engine human escalation requirement (needs_human)
            if rule_verdict == Verdict.ESCALATE:
                logger.info(
                    "Payment exceeds threshold under mandate '%s'. Escalating to human.",
                    mandate.id,
                )
                approval_id = f"appr_{uuid4().hex[:16]}"
                decision = Decision(
                    id=decision_id,
                    verdict=Verdict.ESCALATE,
                    rule_results=rule_results,
                    judge_reason=None,
                    created_at=created_at,
                )
                self.store.save_decision(decision, mandate_id=mandate.id)
                self.store.save_pending_approval(
                    approval_id=approval_id,
                    decision_id=decision_id,
                    mandate_id=mandate.id,
                    amount_minor=request.amount_minor,
                    currency=request.currency,
                    payee=request.payee,
                    memo=request.memo,
                )
                return GatewayResult(decision=decision, provider_result=None)

            # 6. Rules passed! Execute advisory AI Safety Judge
            judge_summary = (
                f"Total spend so far: {spend_so_far} {mandate.currency} across "
                f"{len(history)} approved payments."
            )
            judge_ctx = JudgeContext(
                mandate_purpose=mandate.purpose,
                payee=request.payee,
                amount_minor=request.amount_minor,
                currency=request.currency,
                prior_payments_summary=judge_summary,
                memo=request.memo,
            )

            judge_output = await evaluate_transaction(self.llm_client, judge_ctx)
            judge_reason = f"{judge_output.reason_code}: {judge_output.reason}"

            if judge_output.verdict == JudgeVerdict.BLOCK:
                logger.warning(
                    "Payment blocked by AI Safety Judge (%s) for mandate '%s'.",
                    judge_reason,
                    mandate.id,
                )
                decision = Decision(
                    id=decision_id,
                    verdict=Verdict.BLOCK,
                    rule_results=rule_results,
                    judge_reason=judge_reason,
                    created_at=created_at,
                )
                self.store.save_decision(decision, mandate_id=mandate.id)
                return GatewayResult(decision=decision, provider_result=None)

            if judge_output.verdict == JudgeVerdict.ESCALATE:
                logger.info(
                    "Payment escalated by AI Safety Judge (%s) for mandate '%s'.",
                    judge_reason,
                    mandate.id,
                )
                approval_id = f"appr_{uuid4().hex[:16]}"
                decision = Decision(
                    id=decision_id,
                    verdict=Verdict.ESCALATE,
                    rule_results=rule_results,
                    judge_reason=judge_reason,
                    created_at=created_at,
                )
                self.store.save_decision(decision, mandate_id=mandate.id)
                self.store.save_pending_approval(
                    approval_id=approval_id,
                    decision_id=decision_id,
                    mandate_id=mandate.id,
                    amount_minor=request.amount_minor,
                    currency=request.currency,
                    payee=request.payee,
                    memo=request.memo,
                )
                return GatewayResult(decision=decision, provider_result=None)

            # 7. Both rules and judge approved (judge returned 'ok')
            # Atomically reserve spend in SQLite BEGIN IMMEDIATE transaction
            reserved = self.store.reserve_spend(
                mandate_id=mandate.id,
                decision_id=decision_id,
                amount_minor=request.amount_minor,
                currency=request.currency,
                payee=request.payee,
                memo=request.memo,
                idempotency_key=request.idempotency_key,
            )

            if not reserved:
                logger.warning(
                    "Atomic spend reservation failed (budget exhausted) for mandate '%s'.",
                    mandate.id,
                )
                budget_fail = RuleResult(
                    name="reserve_spend",
                    passed=False,
                    detail="Atomic spend reservation failed due to concurrent budget exhaustion.",
                )
                decision = Decision(
                    id=decision_id,
                    verdict=Verdict.BLOCK,
                    rule_results=[*rule_results, budget_fail],
                    judge_reason=judge_reason,
                    created_at=created_at,
                )
                self.store.save_decision(decision, mandate_id=mandate.id)
                return GatewayResult(decision=decision, provider_result=None)

            # 8. Call Payment Provider
            provider_result: ProviderPaymentResult
            if operation == "pay_invoice":
                provider_result = await self.provider.pay_invoice(
                    amount_minor=request.amount_minor,
                    currency=request.currency,
                    payee=request.payee,
                    memo=request.memo,
                    idempotency_key=request.idempotency_key,
                )
            elif operation == "send_payout":
                provider_result = await self.provider.send_payout(
                    amount_minor=request.amount_minor,
                    currency=request.currency,
                    payee=request.payee,
                    memo=request.memo,
                    idempotency_key=request.idempotency_key,
                )
            else:
                provider_result = await self.provider.create_order(
                    amount_minor=request.amount_minor,
                    currency=request.currency,
                    payee=request.payee,
                    memo=request.memo,
                    idempotency_key=request.idempotency_key,
                )

            decision = Decision(
                id=decision_id,
                verdict=Verdict.APPROVE,
                rule_results=rule_results,
                judge_reason=judge_reason,
                created_at=created_at,
            )
            self.store.save_decision(decision, mandate_id=mandate.id)
            return GatewayResult(decision=decision, provider_result=provider_result)

        except Exception as exc:
            # FAIL CLOSED: Any unhandled exception or crash defaults to BLOCK
            logger.warning(
                "GatewayService processing exception (failing closed to BLOCK): %s: %s",
                type(exc).__name__,
                str(exc),
            )
            error_rule = RuleResult(
                name="gateway_error",
                passed=False,
                detail=f"Unhandled internal gateway error: {type(exc).__name__}.",
            )
            decision = Decision(
                id=decision_id,
                verdict=Verdict.BLOCK,
                rule_results=[error_rule],
                judge_reason=None,
                created_at=created_at,
            )
            try:
                self.store.save_decision(decision, mandate_id=request.mandate_id)
            except Exception as store_err:
                logger.warning(
                    "Failed to record error decision to audit store: %s",
                    store_err,
                )
            return GatewayResult(decision=decision, provider_result=None)
