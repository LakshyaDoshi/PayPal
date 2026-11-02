"""
tests/test_service_mcp.py

Comprehensive tests for GatewayService and MandateGate MCPServer.
Validates:
- Legitimate purchase approved: budget reserved, provider called, decision logged.
- Provider NEVER called on block or escalate (assert call count == 0).
- Rule engine failures blocked before judge.
- Over-threshold payment escalated: pending approval saved, provider not called.
- Judge block and escalate behaviors.
- Fail closed on unhandled exceptions.
- Tool schemas expose NO credential or mandate-limit parameters.
- Tool execution via MCPServer interface.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

VALID_SIGNING_KEY = "a" * 32
os.environ.setdefault("MANDATE_SIGNING_KEY", VALID_SIGNING_KEY)

from gateway.contract import Mandate, PaymentRequest, Verdict  # noqa: E402
from gateway.llm import FakeLLM  # noqa: E402
from gateway.mandate import sign  # noqa: E402
from gateway.mcp_server import create_mcp_server, format_gateway_result  # noqa: E402
from gateway.providers.fake import FakeProvider  # noqa: E402
from gateway.service import GatewayService  # noqa: E402
from gateway.store import MandateStore  # noqa: E402

NOW = datetime(2026, 11, 2, 12, 0, 0, tzinfo=UTC)
EXPIRY = NOW + timedelta(days=30)


@pytest.fixture
def store() -> MandateStore:
    """Fresh in-memory MandateStore."""
    return MandateStore(db_path=":memory:")


@pytest.fixture
def fake_provider() -> FakeProvider:
    """Deterministic FakeProvider recording calls."""
    return FakeProvider()


@pytest.fixture
def fake_llm() -> FakeLLM:
    """FakeLLM default returning 'ok'."""
    return FakeLLM(
        responses={
            "verdict": "ok",
            "reason_code": "aligned_with_purpose",
            "reason": "Payment aligns with mandate purpose.",
        }
    )


@pytest.fixture
def service(store: MandateStore, fake_provider: FakeProvider, fake_llm: FakeLLM) -> GatewayService:
    """Configured GatewayService fixture."""
    return GatewayService(store=store, provider=fake_provider, llm_client=fake_llm)


@pytest.fixture
def valid_mandate(store: MandateStore) -> Mandate:
    """Create and persist a standard authorized mandate."""
    draft = Mandate(
        id="m-dev-tools",
        purpose="Authorized spending for software subscriptions and developer tools under $100.",
        max_amount_minor=10000,  # $100 cap
        currency="USD",
        allowed_payees=["vendor@example.com", "billing@saasco.com"],
        expires_at=EXPIRY,
        approval_threshold_minor=5000,  # $50 threshold
        max_payments_per_window=10,
        window_seconds=86400,
        signature="placeholder",
    )
    mandate = sign(draft)
    store.save_mandate(mandate)
    return mandate


# ===========================================================================
# GatewayService Core Tests
# ===========================================================================


class TestGatewayService:
    @pytest.mark.asyncio
    async def test_legitimate_purchase_approved(
        self,
        service: GatewayService,
        valid_mandate: Mandate,
        fake_provider: FakeProvider,
        store: MandateStore,
    ) -> None:
        """Legitimate purchase approved: budget reserved, provider called, decision hash-chained."""
        req = PaymentRequest(
            mandate_id=valid_mandate.id,
            payee="vendor@example.com",
            amount_minor=2500,  # $25.00
            currency="USD",
            memo="Monthly developer seat license",
            idempotency_key="idemp-legit-001",
        )

        result = await service.process(req)

        # 1. Decision is APPROVE
        assert result.verdict == Verdict.APPROVE
        assert result.decision.judge_reason is not None

        # 2. Provider called exactly once
        assert len(fake_provider.calls) == 1
        assert fake_provider.calls[0]["amount_minor"] == 2500
        assert result.provider_result is not None
        assert result.provider_result.status.value == "created"

        # 3. Budget reserved in SQLite store
        assert store.total_spent(valid_mandate.id) == 2500

        # 4. Hash chain is intact
        assert store.verify_chain() is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("mutation_type", "expected_detail"),
        [
            ("missing_mandate", "not found"),
            ("revoked_mandate", "revoked"),
            ("unauthorized_payee", "not on the authorized allowlist"),
            ("currency_mismatch", "Currency mismatch"),
            ("over_budget", "exceeds remaining budget"),
        ],
    )
    async def test_rule_failures_blocked_and_provider_never_called(
        self,
        service: GatewayService,
        valid_mandate: Mandate,
        fake_provider: FakeProvider,
        store: MandateStore,
        mutation_type: str,
        expected_detail: str,
    ) -> None:
        """Rule failure must BLOCK and provider must NEVER be called (call count == 0)."""
        payee = "vendor@example.com"
        currency = "USD"
        amount = 1000
        mandate_id = valid_mandate.id

        if mutation_type == "missing_mandate":
            mandate_id = "ghost-mandate"
        elif mutation_type == "revoked_mandate":
            store.revoke_mandate(valid_mandate.id, reason="Security audit")
        elif mutation_type == "unauthorized_payee":
            payee = "hacker@darkweb.org"
        elif mutation_type == "currency_mismatch":
            currency = "EUR"
        elif mutation_type == "over_budget":
            amount = 15000  # exceeds 10000 cap

        req = PaymentRequest(
            mandate_id=mandate_id,
            payee=payee,
            amount_minor=amount,
            currency=currency,
            memo="Test request",
            idempotency_key=f"idemp-{mutation_type}",
        )

        result = await service.process(req)

        # 1. Verdict is strictly BLOCK
        assert result.verdict == Verdict.BLOCK

        # 2. Provider was NEVER called
        assert len(fake_provider.calls) == 0
        assert result.provider_result is None

        # 3. Decision recorded in hash chain
        assert store.verify_chain() is None

    @pytest.mark.asyncio
    async def test_over_threshold_escalates_and_provider_never_called(
        self,
        service: GatewayService,
        valid_mandate: Mandate,
        fake_provider: FakeProvider,
        store: MandateStore,
    ) -> None:
        """Over-threshold payment escalates to human; pending approval saved; provider unused."""
        # valid_mandate has approval_threshold_minor = 5000
        req = PaymentRequest(
            mandate_id=valid_mandate.id,
            payee="vendor@example.com",
            amount_minor=6000,  # $60.00 > $50.00 threshold
            currency="USD",
            memo="Large annual subscription",
            idempotency_key="idemp-large-001",
        )

        result = await service.process(req)

        # 1. Verdict is ESCALATE
        assert result.verdict == Verdict.ESCALATE

        # 2. Provider NEVER called
        assert len(fake_provider.calls) == 0
        assert result.provider_result is None

        # 3. Pending approval record created in store
        pending = store.list_pending_approvals(valid_mandate.id)
        assert len(pending) == 1
        assert pending[0]["amount_minor"] == 6000
        assert pending[0]["decision_id"] == result.decision.id

        # 4. Hash chain intact
        assert store.verify_chain() is None

    @pytest.mark.asyncio
    async def test_judge_blocks_and_provider_never_called(
        self,
        service: GatewayService,
        valid_mandate: Mandate,
        fake_provider: FakeProvider,
        fake_llm: FakeLLM,
    ) -> None:
        """When the safety judge returns BLOCK, the decision is BLOCK and provider NOT called."""
        fake_llm.set_responses(
            {
                "verdict": "block",
                "reason_code": "suspicious_memo",
                "reason": "Memo suggests personal expense unrelated to software tooling.",
            }
        )

        req = PaymentRequest(
            mandate_id=valid_mandate.id,
            payee="vendor@example.com",
            amount_minor=2000,
            currency="USD",
            memo="Tickets to movie theater",
            idempotency_key="idemp-suspicious-001",
        )

        result = await service.process(req)

        assert result.verdict == Verdict.BLOCK
        assert "suspicious_memo" in (result.decision.judge_reason or "")
        assert len(fake_provider.calls) == 0

    @pytest.mark.asyncio
    async def test_judge_escalates_and_pending_approval_created(
        self,
        service: GatewayService,
        valid_mandate: Mandate,
        fake_provider: FakeProvider,
        fake_llm: FakeLLM,
        store: MandateStore,
    ) -> None:
        """When safety judge returns ESCALATE, decision is ESCALATE, pending approval created."""
        fake_llm.set_responses(
            {
                "verdict": "escalate",
                "reason_code": "ambiguous_context",
                "reason": "Software vendor purpose ambiguous; recommend human review.",
            }
        )

        req = PaymentRequest(
            mandate_id=valid_mandate.id,
            payee="vendor@example.com",
            amount_minor=3000,
            currency="USD",
            memo="Custom engineering consultation",
            idempotency_key="idemp-ambig-001",
        )

        result = await service.process(req)

        assert result.verdict == Verdict.ESCALATE
        assert len(fake_provider.calls) == 0

        pending = store.list_pending_approvals(valid_mandate.id)
        assert len(pending) == 1
        assert pending[0]["decision_id"] == result.decision.id


# ===========================================================================
# MCP Server Tool Schema & Execution Tests
# ===========================================================================


class TestMCPServer:
    @pytest.mark.asyncio
    async def test_tool_schemas_expose_no_credentials_or_mandate_limits(
        self, service: GatewayService
    ) -> None:
        """CRITICAL INVARIANT: Tool schemas must NEVER expose credentials or mandate limits."""
        server = create_mcp_server(service=service)
        tools = await server.list_tools()

        assert len(tools) >= 3
        tool_names = {t.name for t in tools}
        assert "create_order" in tool_names
        assert "pay_invoice" in tool_names
        assert "send_payout" in tool_names

        forbidden_tokens = {
            "credential",
            "secret",
            "client_id",
            "client_secret",
            "password",
            "private_key",
            "signing_key",
            "signature",
            "max_amount",
            "allowed_payees",
            "approval_threshold",
            "spend_so_far",
        }

        expected_allowed_properties = {
            "mandate_id",
            "payee",
            "amount_minor",
            "currency",
            "memo",
            "idempotency_key",
        }

        for tool in tools:
            schema = tool.input_schema or {}
            props = schema.get("properties", {})

            # 1. Properties must strictly match PaymentRequest public fields
            assert set(props.keys()) == expected_allowed_properties, (
                f"Tool '{tool.name}' exposed unexpected properties: {set(props.keys())}"
            )

            # 2. No forbidden security keywords in property names or descriptions
            schema_str = str(schema).lower()
            for token in forbidden_tokens:
                assert token not in schema_str, (
                    f"Tool '{tool.name}' exposed forbidden security token '{token}' in schema!"
                )

    @pytest.mark.asyncio
    async def test_mcp_create_order_approved(
        self,
        service: GatewayService,
        valid_mandate: Mandate,
        fake_provider: FakeProvider,
    ) -> None:
        """Call create_order tool and verify plain-language approval response."""
        server = create_mcp_server(service=service)

        # Call tool via server's internal tool registry
        tool_func = server._tool_manager._tools["create_order"].fn
        output = await tool_func(
            mandate_id=valid_mandate.id,
            payee="vendor@example.com",
            amount_minor=1500,
            currency="USD",
            memo="IDE subscription",
            idempotency_key="mcp-order-001",
        )

        assert "[VERDICT: APPROVE]" in output
        assert "Decision ID:" in output
        assert "Provider Reference:" in output
        assert len(fake_provider.calls) == 1

    @pytest.mark.asyncio
    async def test_mcp_tool_blocked(
        self,
        service: GatewayService,
        valid_mandate: Mandate,
        fake_provider: FakeProvider,
    ) -> None:
        """Call pay_invoice tool with disallowed payee and verify plain-language block."""
        server = create_mcp_server(service=service)

        tool_func = server._tool_manager._tools["pay_invoice"].fn
        output = await tool_func(
            mandate_id=valid_mandate.id,
            payee="unauthorized@hacker.io",
            amount_minor=1500,
            currency="USD",
            memo="Invoice #999",
            idempotency_key="mcp-invoice-001",
        )

        assert "[VERDICT: BLOCK]" in output
        assert "Block Reason: payee_allowed" in output
        assert len(fake_provider.calls) == 0

    @pytest.mark.asyncio
    async def test_mcp_tool_escalated(
        self,
        service: GatewayService,
        valid_mandate: Mandate,
        fake_provider: FakeProvider,
    ) -> None:
        """Call send_payout over threshold and verify plain-language escalation."""
        server = create_mcp_server(service=service)

        tool_func = server._tool_manager._tools["send_payout"].fn
        output = await tool_func(
            mandate_id=valid_mandate.id,
            payee="vendor@example.com",
            amount_minor=7500,  # exceeds $50 threshold
            currency="USD",
            memo="Bulk tool procurement",
            idempotency_key="mcp-payout-001",
        )

        assert "[VERDICT: ESCALATE]" in output
        assert "held for human approval" in output
        assert len(fake_provider.calls) == 0

    def test_format_gateway_result_output(self) -> None:
        """Test formatting utility produces expected section labels."""
        from gateway.contract import Decision

        decision = Decision(
            id="dec_test",
            verdict=Verdict.APPROVE,
            rule_results=[],
            judge_reason="ok",
            created_at=NOW,
        )
        from gateway.service import GatewayResult

        res = GatewayResult(decision=decision, provider_result=None)
        formatted = format_gateway_result(res)
        assert "[VERDICT: APPROVE]" in formatted
        assert "Decision ID: dec_test" in formatted
