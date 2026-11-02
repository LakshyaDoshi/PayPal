"""
gateway.mcp_server

MCP (Model Context Protocol) Server for MandateGate.
Exposes payment execution tools to AI agents over stdio or Streamable HTTP.

Security & Architecture Invariants:
1. Tool inputs are strictly PaymentRequest fields (minus signature and limits).
2. No credential parameters (client_id, secret, api_key) are ever exposed in tool schemas.
3. No mandate limit parameters (max_amount, allowed_payees) are exposed in tool schemas.
4. Clean JSON-RPC communication: NEVER log or write to sys.stdout in MCP stdio mode.
5. All logging is routed strictly to sys.stderr.
6. Returns plain-language human-readable verdicts and diagnostic traces.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from mcp.server.mcpserver import MCPServer

from gateway.contract import PaymentRequest, Verdict
from gateway.llm import get_llm_client
from gateway.providers.base import PaymentProvider
from gateway.providers.fake import FakeProvider
from gateway.providers.paypal import PayPalProvider
from gateway.service import GatewayResult, GatewayService
from gateway.store import open_store

# Ensure standard logging is strictly directed to sys.stderr to protect stdio transport
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("gateway.mcp_server")


def format_gateway_result(result: GatewayResult) -> str:
    """Format a GatewayResult into plain-language text for agents and users."""
    decision = result.decision
    lines = [f"[VERDICT: {decision.verdict.upper()}]"]

    if decision.verdict == Verdict.APPROVE:
        lines.append("Payment request evaluated successfully and executed with payment provider.")
        lines.append(f"Decision ID: {decision.id}")
        if result.provider_result:
            lines.append(f"Provider Reference: {result.provider_result.provider_reference}")
            lines.append(f"Provider Status: {result.provider_result.status.value}")
            if result.provider_result.approval_url:
                lines.append(f"Approval URL: {result.provider_result.approval_url}")
            if result.provider_result.debug_id:
                lines.append(f"Debug ID: {result.provider_result.debug_id}")
    elif decision.verdict == Verdict.ESCALATE:
        lines.append("Payment request exceeds spending threshold and is held for human approval.")
        lines.append(f"Decision ID: {decision.id}")
        for r in decision.rule_results:
            if not r.passed:
                lines.append(f"Rule Flag: {r.name} - {r.detail}")
        if decision.judge_reason:
            lines.append(f"Judge Advisory: {decision.judge_reason}")
    else:  # BLOCK
        lines.append("Payment request blocked by MandateGate security policy.")
        lines.append(f"Decision ID: {decision.id}")
        for r in decision.rule_results:
            if not r.passed:
                lines.append(f"Block Reason: {r.name} - {r.detail}")
        if decision.judge_reason:
            lines.append(f"Judge Reason: {decision.judge_reason}")

    return "\n".join(lines)


def create_default_service() -> GatewayService:
    """Instantiate the default GatewayService using environment configuration."""
    store = open_store()

    client_id = os.environ.get("PAYPAL_CLIENT_ID", "")
    client_secret = os.environ.get("PAYPAL_CLIENT_SECRET", "")

    provider: PaymentProvider
    if client_id and client_secret:
        provider = PayPalProvider()
    else:
        logger.info("PayPal credentials not set in environment. Using FakeProvider.")
        provider = FakeProvider()

    llm_client = get_llm_client()
    return GatewayService(store=store, provider=provider, llm_client=llm_client)


def create_mcp_server(service: GatewayService | None = None) -> MCPServer:
    """Construct and configure the MandateGate MCPServer with registered tools."""
    gw_service = service or create_default_service()
    server = MCPServer(name="mandategate")

    @server.tool()
    async def create_order(
        mandate_id: str,
        payee: str,
        amount_minor: int,
        currency: str,
        memo: str,
        idempotency_key: str,
    ) -> str:
        """Create a payment order against an authorized mandate.

        Parameters
        ----------
        mandate_id:
            Identifier of the pre-authorized mandate authorizing this transaction.
        payee:
            Recipient email address or merchant ID.
        amount_minor:
            Transaction amount in integer minor units (e.g. cents).
        currency:
            3-letter ISO 4217 currency code (e.g. 'USD').
        memo:
            Human-readable justification or item description.
        idempotency_key:
            Unique idempotency key to prevent replay attacks.
        """
        request = PaymentRequest(
            mandate_id=mandate_id,
            payee=payee,
            amount_minor=amount_minor,
            currency=currency,
            memo=memo,
            idempotency_key=idempotency_key,
        )
        result = await gw_service.process(request, operation="create_order")
        return format_gateway_result(result)

    @server.tool()
    async def pay_invoice(
        mandate_id: str,
        payee: str,
        amount_minor: int,
        currency: str,
        memo: str,
        idempotency_key: str,
    ) -> str:
        """Pay an invoice against an authorized mandate.

        Parameters
        ----------
        mandate_id:
            Identifier of the pre-authorized mandate authorizing this transaction.
        payee:
            Recipient email address or merchant ID.
        amount_minor:
            Transaction amount in integer minor units (e.g. cents).
        currency:
            3-letter ISO 4217 currency code (e.g. 'USD').
        memo:
            Human-readable justification or invoice description.
        idempotency_key:
            Unique idempotency key to prevent replay attacks.
        """
        request = PaymentRequest(
            mandate_id=mandate_id,
            payee=payee,
            amount_minor=amount_minor,
            currency=currency,
            memo=memo,
            idempotency_key=idempotency_key,
        )
        result = await gw_service.process(request, operation="pay_invoice")
        return format_gateway_result(result)

    @server.tool()
    async def send_payout(
        mandate_id: str,
        payee: str,
        amount_minor: int,
        currency: str,
        memo: str,
        idempotency_key: str,
    ) -> str:
        """Send a direct payout against an authorized mandate.

        Parameters
        ----------
        mandate_id:
            Identifier of the pre-authorized mandate authorizing this transaction.
        payee:
            Recipient email address or merchant ID.
        amount_minor:
            Transaction amount in integer minor units (e.g. cents).
        currency:
            3-letter ISO 4217 currency code (e.g. 'USD').
        memo:
            Human-readable justification for the payout.
        idempotency_key:
            Unique idempotency key to prevent replay attacks.
        """
        request = PaymentRequest(
            mandate_id=mandate_id,
            payee=payee,
            amount_minor=amount_minor,
            currency=currency,
            memo=memo,
            idempotency_key=idempotency_key,
        )
        result = await gw_service.process(request, operation="send_payout")
        return format_gateway_result(result)

    return server


def main() -> None:
    """CLI entrypoint for running the MandateGate MCP server."""
    parser = argparse.ArgumentParser(description="MandateGate MCP Gateway Server (Sandbox only)")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http", "sse"],
        default="stdio",
        help="MCP transport to use (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host address for HTTP/SSE transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for HTTP/SSE transport (default: 8000)",
    )

    args = parser.parse_args()
    server = create_mcp_server()

    if args.transport == "streamable-http":
        logger.info(
            "Starting MandateGate MCP Server on streamable-http http://%s:%d/mcp",
            args.host,
            args.port,
        )
        asyncio.run(
            server.run_streamable_http_async(
                host=args.host,
                port=args.port,
            )
        )
    elif args.transport == "sse":
        logger.info(
            "Starting MandateGate MCP Server on SSE http://%s:%d/sse",
            args.host,
            args.port,
        )
        asyncio.run(
            server.run_sse_async(
                host=args.host,
                port=args.port,
            )
        )
    else:
        logger.info("Starting MandateGate MCP Server on stdio transport...")
        asyncio.run(server.run_stdio_async())


if __name__ == "__main__":
    main()
