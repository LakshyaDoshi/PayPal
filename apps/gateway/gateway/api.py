"""
gateway.api

FastAPI web application exposing MandateGate to the user interface and external systems.

Endpoints:
- GET /health & /healthz
- POST /mandates/draft (generate unsigned structured proposal from natural language task)
- POST /mandates (confirm and sign a draft policy)
- GET /mandates/{mandate_id}
- POST /mandates/{mandate_id}/revoke (kill switch, effective immediately on next request)
- GET /decisions (paginated, newest first)
- GET /decisions/stream (Server-Sent Events live feed)
- GET /pending (list payments awaiting human approval)
- POST /pending/{pending_id}/approve (human approval with mandate re-check and idempotency)
- POST /pending/{pending_id}/deny (human denial)
- GET /audit (cryptographic hash chain verification and audit records)
- POST /payments (agent payment evaluation)

Security & Operational Features:
- CORS configuration dynamically loaded from CORS_ORIGINS.
- Request size limit enforcement.
- Unique correlation ID per request traced in headers and logs.
- Uniform JSON error bodies across all HTTP errors and unhandled exceptions.
- Fail closed on all unauthorized actions.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from sse_starlette.sse import EventSourceResponse
from starlette.middleware.base import BaseHTTPMiddleware

from gateway.contract import Decision, Mandate, PaymentRequest, RuleResult, Verdict
from gateway.drafter import DraftResult, draft_mandate
from gateway.llm import get_llm_client
from gateway.mandate import sign, verify
from gateway.providers.base import PaymentProvider
from gateway.providers.fake import FakeProvider
from gateway.providers.paypal import PayPalProvider
from gateway.service import GatewayService
from gateway.store import MandateStore, open_store

logger = logging.getLogger("gateway.api")

# Maximum permitted payload size (1 MB)
MAX_REQUEST_SIZE_BYTES = 1024 * 1024

# In-memory SSE broadcast subscribers
_sse_subscribers: set[asyncio.Queue[str]] = set()


async def broadcast_decision(decision: Decision) -> None:
    """Broadcast a new decision JSON to all active SSE stream subscribers."""
    payload = decision.model_dump_json()
    for queue in list(_sse_subscribers):
        try:
            queue.put_nowait(payload)
        except Exception:
            _sse_subscribers.discard(queue)


# ---------------------------------------------------------------------------
# Dependency Injection Singletons
# ---------------------------------------------------------------------------

_store_instance: MandateStore | None = None
_service_instance: GatewayService | None = None


def get_store() -> MandateStore:
    """Dependency providing the active MandateStore."""
    global _store_instance
    if _store_instance is None:
        _store_instance = open_store()
    return _store_instance


def get_service(store: MandateStore = Depends(get_store)) -> GatewayService:
    """Dependency providing the active GatewayService."""
    global _service_instance
    if _service_instance is None:
        client_id = os.environ.get("PAYPAL_CLIENT_ID", "")
        client_secret = os.environ.get("PAYPAL_CLIENT_SECRET", "")
        provider: PaymentProvider
        if client_id and client_secret:
            provider = PayPalProvider()
        else:
            provider = FakeProvider()
        llm = get_llm_client()
        _service_instance = GatewayService(store=store, provider=provider, llm_client=llm)
    return _service_instance


# ---------------------------------------------------------------------------
# Request & Response Models
# ---------------------------------------------------------------------------


class MandateDraftRequest(BaseModel):
    """Natural language task prompt submitted to generate an unsigned proposal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    prompt: str = Field(..., min_length=1, max_length=2000, description="User's task description.")
    candidate_payees: list[str] | None = Field(
        default=None, description="Optional explicit candidate payees or shops."
    )


class MandateDraft(BaseModel):
    """Draft policy submitted by UI/user to be confirmed and signed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(..., min_length=1, max_length=64)
    purpose: str = Field(..., min_length=1, max_length=2000)
    max_amount_minor: int = Field(..., gt=0)
    currency: str = Field(..., min_length=3, max_length=3)
    allowed_payees: list[str] = Field(..., min_length=1)
    expires_at: datetime = Field(...)
    approval_threshold_minor: int | None = Field(default=None, gt=0)
    max_payments_per_window: int | None = Field(default=None, gt=0)
    window_seconds: int | None = Field(default=None, gt=0)


class AuditResponse(BaseModel):
    """Cryptographic audit chain verification status and log rows."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    chain_valid: bool = Field(...)
    broken_decision_id: str | None = Field(default=None)
    total_records: int = Field(...)
    rows: list[dict[str, Any]] = Field(...)


class UniformError(BaseModel):
    """Standardized error response payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(...)
    message: str = Field(...)
    correlation_id: str = Field(...)
    details: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class CorrelationAndSizeMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing request-size limits and injecting correlation IDs."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        corr_id = request.headers.get("X-Correlation-ID") or f"corr_{uuid4().hex[:12]}"
        request.state.correlation_id = corr_id

        # Enforce request body size limit
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_SIZE_BYTES:
            logger.warning("[%s] Request size %s exceeds limit", corr_id, content_length)
            err = {
                "error": {
                    "code": "PAYLOAD_TOO_LARGE",
                    "message": f"Request size exceeds limit of {MAX_REQUEST_SIZE_BYTES} bytes.",
                    "correlation_id": corr_id,
                    "details": {"max_bytes": MAX_REQUEST_SIZE_BYTES},
                }
            }
            return Response(
                content=json.dumps(err),
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                media_type="application/json",
                headers={"X-Correlation-ID": corr_id},
            )

        response = await call_next(request)
        response.headers["X-Correlation-ID"] = corr_id
        return response


# ---------------------------------------------------------------------------
# Application Setup & Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app_instance: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context managing background resources."""
    yield
    # Cleanup subscriber queues on shutdown
    _sse_subscribers.clear()


app = FastAPI(
    title="MandateGate Gateway API",
    description="MCP gateway between AI agents and PayPal (Sandbox only).",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Parse CORS Origins from environment
_cors_env = os.environ.get("CORS_ORIGINS", "")
_allowed_origins = ["*"]
if _cors_env:
    try:
        parsed_origins = json.loads(_cors_env)
        if isinstance(parsed_origins, list):
            _allowed_origins = [str(o) for o in parsed_origins]
    except Exception:
        _allowed_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(CorrelationAndSizeMiddleware)


# ---------------------------------------------------------------------------
# Uniform Error Exception Handlers
# ---------------------------------------------------------------------------


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> Response:
    corr_id = getattr(request.state, "correlation_id", f"corr_{uuid4().hex[:12]}")
    code = "NOT_FOUND" if exc.status_code == 404 else "HTTP_ERROR"
    payload = {
        "error": {
            "code": code,
            "message": str(exc.detail),
            "correlation_id": corr_id,
            "details": {},
        }
    }
    return Response(
        content=json.dumps(payload),
        status_code=exc.status_code,
        media_type="application/json",
        headers={"X-Correlation-ID": corr_id},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> Response:
    corr_id = getattr(request.state, "correlation_id", f"corr_{uuid4().hex[:12]}")
    payload = {
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Invalid request schema or parameters.",
            "correlation_id": corr_id,
            "details": {"errors": exc.errors()},
        }
    }
    return Response(
        content=json.dumps(payload),
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        media_type="application/json",
        headers={"X-Correlation-ID": corr_id},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
    corr_id = getattr(request.state, "correlation_id", f"corr_{uuid4().hex[:12]}")
    logger.exception("[%s] Unhandled exception in request: %s", corr_id, exc)
    payload = {
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred. Request failed closed.",
            "correlation_id": corr_id,
            "details": {},
        }
    }
    return Response(
        content=json.dumps(payload),
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        media_type="application/json",
        headers={"X-Correlation-ID": corr_id},
    )


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------


@app.get(
    "/health",
    tags=["System"],
    summary="Health Check",
    response_model=dict[str, str],
)
@app.get(
    "/healthz",
    tags=["System"],
    include_in_schema=False,
)
async def health_check() -> dict[str, str]:
    """Verify service health and sandbox connectivity status."""
    return {"status": "ok", "environment": "sandbox"}


@app.post(
    "/mandates/draft",
    response_model=DraftResult,
    status_code=status.HTTP_200_OK,
    tags=["Mandates"],
    summary="Generate Mandate Proposal from Prompt",
    description=(
        "Transforms a natural language task description into an unsigned structured proposal "
        "or requests missing parameters. Does not sign or activate anything."
    ),
)
async def create_mandate_draft(
    request: MandateDraftRequest,
    service: GatewayService = Depends(get_service),
) -> DraftResult:
    """Generate an unsigned mandate draft proposal using LLM extraction."""
    return await draft_mandate(
        prompt=request.prompt,
        llm_client=service.llm_client,
        candidate_payees=request.candidate_payees,
    )


@app.post(
    "/mandates",
    response_model=Mandate,
    status_code=status.HTTP_201_CREATED,
    tags=["Mandates"],
    summary="Register & Sign Mandate",
    description="Confirms, cryptographically signs, and persists an authorized spending mandate.",
)
async def create_mandate(
    draft: MandateDraft,
    store: MandateStore = Depends(get_store),
) -> Mandate:
    """Sign and persist a mandate draft."""
    raw_mandate = Mandate(
        id=draft.id,
        purpose=draft.purpose,
        max_amount_minor=draft.max_amount_minor,
        currency=draft.currency,
        allowed_payees=draft.allowed_payees,
        expires_at=draft.expires_at,
        approval_threshold_minor=draft.approval_threshold_minor,
        max_payments_per_window=draft.max_payments_per_window,
        window_seconds=draft.window_seconds,
        signature="placeholder",
    )
    signed_mandate = sign(raw_mandate)
    store.save_mandate(signed_mandate)
    return signed_mandate


@app.get(
    "/mandates/{mandate_id}",
    response_model=Mandate,
    tags=["Mandates"],
    summary="Retrieve Mandate",
    description="Fetches an existing mandate policy by identifier.",
)
async def get_mandate(
    mandate_id: str,
    response: Response,
    store: MandateStore = Depends(get_store),
) -> Mandate:
    """Retrieve an existing mandate."""
    mandate = store.load_mandate(mandate_id)
    if mandate is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mandate '{mandate_id}' not found.",
        )
    is_revoked = store.is_revoked(mandate_id)
    spent = store.total_spent(mandate_id)
    response.headers["X-Mandate-Revoked"] = str(is_revoked).lower()
    response.headers["X-Total-Spent-Minor"] = str(spent)
    return mandate


@app.post(
    "/mandates/{mandate_id}/revoke",
    tags=["Mandates"],
    summary="Revoke Mandate (Kill Switch)",
    description="Instantly revokes a mandate; takes effect immediately on next transaction.",
)
async def revoke_mandate(
    mandate_id: str,
    store: MandateStore = Depends(get_store),
) -> dict[str, str]:
    """Execute immediate kill switch revocation of a mandate."""
    mandate = store.load_mandate(mandate_id)
    if mandate is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mandate '{mandate_id}' not found.",
        )
    store.revoke_mandate(mandate_id, reason="Revoked via API kill switch")
    return {
        "status": "revoked",
        "mandate_id": mandate_id,
        "message": "Mandate has been revoked. All future payment requests will be blocked.",
    }


@app.get(
    "/decisions",
    response_model=list[Decision],
    tags=["Audit"],
    summary="List Decisions (Paginated)",
    description="Returns decisions in reverse chronological order (newest first).",
)
async def list_decisions(
    response: Response,
    limit: int = 50,
    offset: int = 0,
    mandate_id: str | None = None,
    store: MandateStore = Depends(get_store),
) -> list[Decision]:
    """Retrieve paginated decisions from audit log."""
    total = store.count_decisions(mandate_id=mandate_id)
    decisions = store.list_decisions(limit=limit, offset=offset, mandate_id=mandate_id)
    response.headers["X-Total-Count"] = str(total)
    return decisions


@app.get(
    "/decisions/stream",
    tags=["Audit"],
    summary="Decision Live Feed (SSE)",
    description="Server-Sent Events streaming real-time payment decisions as they occur.",
)
async def stream_decisions() -> EventSourceResponse:
    """Stream live payment decisions over SSE."""
    queue: asyncio.Queue[str] = asyncio.Queue()
    _sse_subscribers.add(queue)

    async def event_generator() -> AsyncGenerator[dict[str, str], None]:
        try:
            while True:
                data = await queue.get()
                yield {"event": "decision", "data": data}
        except asyncio.CancelledError:
            pass
        finally:
            _sse_subscribers.discard(queue)

    return EventSourceResponse(event_generator())


@app.get(
    "/pending",
    tags=["Approvals"],
    summary="List Pending Approvals",
    description="Fetches escalated transactions awaiting human review.",
)
async def list_pending(
    mandate_id: str | None = None,
    store: MandateStore = Depends(get_store),
) -> list[dict[str, Any]]:
    """List transactions currently held in pending approval status."""
    return store.list_pending_approvals(mandate_id=mandate_id)


@app.post(
    "/pending/{pending_id}/approve",
    tags=["Approvals"],
    summary="Approve Escalated Payment",
    description="Human sign-off: re-verifies mandate before idempotent provider execution.",
)
async def approve_pending(
    pending_id: str,
    store: MandateStore = Depends(get_store),
    service: GatewayService = Depends(get_service),
) -> dict[str, Any]:
    """Approve and dispatch a previously escalated payment request."""
    item = store.get_pending_approval(pending_id)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Pending approval '{pending_id}' not found.",
        )

    # 1. Idempotency check: if already approved, return without double-paying
    if item.get("resolution") == "approved":
        return {
            "status": "approved",
            "pending_id": pending_id,
            "message": "Payment was already approved (idempotent).",
        }

    if item.get("resolution") == "denied":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pending transaction was already denied and cannot be approved.",
        )

    # 2. Re-check the mandate invariants
    mandate = store.load_mandate(item["mandate_id"])
    if mandate is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mandate no longer exists.",
        )

    if not verify(mandate):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mandate cryptographic signature is invalid.",
        )

    if store.is_revoked(mandate.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mandate has been revoked; payment cannot be approved.",
        )

    if datetime.now(UTC) >= mandate.expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mandate has expired; payment cannot be approved.",
        )

    if item["currency"].upper() != mandate.currency.upper():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Currency mismatch with mandate.",
        )

    # 3. Reserve spend atomically
    decision_id = f"dec_appr_{uuid4().hex[:12]}"
    reserved = store.reserve_spend(
        mandate_id=mandate.id,
        decision_id=decision_id,
        amount_minor=item["amount_minor"],
        currency=item["currency"],
        payee=item["payee"],
        memo=item["memo"],
        idempotency_key=item.get("idempotency_key") or f"idemp_{pending_id}",
    )

    if not reserved:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Insufficient remaining mandate budget for this approval.",
        )

    # 4. Call Payment Provider
    provider_res = await service.provider.create_order(
        amount_minor=item["amount_minor"],
        currency=item["currency"],
        payee=item["payee"],
        memo=item["memo"],
        idempotency_key=item.get("idempotency_key") or f"idemp_{pending_id}",
    )

    # 5. Mark resolved & record hash-chained decision
    store.resolve_pending_approval(pending_id, resolution="approved")
    decision = Decision(
        id=decision_id,
        verdict=Verdict.APPROVE,
        rule_results=[
            RuleResult(
                name="human_approval",
                passed=True,
                detail=f"Human operator approved pending transaction '{pending_id}'.",
            )
        ],
        judge_reason=None,
        created_at=datetime.now(UTC),
    )
    store.save_decision(decision, mandate_id=mandate.id)
    await broadcast_decision(decision)

    return {
        "status": "approved",
        "pending_id": pending_id,
        "decision": decision.model_dump(mode="json"),
        "provider_reference": provider_res.provider_reference,
    }


@app.post(
    "/pending/{pending_id}/deny",
    tags=["Approvals"],
    summary="Deny Escalated Payment",
    description="Human operator rejects an escalated payment request.",
)
async def deny_pending(
    pending_id: str,
    store: MandateStore = Depends(get_store),
) -> dict[str, Any]:
    """Deny a pending approval request."""
    item = store.get_pending_approval(pending_id)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Pending approval '{pending_id}' not found.",
        )

    if item.get("resolution") == "denied":
        return {
            "status": "denied",
            "pending_id": pending_id,
            "message": "Payment was already denied (idempotent).",
        }

    # Mark resolved as denied & record decision
    store.resolve_pending_approval(pending_id, resolution="denied")
    decision_id = f"dec_deny_{uuid4().hex[:12]}"
    decision = Decision(
        id=decision_id,
        verdict=Verdict.BLOCK,
        rule_results=[
            RuleResult(
                name="human_denial",
                passed=False,
                detail=f"Human operator rejected pending transaction '{pending_id}'.",
            )
        ],
        judge_reason=None,
        created_at=datetime.now(UTC),
    )
    store.save_decision(decision, mandate_id=item["mandate_id"])
    await broadcast_decision(decision)

    return {
        "status": "denied",
        "pending_id": pending_id,
        "decision": decision.model_dump(mode="json"),
    }


@app.get(
    "/audit",
    response_model=AuditResponse,
    tags=["Audit"],
    summary="Audit Log & Chain Integrity",
    description="Retrieves all decision audit rows and verifies cryptographic chain integrity.",
)
async def get_audit_log(
    store: MandateStore = Depends(get_store),
) -> AuditResponse:
    """Inspect cryptographic hash chain integrity and raw decision records."""
    broken_id = store.verify_chain()
    rows = store.list_audit_rows()
    return AuditResponse(
        chain_valid=(broken_id is None),
        broken_decision_id=broken_id,
        total_records=len(rows),
        rows=rows,
    )


@app.post(
    "/payments",
    response_model=Decision,
    status_code=status.HTTP_200_OK,
    tags=["Payments"],
    summary="Process Payment Request",
    description="Evaluates an agent payment request through rules, safety judge, and provider.",
)
async def process_payment(
    request: PaymentRequest,
    service: GatewayService = Depends(get_service),
) -> Decision:
    """Submit a payment request for policy evaluation and execution."""
    result = await service.process(request)
    await broadcast_decision(result.decision)
    return result.decision
