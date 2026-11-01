"""
gateway.api

FastAPI adapter layer exposing MandateGate contract schemas and HTTP endpoints.
Thin wrapper around pure domain models and verification logic.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from gateway.contract import Decision, Mandate, PaymentRequest

app = FastAPI(
    title="MandateGate Gateway API",
    description="MCP gateway between AI agents and PayPal (Sandbox only).",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz", tags=["System"], summary="Health Check")
async def health_check() -> dict[str, str]:
    """Verify service health and sandbox connectivity status."""
    return {"status": "ok", "environment": "sandbox"}


@app.post(
    "/mandates",
    response_model=Mandate,
    status_code=status.HTTP_201_CREATED,
    tags=["Mandates"],
    summary="Register Authorized Mandate",
    description="Registers an authorized spending policy defining constraints for agent payments.",
)
async def create_mandate(mandate: Mandate) -> Mandate:
    """Register a new mandate policy."""
    # Stub adapter layer - persistent storage logic will be integrated by business logic
    return mandate


@app.get(
    "/mandates/{mandate_id}",
    response_model=Mandate,
    tags=["Mandates"],
    summary="Retrieve Mandate",
    description="Fetches an existing mandate policy by identifier.",
)
async def get_mandate(mandate_id: str) -> Mandate:
    """Retrieve an existing mandate."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Mandate retrieval backend pending persistence integration.",
    )


@app.post(
    "/payments",
    response_model=Decision,
    status_code=status.HTTP_200_OK,
    tags=["Payments"],
    summary="Submit Payment Request",
    description="Evaluates a payment request against its mandate and executes via PayPal sandbox.",
)
async def process_payment(request: PaymentRequest) -> Decision:
    """Evaluate and process payment request."""
    # Stub adapter layer returning schema-compliant Decision model
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Payment processing engine pending full policy engine integration.",
    )


@app.get(
    "/decisions/{decision_id}",
    response_model=Decision,
    tags=["Payments"],
    summary="Retrieve Payment Decision",
    description="Fetches audit record and enforcement decision by ID.",
)
async def get_decision(decision_id: str) -> Decision:
    """Retrieve an audit decision."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Decision retrieval pending persistence integration.",
    )
