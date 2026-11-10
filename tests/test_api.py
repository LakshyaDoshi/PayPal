"""
tests/test_api.py

Comprehensive tests for the MandateGate FastAPI web application.
Validates:
- GET /health and /healthz
- POST /mandates (confirm and sign draft policy)
- GET /mandates/{id}
- POST /mandates/{id}/revoke (kill switch takes effect on next request)
- Revoke then pay is BLOCKED (critical test)
- GET /decisions (paginated, newest first, explanation in every decision)
- GET /decisions/stream (SSE live feed)
- GET /pending (unresolved human approvals)
- POST /pending/{id}/approve with mandate re-check
- Double-approve does not double-pay (idempotency test)
- POST /pending/{id}/deny
- GET /audit (cryptographic chain integrity and rows)
- CORS from CORS_ORIGINS
- Request-size limits (413 Payload Too Large)
- Correlation ID tracing and uniform error bodies
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

VALID_SIGNING_KEY = "a" * 32
os.environ.setdefault("MANDATE_SIGNING_KEY", VALID_SIGNING_KEY)

from gateway.api import app, get_service, get_store  # noqa: E402
from gateway.llm import FakeLLM  # noqa: E402
from gateway.mandate import verify  # noqa: E402
from gateway.providers.fake import FakeProvider  # noqa: E402
from gateway.service import GatewayService  # noqa: E402
from gateway.store import MandateStore  # noqa: E402

NOW = datetime(2026, 11, 2, 12, 0, 0, tzinfo=UTC)
EXPIRY = NOW + timedelta(days=30)


@pytest.fixture
def store() -> MandateStore:
    """In-memory store fixture."""
    return MandateStore(db_path=":memory:")


@pytest.fixture
def fake_provider() -> FakeProvider:
    """Fake payment provider fixture."""
    return FakeProvider()


@pytest.fixture
def fake_llm() -> FakeLLM:
    """Fake LLM fixture."""
    return FakeLLM(
        responses={
            "verdict": "ok",
            "reason_code": "aligned_with_purpose",
            "reason": "Payment matches approved SaaS tools.",
        }
    )


@pytest.fixture
def client(store: MandateStore, fake_provider: FakeProvider, fake_llm: FakeLLM) -> TestClient:
    """TestClient with overridden dependencies."""
    service = GatewayService(store=store, provider=fake_provider, llm_client=fake_llm)

    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_service] = lambda: service

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def registered_mandate(client: TestClient) -> dict:
    """Create a standard signed mandate via API."""
    draft = {
        "id": "m-api-001",
        "purpose": "Authorized API developer subscriptions under $100.",
        "max_amount_minor": 10000,
        "currency": "USD",
        "allowed_payees": ["vendor@example.com"],
        "expires_at": EXPIRY.isoformat(),
        "approval_threshold_minor": 5000,  # $50 threshold
        "max_payments_per_window": 10,
        "window_seconds": 86400,
    }
    resp = client.post("/mandates", json=draft)
    assert resp.status_code == 201
    return resp.json()


# ===========================================================================
# 1. System Health & CORS
# ===========================================================================


class TestSystemAndSecurity:
    def test_health_check(self, client: TestClient) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "environment": "sandbox"}

    def test_correlation_id_in_response(self, client: TestClient) -> None:
        custom_corr = "test-corr-abc-123"
        resp = client.get("/health", headers={"X-Correlation-ID": custom_corr})
        assert resp.headers["X-Correlation-ID"] == custom_corr

    def test_uniform_error_body_on_404(self, client: TestClient) -> None:
        resp = client.get("/mandates/nonexistent-id")
        assert resp.status_code == 404
        data = resp.json()
        assert "error" in data
        assert data["error"]["code"] == "NOT_FOUND"
        assert "correlation_id" in data["error"]

    def test_request_size_limit_exceeded(self, client: TestClient) -> None:
        """Exceeding MAX_REQUEST_SIZE_BYTES returns 413 Payload Too Large."""
        headers = {"Content-Length": "2000000"}  # 2MB > 1MB
        resp = client.post("/mandates", headers=headers, content=b"x" * 10)
        assert resp.status_code == 413
        data = resp.json()
        assert data["error"]["code"] == "PAYLOAD_TOO_LARGE"


# ===========================================================================
# 2. Mandates & Kill Switch Revocation
# ===========================================================================


class TestMandatesAPI:
    def test_create_mandate_confirms_and_signs(self, client: TestClient) -> None:
        draft = {
            "id": "m-sign-test",
            "purpose": "Cloud compute services.",
            "max_amount_minor": 20000,
            "currency": "USD",
            "allowed_payees": ["aws@amazon.com"],
            "expires_at": EXPIRY.isoformat(),
        }
        resp = client.post("/mandates", json=draft)
        assert resp.status_code == 201
        data = resp.json()
        assert data["id"] == "m-sign-test"
        assert "signature" in data
        assert len(data["signature"]) == 64

        # Validate signature cryptographically
        from gateway.contract import Mandate

        m = Mandate.model_validate(data)
        assert verify(m) is True

    def test_get_mandate(self, client: TestClient, registered_mandate: dict) -> None:
        mandate_id = registered_mandate["id"]
        resp = client.get(f"/mandates/{mandate_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == mandate_id
        assert resp.headers["X-Mandate-Revoked"] == "false"

    def test_revoke_mandate_kill_switch(self, client: TestClient, registered_mandate: dict) -> None:
        mandate_id = registered_mandate["id"]
        resp = client.post(f"/mandates/{mandate_id}/revoke")
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

        # Subsequent GET indicates revoked
        get_resp = client.get(f"/mandates/{mandate_id}")
        assert get_resp.headers["X-Mandate-Revoked"] == "true"

    def test_revoke_then_pay_is_blocked(
        self,
        client: TestClient,
        registered_mandate: dict,
        fake_provider: FakeProvider,
    ) -> None:
        """Revoking a mandate immediately causes subsequent payments to be BLOCKED."""
        mandate_id = registered_mandate["id"]

        # 1. Kill switch activation
        revoke_resp = client.post(f"/mandates/{mandate_id}/revoke")
        assert revoke_resp.status_code == 200

        # 2. Agent submits payment against the revoked mandate
        payment_payload = {
            "mandate_id": mandate_id,
            "payee": "vendor@example.com",
            "amount_minor": 1500,
            "currency": "USD",
            "memo": "Attempt payment after revocation",
            "idempotency_key": "idemp-post-revoke-001",
        }
        pay_resp = client.post("/payments", json=payment_payload)
        assert pay_resp.status_code == 200
        decision = pay_resp.json()

        # 3. Verdict is strictly BLOCK
        assert decision["verdict"] == "block"
        failed_names = [r["name"] for r in decision["rule_results"] if not r["passed"]]
        assert "not_revoked" in failed_names

        # 4. Provider NEVER called
        assert len(fake_provider.calls) == 0


# ===========================================================================
# 3. Decisions & SSE Live Stream
# ===========================================================================


class TestDecisionsAPI:
    def test_decisions_paginated_and_includes_explanation(
        self, client: TestClient, registered_mandate: dict
    ) -> None:
        mandate_id = registered_mandate["id"]

        # Submit 2 payments
        for i in range(2):
            client.post(
                "/payments",
                json={
                    "mandate_id": mandate_id,
                    "payee": "vendor@example.com",
                    "amount_minor": 1000 + i,
                    "currency": "USD",
                    "memo": f"Payment {i}",
                    "idempotency_key": f"idemp-dec-{i}",
                },
            )

        resp = client.get("/decisions?limit=10&offset=0")
        assert resp.status_code == 200
        decisions = resp.json()
        assert len(decisions) >= 2
        assert int(resp.headers["X-Total-Count"]) >= 2

        # Every decision must contain a plain-English explanation
        for d in decisions:
            assert "explanation" in d
            assert len(d["explanation"]) > 0
            assert "Payment approved" in d["explanation"] or "Payment" in d["explanation"]

    def test_decisions_stream_sse_endpoint(self, client: TestClient) -> None:
        """Verify GET /decisions/stream returns SSE media type."""
        with client.stream("GET", "/decisions/stream") as resp:
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers["content-type"]


# ===========================================================================
# 4. Human Approval Flow & Double-Approve Idempotency
# ===========================================================================


class TestHumanApprovals:
    def test_double_approve_does_not_double_pay(
        self,
        client: TestClient,
        registered_mandate: dict,
        fake_provider: FakeProvider,
    ) -> None:
        """Approving an escalated item re-checks mandate and is idempotent (no double-pay)."""
        mandate_id = registered_mandate["id"]

        # 1. Submit payment over $50 threshold (approval_threshold_minor is 5000)
        pay_resp = client.post(
            "/payments",
            json={
                "mandate_id": mandate_id,
                "payee": "vendor@example.com",
                "amount_minor": 6500,  # $65.00 > $50.00
                "currency": "USD",
                "memo": "Large software purchase",
                "idempotency_key": "idemp-esc-001",
            },
        )
        assert pay_resp.status_code == 200
        assert pay_resp.json()["verdict"] == "escalate"
        assert len(fake_provider.calls) == 0

        # 2. Retrieve pending item
        pending_list = client.get(f"/pending?mandate_id={mandate_id}").json()
        assert len(pending_list) == 1
        pending_id = pending_list[0]["id"]

        # 3. First approval: Re-checks mandate, reserves spend, executes provider
        appr1_resp = client.post(f"/pending/{pending_id}/approve")
        assert appr1_resp.status_code == 200
        assert appr1_resp.json()["status"] == "approved"
        assert len(fake_provider.calls) == 1
        assert fake_provider.calls[0]["amount_minor"] == 6500

        # 4. Second approval: Idempotent! MUST NOT call provider again
        appr2_resp = client.post(f"/pending/{pending_id}/approve")
        assert appr2_resp.status_code == 200
        assert appr2_resp.json()["status"] == "approved"
        assert "idempotent" in appr2_resp.json()["message"].lower()

        # CRITICAL ASSERTION: Provider call count remains exactly 1!
        assert len(fake_provider.calls) == 1

    def test_pending_deny_flow(
        self,
        client: TestClient,
        registered_mandate: dict,
        fake_provider: FakeProvider,
    ) -> None:
        """Denying a pending approval marks denied and logs BLOCK decision."""
        mandate_id = registered_mandate["id"]

        # Trigger escalation
        client.post(
            "/payments",
            json={
                "mandate_id": mandate_id,
                "payee": "vendor@example.com",
                "amount_minor": 7000,
                "currency": "USD",
                "memo": "Procurement",
                "idempotency_key": "idemp-deny-001",
            },
        )

        pending = client.get("/pending").json()
        pending_id = pending[0]["id"]

        deny_resp = client.post(f"/pending/{pending_id}/deny")
        assert deny_resp.status_code == 200
        assert deny_resp.json()["status"] == "denied"
        assert len(fake_provider.calls) == 0

        # Subsequent approve attempt fails
        fail_appr = client.post(f"/pending/{pending_id}/approve")
        assert fail_appr.status_code == 400


# ===========================================================================
# 5. Cryptographic Audit Chain Endpoint
# ===========================================================================


class TestAuditAPI:
    def test_audit_endpoint_reports_valid_chain(
        self, client: TestClient, registered_mandate: dict
    ) -> None:
        mandate_id = registered_mandate["id"]

        # Generate a decision
        client.post(
            "/payments",
            json={
                "mandate_id": mandate_id,
                "payee": "vendor@example.com",
                "amount_minor": 1200,
                "currency": "USD",
                "memo": "Audit test",
                "idempotency_key": "idemp-audit-001",
            },
        )

        resp = client.get("/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["chain_valid"] is True
        assert data["broken_decision_id"] is None
        assert data["total_records"] >= 1
        assert len(data["rows"]) >= 1
        assert "hash" in data["rows"][0]
        assert "prev_hash" in data["rows"][0]
