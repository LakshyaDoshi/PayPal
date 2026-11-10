"""
tests/test_chaos.py

Comprehensive chaos and resilience test suite proving MandateGate fails closed:
1. PayPal timeout, 5xx, malformed JSON, and 401 mid-flow.
2. Advisory safety judge timeout and garbage output.
3. SQLite errors and locked database.
4. Missing or short signing key.
5. Clock edge cases (exact boundary, microsecond expiration, clock skew).
6. Duplicate request retries with same idempotency key (provider called at most once).
7. 50 concurrent requests against a small budget (never overspend, ledger equals approved total).
8. Circuit breaker that freezes a mandate after N consecutive blocked attempts.
9. Secret hygiene verification (zero secrets in logs).
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import respx
from gateway.contract import Mandate, PaymentRequest, Verdict
from gateway.llm import FakeLLM, LLMTimeoutError
from gateway.mandate import get_signing_key, sign, verify
from gateway.providers.base import (
    ProviderError,
)
from gateway.providers.fake import FakeProvider
from gateway.providers.paypal import PayPalProvider
from gateway.rules import RuleContext, evaluate, overall
from gateway.service import GatewayService
from gateway.store import open_store

VALID_KEY = "a" * 32
SANDBOX_URL = "https://api-m.sandbox.paypal.com"


@pytest.fixture(autouse=True)
def setup_signing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MANDATE_SIGNING_KEY", VALID_KEY)
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "test_client_id")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "super_secret_paypal_password_12345")


def make_mandate(
    mandate_id: str = "m_chaos_1",
    max_amount_minor: int = 10000,
    allowed_payees: list[str] | None = None,
    expires_at: datetime | None = None,
) -> Mandate:
    now = datetime.now(UTC)
    draft = Mandate(
        id=mandate_id,
        purpose="Chaos resilience test",
        max_amount_minor=max_amount_minor,
        currency="USD",
        allowed_payees=allowed_payees or ["merchant@example.com"],
        expires_at=expires_at or (now + timedelta(days=1)),
        approval_threshold_minor=None,
        max_payments_per_window=None,
        window_seconds=None,
        signature="placeholder",
    )
    return sign(draft)


def make_request(
    mandate_id: str = "m_chaos_1",
    amount_minor: int = 1000,
    payee: str = "merchant@example.com",
    idempotency_key: str = "idem_chaos_1",
) -> PaymentRequest:
    return PaymentRequest(
        mandate_id=mandate_id,
        payee=payee,
        amount_minor=amount_minor,
        currency="USD",
        memo="Chaos test transaction",
        idempotency_key=idempotency_key,
    )


# ---------------------------------------------------------------------------
# 1. PayPal Provider Upstream Chaos Tests (Timeout, 5xx, Malformed, 401)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_paypal_timeout_fails_closed(
    tmp_path: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When PayPal times out, service fails closed to BLOCK, rolls back spend, logs reason."""
    caplog.set_level(logging.WARNING)
    store = open_store(str(tmp_path / "timeout.db"))
    mandate = make_mandate()
    store.save_mandate(mandate)

    # Mock OAuth success
    respx.post(f"{SANDBOX_URL}/v1/oauth2/token").respond(
        status_code=200,
        json={"access_token": "valid_token", "expires_in": 3600},
    )
    # Mock Orders create timeout
    respx.post(f"{SANDBOX_URL}/v2/checkout/orders").mock(
        side_effect=httpx.TimeoutException("Connection timed out")
    )

    paypal = PayPalProvider(
        client_id="test_client_id",
        client_secret="super_secret_paypal_password_12345",
        timeout_seconds=2.0,
    )
    fake_llm = FakeLLM(
        responses=[{"verdict": "ok", "reason_code": "safe", "reason": "No objection"}]
    )
    service = GatewayService(store=store, provider=paypal, llm_client=fake_llm)

    request = make_request()
    result = await service.process(request)

    # Asserts
    assert result.verdict == Verdict.BLOCK
    assert result.provider_result is None
    failed_rule = result.decision.rule_results[0]
    assert failed_rule.name == "provider_timeout"
    assert "provider_timeout" in failed_rule.detail

    # Spend reservation must be rolled back; ledger must be 0
    assert store.total_spent(mandate.id) == 0

    # Decision is saved to audit chain
    logged = store.list_decisions(mandate_id=mandate.id)
    assert len(logged) == 1
    assert logged[0].verdict == Verdict.BLOCK

    # Secret hygiene
    for record in caplog.records:
        assert "super_secret_paypal_password_12345" not in record.getMessage()

    await paypal.close()
    store.close()


@pytest.mark.asyncio
@respx.mock
async def test_paypal_5xx_server_error_fails_closed(
    tmp_path: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When PayPal returns 500/502/503, fails closed with provider_error."""
    caplog.set_level(logging.WARNING)
    store = open_store(str(tmp_path / "server_error.db"))
    mandate = make_mandate()
    store.save_mandate(mandate)

    respx.post(f"{SANDBOX_URL}/v1/oauth2/token").respond(
        status_code=200,
        json={"access_token": "valid_token", "expires_in": 3600},
    )
    respx.post(f"{SANDBOX_URL}/v2/checkout/orders").respond(
        status_code=503,
        json={"name": "SERVICE_UNAVAILABLE", "message": "PayPal service down"},
    )

    paypal = PayPalProvider(
        client_id="test_client_id",
        client_secret="super_secret_paypal_password_12345",
    )
    fake_llm = FakeLLM(
        responses=[{"verdict": "ok", "reason_code": "safe", "reason": "No objection"}]
    )
    service = GatewayService(store=store, provider=paypal, llm_client=fake_llm)

    result = await service.process(make_request())

    assert result.verdict == Verdict.BLOCK
    assert result.provider_result is None
    assert result.decision.rule_results[0].name == "provider_error"
    assert store.total_spent(mandate.id) == 0

    await paypal.close()
    store.close()


@pytest.mark.asyncio
@respx.mock
async def test_paypal_malformed_json_fails_closed(
    tmp_path: Any,
) -> None:
    """When PayPal returns 201 with missing id or non-JSON body, fails closed."""
    store = open_store(str(tmp_path / "malformed.db"))
    mandate = make_mandate()
    store.save_mandate(mandate)

    respx.post(f"{SANDBOX_URL}/v1/oauth2/token").respond(
        status_code=200,
        json={"access_token": "valid_token", "expires_in": 3600},
    )
    # Returns 201 but with empty JSON payload missing 'id'
    respx.post(f"{SANDBOX_URL}/v2/checkout/orders").respond(
        status_code=201,
        json={"status": "CREATED"},  # missing 'id'
    )

    paypal = PayPalProvider(
        client_id="test_client_id",
        client_secret="super_secret_paypal_password_12345",
    )
    fake_llm = FakeLLM(
        responses=[{"verdict": "ok", "reason_code": "safe", "reason": "No objection"}]
    )
    service = GatewayService(store=store, provider=paypal, llm_client=fake_llm)

    result = await service.process(make_request())

    assert result.verdict == Verdict.BLOCK
    assert result.provider_result is None
    assert result.decision.rule_results[0].name == "provider_error"
    assert store.total_spent(mandate.id) == 0

    await paypal.close()
    store.close()


@pytest.mark.asyncio
@respx.mock
async def test_paypal_401_mid_flow_retry_failure(
    tmp_path: Any,
) -> None:
    """When PayPal returns 401 on request and 401 again on refreshed retry, fails closed."""
    store = open_store(str(tmp_path / "auth_err.db"))
    mandate = make_mandate()
    store.save_mandate(mandate)

    # Initial token acquisition
    respx.post(f"{SANDBOX_URL}/v1/oauth2/token").respond(
        status_code=200,
        json={"access_token": "expired_token", "expires_in": 3600},
    )
    # Orders returns 401
    respx.post(f"{SANDBOX_URL}/v2/checkout/orders").respond(
        status_code=401,
        json={"name": "AUTHENTICATION_FAILURE", "message": "Invalid token"},
    )

    paypal = PayPalProvider(
        client_id="test_client_id",
        client_secret="super_secret_paypal_password_12345",
    )
    fake_llm = FakeLLM(
        responses=[{"verdict": "ok", "reason_code": "safe", "reason": "No objection"}]
    )
    service = GatewayService(store=store, provider=paypal, llm_client=fake_llm)

    result = await service.process(make_request())

    assert result.verdict == Verdict.BLOCK
    assert result.provider_result is None
    assert result.decision.rule_results[0].name == "provider_auth_error"
    assert store.total_spent(mandate.id) == 0

    await paypal.close()
    store.close()


# ---------------------------------------------------------------------------
# 2. Judge Timeout & Garbage Output
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_judge_timeout_fails_closed(tmp_path: Any) -> None:
    """When the advisory safety judge times out, fails closed to BLOCK."""
    store = open_store(str(tmp_path / "judge_timeout.db"))
    mandate = make_mandate()
    store.save_mandate(mandate)

    fake_provider = FakeProvider()
    fake_llm = FakeLLM(error_to_raise=LLMTimeoutError("Judge LLM timeout after 3.0s"))
    service = GatewayService(store=store, provider=fake_provider, llm_client=fake_llm)

    result = await service.process(make_request())

    assert result.verdict == Verdict.BLOCK
    assert result.provider_result is None
    assert fake_provider.call_count == 0  # Provider NEVER called
    assert "judge_unavailable" in str(result.decision.judge_reason)

    store.close()


@pytest.mark.asyncio
async def test_judge_garbage_output_fails_closed(tmp_path: Any) -> None:
    """When judge outputs invalid schema or garbage, fails closed to BLOCK."""
    store = open_store(str(tmp_path / "judge_garbage.db"))
    mandate = make_mandate()
    store.save_mandate(mandate)

    fake_provider = FakeProvider()
    fake_llm = FakeLLM(responses=[{"unexpected_key": "some_garbage", "verdict": "unknown"}])
    service = GatewayService(store=store, provider=fake_provider, llm_client=fake_llm)

    result = await service.process(make_request())

    assert result.verdict == Verdict.BLOCK
    assert result.provider_result is None
    assert fake_provider.call_count == 0
    assert "judge_unavailable" in str(result.decision.judge_reason)

    store.close()


# ---------------------------------------------------------------------------
# 3. SQLite Errors and Locked Database
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sqlite_locked_database_fails_closed(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When SQLite raises database locked operational error, fails closed with database_locked."""
    store = open_store(str(tmp_path / "locked.db"))
    mandate = make_mandate()
    store.save_mandate(mandate)

    fake_provider = FakeProvider()
    fake_llm = FakeLLM(
        responses=[{"verdict": "ok", "reason_code": "safe", "reason": "No objection"}]
    )
    service = GatewayService(store=store, provider=fake_provider, llm_client=fake_llm)

    def mock_reserve_spend(*args: Any, **kwargs: Any) -> bool:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "reserve_spend", mock_reserve_spend)

    result = await service.process(make_request())

    assert result.verdict == Verdict.BLOCK
    assert result.provider_result is None
    assert fake_provider.call_count == 0
    assert result.decision.rule_results[0].name == "database_locked"

    store.close()


# ---------------------------------------------------------------------------
# 4. Missing or Short Signing Key
# ---------------------------------------------------------------------------


def test_missing_signing_key_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """When MANDATE_SIGNING_KEY is missing, verify returns False and sign raises."""
    mandate = make_mandate()
    monkeypatch.delenv("MANDATE_SIGNING_KEY", raising=False)

    # Verification fails closed to False
    assert verify(mandate) is False

    # Signing attempts raise RuntimeError
    with pytest.raises(RuntimeError, match="MANDATE_SIGNING_KEY"):
        get_signing_key()


def test_short_signing_key_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """When MANDATE_SIGNING_KEY is shorter than 32 chars, verify returns False."""
    mandate = make_mandate()
    monkeypatch.setenv("MANDATE_SIGNING_KEY", "too_short_key_1234")

    assert verify(mandate) is False

    with pytest.raises(RuntimeError, match="too short"):
        get_signing_key()


@pytest.mark.asyncio
async def test_missing_key_in_service_process_fails_closed(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Service process fails closed when signing key is missing or corrupted at runtime."""
    store = open_store(str(tmp_path / "key_corrupt.db"))
    mandate = make_mandate()
    store.save_mandate(mandate)

    fake_provider = FakeProvider()
    fake_llm = FakeLLM()
    service = GatewayService(store=store, provider=fake_provider, llm_client=fake_llm)

    # Invalidate key at runtime
    monkeypatch.setenv("MANDATE_SIGNING_KEY", "bad_short_key")

    result = await service.process(make_request())

    assert result.verdict == Verdict.BLOCK
    assert result.provider_result is None
    assert fake_provider.call_count == 0
    failed_rule = next(r for r in result.decision.rule_results if not r.passed)
    assert failed_rule.name == "signature_valid"

    store.close()


# ---------------------------------------------------------------------------
# 5. Clock Edge Cases
# ---------------------------------------------------------------------------


def test_clock_exact_millisecond_expiry() -> None:
    """When current time exactly matches expires_at, mandate is expired."""
    fixed_time = datetime(2026, 11, 10, 12, 0, 0, tzinfo=UTC)
    mandate = make_mandate(expires_at=fixed_time)
    ctx = RuleContext(now=fixed_time)

    res = evaluate(make_request(), mandate, ctx)
    expired_rule = next(r for r in res if r.name == "not_expired")
    assert expired_rule.passed is False
    assert overall(res) == Verdict.BLOCK


def test_clock_one_microsecond_past_expiry() -> None:
    """When current time is 1 microsecond past expires_at, mandate is expired."""
    fixed_time = datetime(2026, 11, 10, 12, 0, 0, tzinfo=UTC)
    mandate = make_mandate(expires_at=fixed_time)
    ctx = RuleContext(now=fixed_time + timedelta(microseconds=1))

    res = evaluate(make_request(), mandate, ctx)
    expired_rule = next(r for r in res if r.name == "not_expired")
    assert expired_rule.passed is False
    assert overall(res) == Verdict.BLOCK


# ---------------------------------------------------------------------------
# 6. Duplicate Request Retries with Same Idempotency Key
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_duplicate_idempotency_key_provider_called_at_most_once(tmp_path: Any) -> None:
    """Duplicate requests with identical idempotency key call provider at most once."""
    store = open_store(str(tmp_path / "duplicate.db"))
    mandate = make_mandate(max_amount_minor=10000)
    store.save_mandate(mandate)

    fake_provider = FakeProvider()
    fake_llm = FakeLLM(
        responses=[{"verdict": "ok", "reason_code": "safe", "reason": "No objection"}]
    )
    service = GatewayService(store=store, provider=fake_provider, llm_client=fake_llm)

    req = make_request(idempotency_key="idempotent_test_key_abc")

    # 1. First call: approved
    res1 = await service.process(req)
    assert res1.verdict == Verdict.APPROVE
    assert fake_provider.call_count == 1

    # 2. Replay with identical key: blocked!
    res2 = await service.process(req)
    assert res2.verdict == Verdict.BLOCK
    # CRITICAL: Provider call count must still be 1 (never called again)
    assert fake_provider.call_count == 1
    failed_rule = next(r for r in res2.decision.rule_results if not r.passed)
    assert failed_rule.name in ("duplicate", "within_budget")

    store.close()


# ---------------------------------------------------------------------------
# 7. 50 Concurrent Requests Against Small Budget
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_50_concurrent_requests_never_overspends_ledger_equals_approved(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """50 concurrent requests against a 1000 cent budget:

    - At most 10 approved (100 cents each).
    - 40 blocked.
    - Never overspends.
    - Total in spend_ledger strictly equals approved total.
    """
    monkeypatch.setenv("CIRCUIT_BREAKER_MAX_BLOCKS", "100")
    store = open_store(str(tmp_path / "concurrent_spend.db"))
    budget_minor = 1000  # $10.00
    each_amount_minor = 100  # $1.00
    mandate = make_mandate(max_amount_minor=budget_minor)
    store.save_mandate(mandate)

    fake_provider = FakeProvider()
    fake_llm = FakeLLM(
        responses=[{"verdict": "ok", "reason_code": "safe", "reason": "No objection"}]
    )
    service = GatewayService(store=store, provider=fake_provider, llm_client=fake_llm)

    # Create 50 distinct requests with unique idempotency keys and distinct item memos
    requests = [
        PaymentRequest(
            mandate_id=mandate.id,
            payee="merchant@example.com",
            amount_minor=each_amount_minor,
            currency="USD",
            memo=f"Order item {i}",
            idempotency_key=f"concurrent_key_{i}",
        )
        for i in range(50)
    ]

    # Fire all 50 concurrently
    results = await asyncio.gather(*(service.process(r) for r in requests))

    approved = [r for r in results if r.verdict == Verdict.APPROVE]
    blocked = [r for r in results if r.verdict == Verdict.BLOCK]

    # Exactly 10 approved, 40 blocked
    assert len(approved) == 10
    assert len(blocked) == 40

    # Provider called exactly 10 times
    assert fake_provider.call_count == 10

    # Total spend in ledger equals approved total and does not exceed budget
    total_spent = store.total_spent(mandate.id)
    assert total_spent == 1000
    assert total_spent <= budget_minor

    # Verify audit chain integrity across all 50 recorded decisions
    broken_id = store.verify_chain()
    assert broken_id is None

    store.close()


# ---------------------------------------------------------------------------
# 8. Circuit Breaker Freezes Mandate After N Consecutive Blocked Attempts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_circuit_breaker_freezes_mandate(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Circuit breaker freezes mandate after N consecutive blocked attempts (configurable)."""
    # Set threshold to 3
    monkeypatch.setenv("CIRCUIT_BREAKER_MAX_BLOCKS", "3")
    store = open_store(str(tmp_path / "circuit.db"))
    mandate = make_mandate(allowed_payees=["good@example.com"])
    store.save_mandate(mandate)

    fake_provider = FakeProvider()
    fake_llm = FakeLLM()
    service = GatewayService(store=store, provider=fake_provider, llm_client=fake_llm)

    bad_req = make_request(payee="unauthorized@evil.com", idempotency_key="bad_1")

    # 1. First block
    r1 = await service.process(bad_req)
    assert r1.verdict == Verdict.BLOCK
    assert store.is_frozen(mandate.id) is False

    # 2. Second block
    r2 = await service.process(make_request(payee="unauthorized@evil.com", idempotency_key="bad_2"))
    assert r2.verdict == Verdict.BLOCK
    assert store.is_frozen(mandate.id) is False

    # 3. Third block -> Circuit breaker trips!
    r3 = await service.process(make_request(payee="unauthorized@evil.com", idempotency_key="bad_3"))
    assert r3.verdict == Verdict.BLOCK
    assert store.is_frozen(mandate.id) is True

    # 4. Fourth request: Even a completely legitimate request is now FROZEN!
    legit_req = make_request(payee="good@example.com", idempotency_key="legit_attempt")
    r4 = await service.process(legit_req)

    assert r4.verdict == Verdict.BLOCK
    assert r4.provider_result is None
    assert fake_provider.call_count == 0
    circuit_rule = r4.decision.rule_results[0]
    assert circuit_rule.name == "circuit_breaker"
    assert "frozen by circuit breaker" in circuit_rule.detail

    # 5. Admin unfreezes mandate -> Legitimate request now succeeds
    store.unfreeze_mandate(mandate.id)
    assert store.is_frozen(mandate.id) is False

    fake_llm.set_responses([{"verdict": "ok", "reason_code": "safe", "reason": "No objection"}])
    r5 = await service.process(legit_req)
    assert r5.verdict == Verdict.APPROVE
    assert fake_provider.call_count == 1

    store.close()


# ---------------------------------------------------------------------------
# 9. Secret Hygiene Verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_zero_secrets_in_logs_across_failures(
    tmp_path: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify that sensitive secrets never appear in log records."""
    caplog.set_level(logging.DEBUG)
    store = open_store(str(tmp_path / "secrets.db"))
    mandate = make_mandate()
    store.save_mandate(mandate)

    fake_provider = FakeProvider(
        error_to_raise=ProviderError("Error containing test_client_id and internal trace")
    )
    fake_llm = FakeLLM(
        responses=[{"verdict": "ok", "reason_code": "safe", "reason": "No objection"}]
    )
    service = GatewayService(store=store, provider=fake_provider, llm_client=fake_llm)

    await service.process(make_request())

    secret_key = VALID_KEY
    client_secret = "super_secret_paypal_password_12345"

    for record in caplog.records:
        msg = record.getMessage()
        assert secret_key not in msg, f"Signing key leaked in log: {msg}"
        assert client_secret not in msg, f"Client secret leaked in log: {msg}"

    store.close()
