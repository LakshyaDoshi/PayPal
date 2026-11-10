"""
tests.test_deployment
====================

Unit and integration tests for deployment readiness:
- Environment variable validation at startup (fail closed with clear messages, no secret leaks)
- Configurable CORS origins parsing
- Automatic empty database seeding hook
- End-to-end smoke test runner execution (scripts/smoke.py)
"""

from __future__ import annotations

import pytest
from gateway.api import app, get_cors_origins, validate_environment
from gateway.contract import Mandate
from gateway.mandate import sign
from gateway.store import open_store

from scripts.smoke import SmokeRunner

# ---------------------------------------------------------------------------
# 1. Environment Variable Validation Tests
# ---------------------------------------------------------------------------


class TestValidateEnvironment:
    def test_missing_signing_key_fails_startup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MANDATE_SIGNING_KEY", raising=False)
        with pytest.raises(RuntimeError) as exc_info:
            validate_environment()
        err_msg = str(exc_info.value)
        assert "Missing required environment variable" in err_msg
        assert "MANDATE_SIGNING_KEY" in err_msg

    def test_short_signing_key_fails_startup_without_leaking_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        short_secret = "secret123"
        monkeypatch.setenv("MANDATE_SIGNING_KEY", short_secret)
        with pytest.raises(RuntimeError) as exc_info:
            validate_environment()
        err_msg = str(exc_info.value)
        assert "must be at least 32 characters long" in err_msg
        assert short_secret not in err_msg  # Never leaks secret value

    def test_partial_paypal_credentials_fails_startup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MANDATE_SIGNING_KEY", "a" * 32)
        monkeypatch.setenv("PAYPAL_CLIENT_ID", "client_123")
        monkeypatch.delenv("PAYPAL_CLIENT_SECRET", raising=False)
        with pytest.raises(RuntimeError) as exc_info:
            validate_environment()
        err_msg = str(exc_info.value)
        assert "PAYPAL_CLIENT_SECRET" in err_msg
        assert "client_123" not in err_msg

    def test_valid_environment_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MANDATE_SIGNING_KEY", "a" * 32)
        monkeypatch.delenv("PAYPAL_CLIENT_ID", raising=False)
        monkeypatch.delenv("PAYPAL_CLIENT_SECRET", raising=False)
        # Should not raise
        validate_environment()


# ---------------------------------------------------------------------------
# 2. Configurable CORS Origins Tests
# ---------------------------------------------------------------------------


class TestCorsOrigins:
    def test_default_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CORS_ORIGINS", raising=False)
        assert get_cors_origins() == ["*"]

    def test_json_list_format(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "CORS_ORIGINS",
            '["https://frontend.onrender.com", "http://localhost:3000"]',
        )
        origins = get_cors_origins()
        assert origins == ["https://frontend.onrender.com", "http://localhost:3000"]

    def test_comma_delimited_format(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "CORS_ORIGINS",
            "https://frontend.onrender.com, http://localhost:3000",
        )
        origins = get_cors_origins()
        assert origins == ["https://frontend.onrender.com", "http://localhost:3000"]


# ---------------------------------------------------------------------------
# 3. Automatic Database Seeding Hook Tests
# ---------------------------------------------------------------------------


class TestSeedHook:
    def test_count_mandates_on_empty_store(self, tmp_path: pytest.TempPathFactory) -> None:
        db_file = str(tmp_path / "test_empty.db")  # type: ignore[operator]
        store = open_store(db_file)
        assert store.count_mandates() == 0
        store.close()

    def test_count_mandates_after_saving(self, tmp_path: pytest.TempPathFactory) -> None:
        db_file = str(tmp_path / "test_count.db")  # type: ignore[operator]
        store = open_store(db_file)
        assert store.count_mandates() == 0

        # Create and save a mandate
        draft = Mandate(
            id="test-mandate-count",
            purpose="Testing count_mandates method",
            max_amount_minor=1000,
            currency="USD",
            allowed_payees=["vendor@example.com"],
            expires_at="2099-01-01T00:00:00+00:00",
            signature="placeholder",
        )
        signed = sign(draft)
        store.save_mandate(signed)

        assert store.count_mandates() == 1
        store.close()

    def test_seed_run_populates_empty_store(self, tmp_path: pytest.TempPathFactory) -> None:
        from scripts.seed import run as run_seed

        db_file = str(tmp_path / "test_seed.db")  # type: ignore[operator]
        store = open_store(db_file)
        assert store.count_mandates() == 0

        seeded_mandate = run_seed(store=store, reset=False)
        assert store.count_mandates() == 1
        assert seeded_mandate.id == "demo-mandate-001"
        assert store.load_mandate("demo-mandate-001") is not None
        store.close()


# ---------------------------------------------------------------------------
# 4. Smoke Test Runner End-to-End Tests
# ---------------------------------------------------------------------------


class TestSmokeRunner:
    def test_smoke_runner_all_steps_pass(self, tmp_path: pytest.TempPathFactory) -> None:
        """Run all 7 smoke test steps against in-memory ASGI app via TestClient."""
        from fastapi.testclient import TestClient
        from gateway.api import get_service, get_store
        from gateway.llm import FakeLLM
        from gateway.providers.fake import FakeProvider
        from gateway.service import GatewayService

        db_file = str(tmp_path / "smoke_test.db")  # type: ignore[operator]
        test_store = open_store(db_file)
        test_provider = FakeProvider()
        test_llm = FakeLLM(
            responses={"verdict": "ok", "reason_code": "smoke_ok", "reason": "Smoke test OK"}
        )
        test_service = GatewayService(store=test_store, provider=test_provider, llm_client=test_llm)

        # Override dependencies for test isolation
        app.dependency_overrides[get_store] = lambda: test_store
        app.dependency_overrides[get_service] = lambda: test_service

        try:
            with TestClient(app, base_url="http://testserver") as client:
                runner = SmokeRunner(base_url="http://testserver", client=client)
                exit_code = runner.run_all()
                assert exit_code == 0
                assert runner.passed == 7
                assert runner.failed == 0
        finally:
            app.dependency_overrides.clear()
            test_store.close()
