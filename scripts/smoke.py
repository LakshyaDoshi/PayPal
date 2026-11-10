#!/usr/bin/env python3
"""
scripts/smoke.py

End-to-end smoke test suite for MandateGate gateway API.
Exercises the core gateway lifecycle against a running local or remote instance (e.g. Render):
  1. GET  /health                      (health check)
  2. POST /mandates                    (create and cryptographically sign mandate)
  3. POST /payments                    (legitimate payment under limit -> APPROVE)
  4. POST /payments                    (blocked payment to unauthorized payee -> BLOCK)
  5. POST /payments                    (payment over threshold -> ESCALATE to pending)
  6. POST /pending/{id}/approve        (human approval -> APPROVE)
  7. GET  /audit                       (verify cryptographic hash chain integrity)

Usage:
    python scripts/smoke.py [BASE_URL]
    python scripts/smoke.py http://localhost:8000
    python scripts/smoke.py https://mandategate.onrender.com
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx

# Exit codes
EXIT_SUCCESS = 0
EXIT_FAILURE = 1


class SmokeRunner:
    """Orchestrates end-to-end smoke test steps against MandateGate API."""

    def __init__(self, base_url: str, client: httpx.Client | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._external_client = client
        self.passed = 0
        self.failed = 0
        self.mandate_id = f"smoke-mandate-{uuid4().hex[:8]}"
        self.pending_id: str | None = None
        self.authorized_payee = "vendor-api@example.com"
        self.unauthorized_payee = "attacker@evil.example"

    def _get_client(self) -> httpx.Client:
        if self._external_client is not None:
            return self._external_client
        return httpx.Client(base_url=self.base_url, timeout=15.0)

    def _record_result(self, step_num: int, name: str, success: bool, detail: str) -> None:
        if success:
            self.passed += 1
            print(f"[PASS] Step {step_num}: {name} - {detail}")
        else:
            self.failed += 1
            print(f"[FAIL] Step {step_num}: {name} - {detail}", file=sys.stderr)

    def step_health(self, client: httpx.Client) -> bool:
        """1. Health Check."""
        name = "Health Check"
        step_num = 1
        try:
            resp = client.get("/health")
            if resp.status_code != 200:
                self._record_result(
                    step_num, name, False, f"Expected HTTP 200, got {resp.status_code}: {resp.text}"
                )
                return False
            data = resp.json()
            if data.get("status") != "ok":
                self._record_result(step_num, name, False, f"Expected status 'ok', got: {data}")
                return False
            self._record_result(
                step_num,
                name,
                True,
                f"Status ok, environment={data.get('environment', 'unknown')}",
            )
            return True
        except Exception as exc:
            self._record_result(step_num, name, False, f"Connection or parsing error: {exc}")
            return False

    def step_create_mandate(self, client: httpx.Client) -> bool:
        """2. Create Mandate."""
        name = "Create Mandate"
        step_num = 2
        expires_at = (datetime.now(UTC) + timedelta(days=30)).isoformat()
        draft: dict[str, Any] = {
            "id": self.mandate_id,
            "purpose": "Smoke test policy for automated gateway verification",
            "max_amount_minor": 100000,  # $1,000.00
            "currency": "USD",
            "allowed_payees": [self.authorized_payee],
            "expires_at": expires_at,
            "approval_threshold_minor": 5000,  # payments > $50.00 escalate
            "max_payments_per_window": 10,
            "window_seconds": 3600,
        }
        try:
            resp = client.post("/mandates", json=draft)
            if resp.status_code != 201:
                self._record_result(
                    step_num, name, False, f"Expected HTTP 201, got {resp.status_code}: {resp.text}"
                )
                return False
            data = resp.json()
            sig = data.get("signature", "")
            if not sig or sig == "placeholder":
                self._record_result(
                    step_num, name, False, f"Mandate was not cryptographically signed: {data}"
                )
                return False
            self._record_result(
                step_num,
                name,
                True,
                f"Mandate '{self.mandate_id}' registered and signed (sig: {sig[:12]}...)",
            )
            return True
        except Exception as exc:
            self._record_result(step_num, name, False, f"Request failed: {exc}")
            return False

    def step_legitimate_payment(self, client: httpx.Client) -> bool:
        """3. Legitimate Payment."""
        name = "Legitimate Payment"
        step_num = 3
        payment_payload = {
            "mandate_id": self.mandate_id,
            "payee": self.authorized_payee,
            "amount_minor": 1500,  # $15.00 < $50.00 threshold
            "currency": "USD",
            "memo": "Legitimate office supplies purchase",
            "idempotency_key": f"smoke-legit-{uuid4().hex[:12]}",
        }
        try:
            resp = client.post("/payments", json=payment_payload)
            if resp.status_code != 200:
                self._record_result(
                    step_num, name, False, f"Expected HTTP 200, got {resp.status_code}: {resp.text}"
                )
                return False
            decision = resp.json()
            verdict = decision.get("verdict")
            if verdict != "approve":
                rules = decision.get("rule_results")
                self._record_result(
                    step_num,
                    name,
                    False,
                    f"Expected verdict 'approve', got '{verdict}'. Rules: {rules}",
                )
                return False
            self._record_result(
                step_num,
                name,
                True,
                f"Payment of 1500 minor units approved (decision: {decision.get('id')})",
            )
            return True
        except Exception as exc:
            self._record_result(step_num, name, False, f"Request failed: {exc}")
            return False

    def step_blocked_payment(self, client: httpx.Client) -> bool:
        """4. Blocked Payment."""
        name = "Blocked Payment"
        step_num = 4
        payment_payload = {
            "mandate_id": self.mandate_id,
            "payee": self.unauthorized_payee,
            "amount_minor": 1500,
            "currency": "USD",
            "memo": "Attack attempt: payment to unauthorized recipient",
            "idempotency_key": f"smoke-block-{uuid4().hex[:12]}",
        }
        try:
            resp = client.post("/payments", json=payment_payload)
            if resp.status_code != 200:
                self._record_result(
                    step_num, name, False, f"Expected HTTP 200, got {resp.status_code}: {resp.text}"
                )
                return False
            decision = resp.json()
            verdict = decision.get("verdict")
            if verdict != "block":
                self._record_result(
                    step_num, name, False, f"Expected verdict 'block', got '{verdict}'"
                )
                return False
            self._record_result(
                step_num,
                name,
                True,
                f"Payment correctly blocked by payee allowlist (decision: {decision.get('id')})",
            )
            return True
        except Exception as exc:
            self._record_result(step_num, name, False, f"Request failed: {exc}")
            return False

    def step_pending_approval(self, client: httpx.Client) -> bool:
        """5. Pending Approval (Escalation)."""
        name = "Pending Approval"
        step_num = 5
        payment_payload = {
            "mandate_id": self.mandate_id,
            "payee": self.authorized_payee,
            "amount_minor": 8000,  # $80.00 > $50.00 approval_threshold_minor
            "currency": "USD",
            "memo": "Large software subscription requiring human approval",
            "idempotency_key": f"smoke-pending-{uuid4().hex[:12]}",
        }
        try:
            resp = client.post("/payments", json=payment_payload)
            if resp.status_code != 200:
                self._record_result(
                    step_num, name, False, f"Expected HTTP 200, got {resp.status_code}: {resp.text}"
                )
                return False
            decision = resp.json()
            verdict = decision.get("verdict")
            if verdict != "escalate":
                self._record_result(
                    step_num, name, False, f"Expected verdict 'escalate', got '{verdict}'"
                )
                return False

            # Query /pending to locate the created approval record
            pending_resp = client.get(f"/pending?mandate_id={self.mandate_id}")
            if pending_resp.status_code != 200:
                self._record_result(
                    step_num,
                    name,
                    False,
                    f"GET /pending returned {pending_resp.status_code}: {pending_resp.text}",
                )
                return False

            pending_items = pending_resp.json()
            if not pending_items:
                self._record_result(
                    step_num, name, False, "No pending approval record found for mandate"
                )
                return False

            self.pending_id = pending_items[0].get("id")
            self._record_result(
                step_num,
                name,
                True,
                f"Payment over threshold escalated to pending approval (id: {self.pending_id})",
            )
            return True
        except Exception as exc:
            self._record_result(step_num, name, False, f"Request failed: {exc}")
            return False

    def step_approve_pending(self, client: httpx.Client) -> bool:
        """6. Approve Pending Payment."""
        name = "Approve Pending"
        step_num = 6
        if not self.pending_id:
            self._record_result(
                step_num, name, False, "Skipped: no pending_id available from step 5"
            )
            return False

        try:
            resp = client.post(f"/pending/{self.pending_id}/approve")
            if resp.status_code != 200:
                self._record_result(
                    step_num, name, False, f"Expected HTTP 200, got {resp.status_code}: {resp.text}"
                )
                return False
            data = resp.json()
            if data.get("status") != "approved":
                self._record_result(
                    step_num, name, False, f"Expected status 'approved', got: {data}"
                )
                return False
            self._record_result(
                step_num,
                name,
                True,
                f"Human approval executed and spend reserved for pending '{self.pending_id}'",
            )
            return True
        except Exception as exc:
            self._record_result(step_num, name, False, f"Request failed: {exc}")
            return False

    def step_audit_verification(self, client: httpx.Client) -> bool:
        """7. Audit Hash Chain Verification."""
        name = "Audit Verification"
        step_num = 7
        try:
            resp = client.get("/audit")
            if resp.status_code != 200:
                self._record_result(
                    step_num, name, False, f"Expected HTTP 200, got {resp.status_code}: {resp.text}"
                )
                return False
            data = resp.json()
            chain_valid = data.get("chain_valid")
            broken_id = data.get("broken_decision_id")
            total = data.get("total_records", 0)

            if not chain_valid or broken_id is not None:
                self._record_result(
                    step_num,
                    name,
                    False,
                    f"Cryptographic chain compromised! Broken at decision: {broken_id}",
                )
                return False

            self._record_result(
                step_num,
                name,
                True,
                f"Cryptographic hash chain verified valid across {total} decision records",
            )
            return True
        except Exception as exc:
            self._record_result(step_num, name, False, f"Request failed: {exc}")
            return False

    def run_all(self) -> int:
        """Execute all smoke test steps sequentially and return exit code."""
        print("=== MandateGate Smoke Verification ===")
        print(f"Target Base URL: {self.base_url}\n")

        with self._get_client() as client:
            self.step_health(client)
            self.step_create_mandate(client)
            self.step_legitimate_payment(client)
            self.step_blocked_payment(client)
            self.step_pending_approval(client)
            self.step_approve_pending(client)
            self.step_audit_verification(client)

        total_steps = self.passed + self.failed
        print("\n" + "=" * 45)
        print(f"Smoke Test Summary: {self.passed}/{total_steps} steps PASSED")
        print("=" * 45)

        if self.failed > 0:
            print(
                f"\n[FAIL] Smoke verification FAILED ({self.failed} step(s) failed).",
                file=sys.stderr,
            )
            return EXIT_FAILURE

        print("\n[OK] All smoke verification steps passed successfully.")
        return EXIT_SUCCESS


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="MandateGate API end-to-end smoke test suite.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "base_url",
        nargs="?",
        default="http://localhost:8000",
        help="Target base URL of MandateGate API.",
    )
    args = parser.parse_args(argv)
    runner = SmokeRunner(base_url=args.base_url)
    exit_code = runner.run_all()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
