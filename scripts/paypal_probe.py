#!/usr/bin/env python3
"""
scripts/paypal_probe.py

PayPal Sandbox Spike & Diagnostic Probe.
Tests the four core PayPal Sandbox flows in sequence:
  (a) OAuth2 Token Fetch
  (b) Orders v2 Create
  (c) Payouts v1 Send (to sandbox personal receiver email)
  (d) Invoicing v2 Create & Send

For each step, reports:
- PASS / FAIL
- HTTP Status Code
- Paypal-Debug-Id header
- Root cause diagnosis (e.g. buyer approval required, unenabled features)

Concludes with a definitive recommendation on which flow autonomous AI agents
can execute without requiring a human browser redirect step.

Usage:
    python scripts/paypal_probe.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

# Ensure repo and gateway are importable
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Nonce for unique transaction references
RUN_ID = datetime.now(UTC).strftime("%Y%m%d%H%M%S")


def load_env_file(env_path: Path) -> dict[str, str]:
    """Parse key-value pairs from .env without third-party dependencies."""
    env_vars: dict[str, str] = {}
    if not env_path.exists():
        return env_vars

    with open(env_path, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" in stripped:
                key, val = stripped.split("=", 1)
                clean_key = key.strip()
                clean_val = val.strip().strip("'\"")
                env_vars[clean_key] = clean_val
    return env_vars


def extract_debug_id(response: httpx.Response | None, body: dict[str, Any] | None = None) -> str:
    """Extract Paypal-Debug-Id from HTTP headers or response body."""
    if response is not None:
        header_id = response.headers.get("paypal-debug-id") or response.headers.get(
            "Paypal-Debug-Id"
        )
        if header_id:
            return header_id.strip()
    if body and isinstance(body, dict):
        body_id = body.get("debug_id")
        if body_id:
            return str(body_id).strip()
    return "N/A"


class PayPalProbe:
    """Probes PayPal Sandbox capabilities to identify zero-browser agent flows."""

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        base_url: str = "https://api-m.sandbox.paypal.com",
        receiver_email: str = "sandbox-buyer@example.com",
        timeout_seconds: float = 15.0,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip("/")
        self.receiver_email = receiver_email
        self.timeout = httpx.Timeout(timeout_seconds)
        self.access_token: str | None = None
        self.results: list[dict[str, Any]] = []

    async def run_probe(self) -> None:
        """Execute the probe steps in sequence."""
        print("=" * 80)
        print("         MANDATEGATE PAYPAL SANDBOX SPIKE & DIAGNOSTIC PROBE")
        print("=" * 80)
        print(f" Target Endpoint  : {self.base_url}")
        print(f" Receiver Account : {self.receiver_email}")
        print(f" Probe Timestamp  : {datetime.now(UTC).isoformat()}")
        print("-" * 80)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # Step (a): OAuth Token Fetch
            token_ok = await self._probe_token(client)
            if not token_ok:
                print("\n[!] Halting probe: Cannot proceed without valid OAuth2 access token.")
                self._print_summary()
                return

            # Step (b): Orders Create
            await self._probe_orders(client)

            # Step (c): Payouts
            await self._probe_payouts(client)

            # Step (d): Invoicing Create & Send
            await self._probe_invoicing(client)

        self._print_summary()

    async def _probe_token(self, client: httpx.AsyncClient) -> bool:
        """Step (a): OAuth Client Credentials Token Fetch."""
        print("[1/4] Probing (a) OAuth2 Client-Credentials Token Fetch...")
        url = f"{self.base_url}/v1/oauth2/token"

        try:
            resp = await client.post(
                url,
                auth=(self.client_id, self.client_secret),
                data={"grant_type": "client_credentials"},
                headers={"Accept": "application/json"},
            )
            debug_id = extract_debug_id(resp)
            status = resp.status_code

            if status == 200:
                data = resp.json()
                self.access_token = data.get("access_token")
                expires_in = data.get("expires_in", 32400)
                cause = f"Token acquired successfully (valid for {expires_in}s)."
                self.results.append(
                    {
                        "step": "(a) OAuth2 Token",
                        "status": "PASS",
                        "code": status,
                        "debug_id": debug_id,
                        "cause": cause,
                    }
                )
                print(f"      -> PASS (HTTP {status}) [Debug ID: {debug_id}]")
                return True
            else:
                data = resp.json() if resp.content else {}
                err = data.get("error") or "AUTH_FAILED"
                err_desc = data.get("error_description") or resp.text
                cause = f"Auth failed ({err}): {err_desc}. Check sandbox credentials or base URL."
                self.results.append(
                    {
                        "step": "(a) OAuth2 Token",
                        "status": "FAIL",
                        "code": status,
                        "debug_id": debug_id,
                        "cause": cause,
                    }
                )
                print(f"      -> FAIL (HTTP {status}) [Debug ID: {debug_id}]: {cause}")
                return False

        except Exception as exc:
            cause = f"Network or connection exception: {exc}"
            self.results.append(
                {
                    "step": "(a) OAuth2 Token",
                    "status": "FAIL",
                    "code": 0,
                    "debug_id": "N/A",
                    "cause": cause,
                }
            )
            print(f"      -> FAIL (Exception): {cause}")
            return False

    async def _probe_orders(self, client: httpx.AsyncClient) -> None:
        """Step (b): Orders v2 Create."""
        print("[2/4] Probing (b) Orders v2 Create (intent=CAPTURE)...")
        url = f"{self.base_url}/v2/checkout/orders"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "PayPal-Request-Id": f"probe_ord_{RUN_ID}",
        }
        body = {
            "intent": "CAPTURE",
            "purchase_units": [
                {
                    "reference_id": f"ref_{RUN_ID}",
                    "description": "MandateGate autonomous probe purchase",
                    "amount": {"currency_code": "USD", "value": "1.00"},
                    "payee": {"email_address": self.receiver_email},
                }
            ],
        }

        try:
            resp = await client.post(url, headers=headers, json=body)
            debug_id = extract_debug_id(resp)
            status = resp.status_code
            data = resp.json() if resp.content else {}

            if status in (200, 201):
                order_id = data.get("id", "")
                order_status = data.get("status", "")
                has_payer_action = any(
                    link.get("rel") in ("payer-action", "approve") for link in data.get("links", [])
                )

                if has_payer_action and order_status == "CREATED":
                    cause = (
                        f"Order created ({order_id}, status={order_status}). "
                        "BUYER APPROVAL REQUIRED: An unvaulted order cannot be captured "
                        "by an autonomous agent without a browser redirect."
                    )
                else:
                    cause = f"Order created ({order_id}, status={order_status})."

                self.results.append(
                    {
                        "step": "(b) Orders v2 Create",
                        "status": "PASS",
                        "code": status,
                        "debug_id": debug_id,
                        "cause": cause,
                    }
                )
                print(f"      -> PASS (HTTP {status}) [Debug ID: {debug_id}]")
                print(f"         Observation: {cause}")
            else:
                name = data.get("name", "ORDER_ERROR")
                msg = data.get("message", resp.text)
                cause = f"Failed ({name}): {msg}"
                self.results.append(
                    {
                        "step": "(b) Orders v2 Create",
                        "status": "FAIL",
                        "code": status,
                        "debug_id": debug_id,
                        "cause": cause,
                    }
                )
                print(f"      -> FAIL (HTTP {status}) [Debug ID: {debug_id}]: {cause}")

        except Exception as exc:
            self.results.append(
                {
                    "step": "(b) Orders v2 Create",
                    "status": "FAIL",
                    "code": 0,
                    "debug_id": "N/A",
                    "cause": f"Exception: {exc}",
                }
            )
            print(f"      -> FAIL (Exception): {exc}")

    async def _probe_payouts(self, client: httpx.AsyncClient) -> None:
        """Step (c): Batch Payouts v1 Send."""
        print("[3/4] Probing (c) Batch Payouts v1 to sandbox personal account...")
        url = f"{self.base_url}/v1/payments/payouts"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "PayPal-Request-Id": f"probe_pay_{RUN_ID}",
        }
        body = {
            "sender_batch_header": {
                "sender_batch_id": f"batch_{RUN_ID}",
                "email_subject": "MandateGate Agent Probe Payout",
                "email_message": "Automated probe disbursement.",
            },
            "items": [
                {
                    "recipient_type": "EMAIL",
                    "amount": {"value": "1.00", "currency": "USD"},
                    "note": "Autonomous agent payout spike",
                    "sender_item_id": f"item_{RUN_ID}",
                    "receiver": self.receiver_email,
                }
            ],
        }

        try:
            resp = await client.post(url, headers=headers, json=body)
            debug_id = extract_debug_id(resp)
            status = resp.status_code
            data = resp.json() if resp.content else {}

            if status in (200, 201):
                batch_id = data.get("batch_header", {}).get("payout_batch_id", "")
                batch_status = data.get("batch_header", {}).get("batch_status", "")
                cause = (
                    f"Payout batch accepted ({batch_id}, status={batch_status}). "
                    "ZERO BROWSER STEPS NEEDED: Direct disbursement to receiver."
                )
                self.results.append(
                    {
                        "step": "(c) Payouts v1",
                        "status": "PASS",
                        "code": status,
                        "debug_id": debug_id,
                        "cause": cause,
                    }
                )
                print(f"      -> PASS (HTTP {status}) [Debug ID: {debug_id}]")
                print(f"         Observation: {cause}")
            else:
                name = data.get("name", "PAYOUT_ERROR")
                msg = data.get("message", resp.text)
                if status == 403 or "NOT_ENABLED" in name or "FEATURE_NOT_ENABLED" in str(data):
                    cause = (
                        f"Failed ({name}): Feature not enabled on sandbox REST app. "
                        "Enable 'Payouts' under Apps & Credentials -> Features."
                    )
                else:
                    cause = f"Failed ({name}): {msg}"

                self.results.append(
                    {
                        "step": "(c) Payouts v1",
                        "status": "FAIL",
                        "code": status,
                        "debug_id": debug_id,
                        "cause": cause,
                    }
                )
                print(f"      -> FAIL (HTTP {status}) [Debug ID: {debug_id}]: {cause}")

        except Exception as exc:
            self.results.append(
                {
                    "step": "(c) Payouts v1",
                    "status": "FAIL",
                    "code": 0,
                    "debug_id": "N/A",
                    "cause": f"Exception: {exc}",
                }
            )
            print(f"      -> FAIL (Exception): {exc}")

    async def _probe_invoicing(self, client: httpx.AsyncClient) -> None:
        """Step (d): Invoicing v2 Create Draft & Send."""
        print("[4/4] Probing (d) Invoicing v2 Create Draft & Send...")
        draft_url = f"{self.base_url}/v2/invoicing/invoices"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "PayPal-Request-Id": f"probe_inv_{RUN_ID}",
        }
        body = {
            "detail": {
                "currency_code": "USD",
                "invoice_number": f"INV-{RUN_ID}",
                "invoice_date": datetime.now(UTC).strftime("%Y-%m-%d"),
                "note": "MandateGate agent test invoice",
            },
            "primary_recipients": [
                {
                    "billing_info": {
                        "email_address": self.receiver_email,
                    }
                }
            ],
            "items": [
                {
                    "name": "Autonomous Agent Compute Task",
                    "description": "Benchmark execution",
                    "quantity": "1",
                    "unit_amount": {"currency_code": "USD", "value": "1.00"},
                }
            ],
        }

        try:
            # 1. Create Draft
            resp = await client.post(draft_url, headers=headers, json=body)
            debug_id = extract_debug_id(resp)
            status = resp.status_code
            data = resp.json() if resp.content else {}

            if status in (200, 201):
                # Invoice created
                invoice_href = data.get("href") or ""
                invoice_id = invoice_href.split("/")[-1] if invoice_href else data.get("id", "")

                # 2. Send Invoice
                send_url = f"{self.base_url}/v2/invoicing/invoices/{invoice_id}/send"
                send_resp = await client.post(
                    send_url,
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                        "Content-Type": "application/json",
                    },
                    json={"send_to_recipient": True},
                )
                send_debug_id = extract_debug_id(send_resp)

                if send_resp.status_code in (200, 202, 204):
                    cause = (
                        f"Invoice created & sent ({invoice_id}). "
                        "REQUIRES ASYNC PAYER SETTLEMENT: Invoice delivered to recipient email, "
                        "awaiting external settlement or recording."
                    )
                    self.results.append(
                        {
                            "step": "(d) Invoicing v2",
                            "status": "PASS",
                            "code": send_resp.status_code,
                            "debug_id": send_debug_id,
                            "cause": cause,
                        }
                    )
                    print(
                        f"      -> PASS (HTTP {send_resp.status_code}) [Debug ID: {send_debug_id}]"
                    )
                    print(f"         Observation: {cause}")
                else:
                    send_data = send_resp.json() if send_resp.content else {}
                    send_err = send_data.get("message", send_resp.text)
                    cause = f"Draft created ({invoice_id}), but send failed: {send_err}"
                    self.results.append(
                        {
                            "step": "(d) Invoicing v2",
                            "status": "PARTIAL",
                            "code": send_resp.status_code,
                            "debug_id": send_debug_id,
                            "cause": cause,
                        }
                    )
                    print(f"      -> PARTIAL (Send failed HTTP {send_resp.status_code}): {cause}")
            else:
                name = data.get("name", "INVOICE_ERROR")
                msg = data.get("message", resp.text)
                cause = f"Invoice draft failed ({name}): {msg}"
                self.results.append(
                    {
                        "step": "(d) Invoicing v2",
                        "status": "FAIL",
                        "code": status,
                        "debug_id": debug_id,
                        "cause": cause,
                    }
                )
                print(f"      -> FAIL (HTTP {status}) [Debug ID: {debug_id}]: {cause}")

        except Exception as exc:
            self.results.append(
                {
                    "step": "(d) Invoicing v2",
                    "status": "FAIL",
                    "code": 0,
                    "debug_id": "N/A",
                    "cause": f"Exception: {exc}",
                }
            )
            print(f"      -> FAIL (Exception): {exc}")

    def _print_summary(self) -> None:
        """Print the results table and final architectural flow recommendation."""
        print("\n" + "=" * 80)
        print("                        SPIKE RESULTS SUMMARY")
        print("=" * 80)
        print(f"{'Flow Step':<24} | {'Status':<7} | {'HTTP':<5} | {'Debug ID':<16} | {'Details'}")
        print("-" * 80)

        for res in self.results:
            step = res["step"]
            status = res["status"]
            code = str(res["code"])
            debug_id = res["debug_id"]
            cause = res["cause"]
            # Wrap cause if long
            print(f"{step:<24} | {status:<7} | {code:<5} | {debug_id:<16} | {cause}")

        print("=" * 80)
        print("                  AGENT ZERO-BROWSER FLOW RECOMMENDATION")
        print("=" * 80)
        print(
            """
RECOMMENDATION:
1. Primary Autonomous Agent Payment Flow: PayPal Payouts v1 (POST /v1/payments/payouts)
   - Why: Payouts are merchant-initiated disbursements that transfer funds directly
     from the merchant account to the payee's PayPal email or phone number.
   - Zero-Browser Invariant: Completely autonomous; requires NO buyer approval redirect
     or browser session.
   - Requirement: The REST API App in developer.paypal.com must have 'Payouts' enabled
     under App Settings -> Features.

2. Why Standard Orders v2 (POST /v2/checkout/orders) CANNOT be used autonomously:
   - Creating an order with intent=CAPTURE results in status 'CREATED' with a 'payer-action'
     approval link.
   - PayPal strictly rejects POST /v2/checkout/orders/{id}/capture with 422 ORDER_NOT_APPROVED
     until an interactive user completes PayPal web authentication in a browser.
   - Exception: Orders v2 CAN only be captured autonomously if customer payment sources
     are pre-vaulted (payment_source.vault_id).

3. Invoicing v2 (POST /v2/invoicing/invoices):
   - Invoicing is asynchronous: it bills a counterparty who must subsequently pay via email
     link, rather than executing an immediate agent payment.
"""
        )
        print("=" * 80)


def main() -> int:
    env_vars = load_env_file(REPO_ROOT / ".env")

    client_id = os.getenv("PAYPAL_CLIENT_ID") or env_vars.get("PAYPAL_CLIENT_ID")
    client_secret = os.getenv("PAYPAL_CLIENT_SECRET") or env_vars.get("PAYPAL_CLIENT_SECRET")
    base_url = (
        os.getenv("PAYPAL_BASE_URL")
        or env_vars.get("PAYPAL_BASE_URL")
        or "https://api-m.sandbox.paypal.com"
    )
    receiver_email = (
        os.getenv("PAYPAL_SANDBOX_RECEIVER_EMAIL")
        or os.getenv("PAYPAL_RECEIVER_EMAIL")
        or env_vars.get("PAYPAL_SANDBOX_RECEIVER_EMAIL")
        or env_vars.get("PAYPAL_RECEIVER_EMAIL")
        or "sandbox-personal@example.com"
    )

    if not client_id or not client_secret:
        print(
            "ERROR: Missing PAYPAL_CLIENT_ID or PAYPAL_CLIENT_SECRET.\n"
            "Please configure them in .env before running the probe.",
            file=sys.stderr,
        )
        return 1

    probe = PayPalProbe(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
        receiver_email=receiver_email,
    )

    asyncio.run(probe.run_probe())
    return 0


if __name__ == "__main__":
    sys.exit(main())
