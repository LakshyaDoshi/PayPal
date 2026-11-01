---
name: paypal-sandbox-debug
description: Diagnose and resolve PayPal sandbox API errors including token expiry, base URL mismatches, unenabled app features, buyer approval flow states, and debug ID tracing.
---

# PayPal Sandbox Debugging Skill

This skill guides engineers and agents through systematic diagnosis and resolution of PayPal Sandbox API errors encountered in the MandateGate environment.

---

## Sandbox Error Diagnostic Checklist

When any PayPal API call fails, walk through this checklist in order:

### 1. Token Expiry
- **Symptom**: `401 Unauthorized` with `{"error": "invalid_token", "error_description": "Token has expired"}` or `INVALID_CLIENT`.
- **Root Cause**: PayPal OAuth2 access tokens have a limited lifespan (typically 32,400 seconds / 9 hours in sandbox).
- **Diagnostics**:
  1. Check token cached timestamp and `expires_in` attribute.
  2. Verify that token refresh is requested with HTTP Basic Auth (`client_id:client_secret`) on `/v1/oauth2/token` with body `grant_type=client_credentials`.
  3. Ensure token refresh triggers automatically before making payment requests if within a 5-minute expiry safety buffer.

### 2. Sandbox vs. Live Base URL Mismatch
- **Symptom**: `401 Unauthorized`, `404 Not Found`, unexpected routing errors, or authentication rejection of valid sandbox credentials.
- **Root Cause**: Request sent to live endpoint (`api-m.paypal.com`) instead of sandbox, or credentials from live account used against sandbox.
- **MandateGate Invariant**: MandateGate operates in **SANDBOX ONLY**. Live URLs must never be reached.
- **Verification**:
  - Valid Sandbox Endpoint: `https://api-m.sandbox.paypal.com`
  - Forbidden Live Endpoint: `https://api-m.paypal.com`
  - Inspect client configuration to confirm `base_url` is strictly set to `https://api-m.sandbox.paypal.com`.

### 3. Feature Not Enabled on Sandbox App
- **Symptom**: `403 Forbidden` with `NOT_AUTHORIZED`, `PERMISSION_DENIED`, or `FEATURE_NOT_ENABLED_FOR_MERCHANT`.
- **Root Cause**: The REST API application created under the PayPal Developer Dashboard lacks permissions or feature toggles required by the endpoint (e.g., Vault, Subscriptions, Customer Disputes, Advanced Credit and Debit Card processing).
- **Diagnostics & Resolution**:
  1. Log into [PayPal Developer Dashboard](https://developer.paypal.com/dashboard/applications/sandbox).
  2. Navigate to **Apps & Credentials** -> Select your Sandbox App.
  3. Under **App Settings** -> **Sandbox App Settings**, check the **Features** matrix.
  4. Enable the relevant feature (e.g. *Vault*, *Payment Methods*, *Accept payments*) and click **Save Changes**.
  5. Note: Permission changes can take 1–3 minutes to propagate across PayPal sandbox services.

### 4. Buyer-Approval-Required Orders
- **Symptom**: `422 Unprocessable Entity` with `{"issue": "ORDER_NOT_APPROVED", "description": "Payer has not yet approved the Order for payment."}` when attempting capture.
- **Root Cause**: PayPal Orders v2 (`/v2/checkout/orders`) created with `intent: "CAPTURE"` or `intent: "AUTHORIZE"` require explicit buyer approval by default. The order status remains `CREATED` or `SAVED` until approved.
- **Diagnostics & Lifecycle Verification**:
  1. Inspect the order status:
     - `CREATED`: Order initiated. Look for link `rel: "payer-action"` or `"approve"`. The buyer must open this URL and log in to a sandbox personal buyer account to approve.
     - `APPROVED`: Buyer completed approval. Now ready for `POST /v2/checkout/orders/{id}/capture`.
     - `COMPLETED`: Funds captured.
  2. In an autonomous AI agent workflow:
     - If the flow requires autonomous payment without buyer redirect, verify whether a vaulted payment method (`payment_source.vault_id` / customer billing agreement) must be supplied instead of a standard redirect order.

### 5. Response Debug IDs (`Paypal-Debug-Id`)
- **Symptom**: Unclear, generic, or intermittent upstream PayPal error responses.
- **Root Cause**: Internal PayPal downstream microservice rejection, risk engine trigger, or validation fault.
- **Diagnostics**:
  1. Every PayPal response (both error and success) includes the header:
     `Paypal-Debug-Id: <alphanumeric_id>` (e.g., `Paypal-Debug-Id: c8945f3ba1e09`).
  2. The JSON error payload also usually includes `"debug_id": "<alphanumeric_id>"`.
  3. Cross-reference this ID in the PayPal Developer Dashboard:
     - Navigate to [Sandbox API Calls Log](https://developer.paypal.com/dashboard/dashboardSandboxApiCalls).
     - Search by the `Paypal-Debug-Id` to inspect exact upstream request headers, request payload, internal failure reasons, and risk scores.
  4. Always quote this Debug ID when discussing issues or opening tickets with PayPal support.

---

## Sanitizing Failed PayPal Responses

To securely inspect and diagnose failed responses without leaking credentials, tokens, or PII into logs or chat, run the bundled helper script:

### Location
`scripts/sanitize_paypal_response.py`

### Usage Examples

1. **Pipe raw response or log output**:
   ```powershell
   Get-Content failed_response.json | python .agent/skills/paypal-sandbox-debug/scripts/sanitize_paypal_response.py
   ```

2. **Pass as file or inline argument**:
   ```powershell
   python .agent/skills/paypal-sandbox-debug/scripts/sanitize_paypal_response.py failed_response.json
   ```

3. **Output as sanitized JSON**:
   ```powershell
   python .agent/skills/paypal-sandbox-debug/scripts/sanitize_paypal_response.py --json failed_response.json
   ```

### Sanitization Guarantee
The script automatically redacts:
- Bearer tokens (`Bearer ...`)
- Basic authentication tokens (`Basic ...`)
- Client secrets, access tokens, and refresh tokens
- Sensitive card details (CVV, PAN numbers)
- Session cookies (`Set-Cookie`)
While extracting and clearly presenting:
- HTTP Status Code
- `Paypal-Debug-Id` with direct link to developer log lookup
- Error name & human-readable message
- Structured error details array (issue, field, description)
- Diagnostic links returned by PayPal
