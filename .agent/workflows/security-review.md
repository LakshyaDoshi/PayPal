---
name: security-review
description: Review files changed on this branch against the MandateGate security checklist and output findings by severity with file:line references.
---

# /security-review Workflow

This workflow audits all changed files on the current branch against the MandateGate security checklist to prevent financial loss, authorization bypass, race conditions, and prompt injection.

---

## 1. Discovery: Identify Branch Changes

Run the following commands to locate modified, added, or staged files:
```powershell
# Compare current branch against base branch (e.g., origin/main or main)
$baseBranch = if (git rev-parse --verify origin/main 2>$null) { "origin/main" } else { "main" }
$changedFiles = git diff --name-only $baseBranch...HEAD

# If empty or on an uncommitted working tree, inspect working tree diff
if (-not $changedFiles) {
    $changedFiles = git diff --name-only HEAD
}
if (-not $changedFiles) {
    $changedFiles = git status --porcelain | ForEach-Object { ($_ -split '\s+')[-1] }
}
$changedFiles
```

Review the full patch for each file using:
```powershell
git diff $baseBranch...HEAD -- <file>
```

---

## 2. Review Checklist

Audit the patch line-by-line against these eight critical vulnerability categories:

### 1. Fail-Closed Paths
- [ ] Every exception, network timeout, HTTP status != 200/201, invalid JSON, or schema error in payment authorization MUST evaluate to `BLOCK`.
- [ ] No `try/except` block may swallow an error and default to `True`, `allow`, or `approve`.
- [ ] An `APPROVE` verdict must ONLY be produced by explicit rule engine success.

### 2. Mandate Tampering
- [ ] Client or agent input must never be capable of mutating active mandate parameters (spending limits, allowable payees, expiry timestamps, rule configs).
- [ ] Mandate IDs received from requests must be verified against persistent storage records, not trusted blindly from request payloads.
- [ ] Any signed tokens or mandate representations must have their signatures/hashes validated before use.

### 3. Replay / Duplicate Requests
- [ ] All payment and authorization requests must require a unique idempotency key or request ID.
- [ ] Verify database constraints (e.g., `UNIQUE(idempotency_key)`) prevent re-executing or double-charging.
- [ ] Replayed requests must return the cached initial response or fail safely, never re-trigger a second payment.

### 4. Race Conditions on Budget Checks
- [ ] Budget checks and balance updates must be atomic.
- [ ] Verify that balance verification and balance decrement do NOT suffer from TOCTOU (Time-Of-Check to Time-Of-Use) flaws.
- [ ] In SQLite, ensure transactions use `BEGIN IMMEDIATE` or atomic update patterns (e.g., `UPDATE mandates SET remaining_cents = remaining_cents - :amount WHERE id = :id AND remaining_cents >= :amount`).

### 5. Payee Normalization Tricks
- [ ] Payee identifiers (PayPal email, Merchant ID) must undergo strict canonicalization prior to allowlist matching.
- [ ] Verify resistance against:
  - Case differences (`Vendor@Example.com` vs `vendor@example.com`)
  - Whitespace padding / URL encoding tricks
  - Unicode homoglyph attacks or confusable characters
  - Subdomain or path manipulation

### 6. Negative or Oversized Amounts
- [ ] Monetary amounts must be strictly positive integers (`amount > 0`).
- [ ] Verify rejection of zero (`0`), negative numbers, floats, and scientific notation.
- [ ] Verify amount bounds checks against transaction caps and mandate upper limits before evaluating rules.

### 7. Secrets in Code or Logs
- [ ] Check diff for hardcoded API keys, client secrets, bearer tokens, or real credentials.
- [ ] Verify that `.env` files are not tracked by git.
- [ ] Inspect log statements: ensure headers, authorization payloads, access tokens, and sensitive account details are redacted.
- [ ] Confirm MCP code routes all logging to `sys.stderr` and never writes to `sys.stdout`.

### 8. Untrusted Text Reaching the LLM Judge
- [ ] Untrusted inputs (item titles, merchant descriptions, user memos, prompt arguments) must be sanitized and isolated using rigid delimiters before inclusion in LLM prompts.
- [ ] Prevent indirect prompt injection attacks designed to manipulate the LLM judge's output.
- [ ] The LLM judge output parser must enforce that the model can ONLY return `BLOCK` or `ESCALATE`—any response attempting to return `APPROVE` must be rejected and defaulted to `BLOCK`.

---

## 3. Findings Report Format

Format findings in the chat response as follows:

### Security Review Summary
- **Files Reviewed**: `<list of files>`
- **Total Findings**: `<count>` (Critical: `<n>`, High: `<n>`, Medium: `<n>`, Low: `<n>`)

### Findings Table
| Severity | Category | File:Line | Description & Impact | Remediation |
| :--- | :--- | :--- | :--- | :--- |
| `CRITICAL` | Race Condition | [app/budget.py:45](file:///d:/paypal/app/budget.py#L45) | Budget checked in Python before DB write without atomic lock | Use `UPDATE ... WHERE remaining >= :amount` with rowcount check |

*(If no vulnerabilities are detected, explicitly state: **"No security findings identified across checked files. All 8 checklist invariants are satisfied."**)*
