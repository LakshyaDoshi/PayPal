---
name: verify
description: Run ruff check, pytest -q, and gitleaks detect (if installed), reporting results in a concise summary table.
---

# /verify Workflow

Use this workflow to validate code formatting, test status, and secret detection across the MandateGate codebase.

## Execution Steps

Run the following validation commands in sequence from the workspace root:

### 1. Code Quality & Linting (`ruff`)
Run Ruff linter to verify code cleanliness and type standards:
```powershell
ruff check .
```
*(Optionally verify formatting with `ruff format --check .`)*

### 2. Test Suite (`pytest`)
Execute the test suite in quiet mode:
```powershell
pytest -q
```
*Note: Never alter or weaken assertions if tests fail.*

### 3. Secret Leakage Detection (`gitleaks`)
Check if `gitleaks` is available on the host system:
```powershell
if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
    gitleaks detect --no-git --verbose
} else {
    Write-Output "GITLEAKS_NOT_INSTALLED"
}
```
If `gitleaks` is not installed on the system, record its status as `SKIPPED (not installed)`.
If installed and leaks are found, record `FAIL` and list flagged files.
If installed and no leaks found, record `PASS`.

---

## Output Format

Report the results directly in chat using the following concise markdown table:

| Check | Status | Details / Summary |
| :--- | :--- | :--- |
| **Ruff Check** | `PASS` \| `FAIL` | `<rule violation count or "All checks passed">` |
| **Pytest** | `PASS` \| `FAIL` | `<passed/failed test counts and execution time>` |
| **Gitleaks** | `PASS` \| `FAIL` \| `SKIPPED` | `<clean / leaked secret count / not installed>` |

### Post-Check Actions
- If all checks pass: State that the codebase is clean, verified, and ready.
- If any check fails: Display the failing output excerpts, isolate the root cause, and specify concrete remediation without weakening any existing test assertions or security rules.
