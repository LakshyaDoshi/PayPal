---
description: Always-on workspace rules and security invariants for MandateGate
trigger: always_on
alwaysApply: true
---

# MandateGate Workspace Rules

These rules are ALWAYS active for the MandateGate project. Every code change, test, refactoring, and agent interaction must comply with the following invariants without exception.

---

## 1. Project Context & Technology Stack

- **Project Purpose**: MandateGate is an MCP (Model Context Protocol) gateway bridging AI agents and PayPal.
- **Environment**: **SANDBOX ONLY**. Live PayPal production endpoints or credentials must never be configured, called, or referenced.
- **Approved Stack**:
  - Runtime: Python 3.11+
  - Web & API: FastAPI
  - Data Validation: Pydantic v2
  - Protocols: MCP Python SDK (stdio / SSE transports)
  - HTTP Client: `httpx` (async)
  - Persistence: Standard library `sqlite3`
  - Testing & Mocking: `pytest`, `pytest-asyncio`, `respx`
  - Linting & Formatting: `ruff`

---

## 2. Architectural Boundaries & Modularity

- **Keep Modules Small & Pure**: Business logic must remain decoupled from transport and delivery frameworks.
- **No Framework Leakage into Core Logic**:
  - Core domain models, mandate validation, policy evaluation, and transaction state machines **MUST NOT** import `fastapi`, `starlette`, or `mcp`.
  - Framework integration code (FastAPI routes, MCP tool handlers) must act solely as thin adapter layers calling into pure domain functions.

---

## 3. Financial Invariants

- **Integer Minor Units Only**: All monetary amounts must be stored, computed, and transferred as integer minor units (e.g., cents in USD: `$12.50` = `1250`).
- **Never Use Float**: Floating-point numbers (`float`) are strictly forbidden for currency, prices, balances, limits, and financial arithmetic. Use `int` exclusively (or standard library `decimal.Decimal` if exact fractional calculations are required before casting to minor unit integers).

---

## 4. Security & Safety Invariants

### A. FAIL CLOSED
- Any exception, network failure, timeout, malformed payload, schema mismatch, or unexpected condition encountered in any payment authorization, verification, or execution path **MUST** result in an immediate **`BLOCK`**.
- An unhandled error or failure must **NEVER** fail open or default to an approval.
- An **`APPROVE`** decision may **ONLY** originate from the deterministic rule engine when all checks and mandate policies have explicitly evaluated to passed.

### B. LLM Judge Constraints
- When an LLM judge evaluates transactions or context, the LLM judge is restricted to returning either **`BLOCK`** or **`ESCALATE`** (to human review).
- The LLM judge **MUST NEVER** have the authority to return `APPROVE` or override a rule engine rejection.

### C. Stdout Transport Protection in MCP Code
- MCP stdio transport relies exclusively on clean JSON-RPC communication over `sys.stdout`.
- **NEVER** use `print()`, write to `sys.stdout`, or direct logger outputs to stdout within MCP server or handler code.
- Always use `sys.stderr` or Python's standard `logging` library configured to emit to `stderr`.

### D. Secret Management
- **NEVER** read, print, output to terminal/logs, or commit `.env` or any live API secret, client secret, or private key.
- Always document configuration schema and environment variable requirements via `.env.example`.
- Ensure `.env` is listed in `.gitignore`.

---

## 5. Testing & Verification Standards

- **Complete Test Coverage**: Every function, tool handler, and domain module must ship with corresponding `pytest` tests.
- **Assertion Inviolability**:
  - **NEVER** weaken, skip, comment out, or delete an assertion to make a failing test pass.
  - If a test assertion appears incorrect or conflicting, **STOP immediately and explain the issue** to the user before modifying assertions.
- **Mocking**: Use `respx` for all PayPal HTTP interactions in unit and integration tests. Live network requests must never execute during tests.

---

## 6. Code Quality & Type Safety

- **Strict Type Annotations**: Type hints must be used across all function signatures, parameters, return types, and class attributes.
- **Linter & Formatter**: Always run `ruff check` and `ruff format` before finishing any task to guarantee clean formatting and no lint violations.
