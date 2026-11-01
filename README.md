# MandateGate

MandateGate is an MCP (Model Context Protocol) gateway bridging autonomous AI agents and PayPal (Sandbox only). It establishes a fail-closed, deterministic security boundary for agentic payments.

## Architecture & Principles

- **Deterministic Rule Engine**: Approvals originate exclusively from explicit policy verification.
- **Fail Closed**: Any network failure, schema mismatch, or unhandled exception immediately results in a `BLOCK`.
- **Financial Invariant**: All amounts are strictly modeled as integer minor units (cents). Floating-point arithmetic is forbidden.
- **LLM Safety Net**: The LLM judge acts as an advisory secondary layer restricted to returning `BLOCK` or `ESCALATE` (never `APPROVE`).
- **Decoupled Core Logic**: Pure domain and state machine models have zero dependencies on FastAPI or MCP SDK.

## Directory Structure

```text
paypal/
├── apps/
│   └── gateway/             # Python package "gateway"
│       ├── gateway/
│       │   ├── __init__.py
│       │   ├── contract.py  # Pydantic v2 domain models
│       │   └── api.py       # FastAPI adapter layer
│       └── tests/           # Package-level tests
├── bench/                   # Benchmark suites & load testing
├── docs/                    # OpenAPI specifications & architecture documentation
│   └── openapi.json         # Exported OpenAPI schema for mock servers
├── scripts/                 # Utility scripts (e.g. export_openapi.py)
├── pyproject.toml
└── .env.example
```

## Quickstart

1. Copy `.env.example` to `.env` and configure sandbox keys:
   ```bash
   cp .env.example .env
   ```
2. Install dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
3. Run verification suite:
   ```bash
   ruff check .
   pytest -q
   ```
4. Export OpenAPI schema:
   ```bash
   python scripts/export_openapi.py
   ```
