# MandateGate

MandateGate is an MCP (Model Context Protocol) gateway bridging autonomous AI agents and PayPal (Sandbox only). It establishes a fail-closed, deterministic security boundary for agentic payments.

## Architecture & Principles

- **Deterministic Rule Engine**: Approvals originate exclusively from explicit policy verification.
- **Fail Closed**: Any network failure, schema mismatch, or unhandled exception immediately results in a `BLOCK`.
- **Financial Invariant**: All amounts are strictly modeled as integer minor units (cents). Floating-point arithmetic is forbidden.
- **LLM Safety Net**: The LLM judge acts as an advisory secondary layer restricted to returning `BLOCK` or `ESCALATE` (never `APPROVE`).
- **Decoupled Core Logic**: Pure domain and state machine models have zero dependencies on FastAPI or MCP SDK.
- **Audit Hash Chain**: Decisions are permanently linked via an immutable, cryptographically verified SHA-256 hash chain.

## Directory Structure

```text
paypal/
├── apps/
│   └── gateway/             # Python package "gateway"
│       └── gateway/
│           ├── api.py       # FastAPI REST & SSE endpoints
│           ├── contract.py  # Pydantic v2 domain models
│           ├── drafter.py   # Natural language mandate proposal extraction
│           ├── judge.py     # Advisory LLM safety judge
│           ├── llm.py       # Gemini REST client & mock adapters
│           ├── mandate.py   # HMAC-SHA256 mandate cryptographic signing
│           ├── mcp_server.py# MCP Stdio & SSE tool server
│           ├── rules.py     # Deterministic policy & velocity rule engine
│           ├── service.py   # Gateway orchestrator & circuit breaker
│           └── store.py     # SQLite persistence & audit hash chain
├── bench/                   # Benchmark runner & evaluation dataset
│   ├── cases.jsonl          # 10 starter benchmark cases (dev + test split)
│   └── runner.py            # CLI benchmark harness (rules_only, judge_only, combined)
├── docs/
│   └── openapi.json         # Exported OpenAPI schema
├── scripts/
│   ├── export_openapi.py    # OpenAPI schema exporter
│   ├── paypal_probe.py      # Sandbox OAuth & order verification probe
│   ├── seed.py              # Demo mandate database seeder
│   └── smoke.py             # 7-step end-to-end smoke test suite
├── tests/                   # 270+ unit, chaos, API, and bench tests
├── Dockerfile               # Production container image
├── pyproject.toml           # Project metadata & dependencies
├── render.yaml              # Render Blueprint specification
└── .env.example             # Documented environment template
```

---

## Run Locally

### 1. Prerequisites
- Python 3.11+
- Virtual environment tool (`venv` or `uv`)

### 2. Environment Setup
```bash
# Clone and enter repo
cd paypal

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install package in editable mode with development dependencies
pip install -e ".[dev]"

# Create local environment file
cp .env.example .env
```

Generate a secure 32+ character signing key for `.env`:
```bash
# Linux / macOS:
openssl rand -hex 32

# Windows PowerShell:
python -c "import secrets; print(secrets.token_hex(32))"
```
Paste this into `.env` as `MANDATE_SIGNING_KEY`.

### 3. Database Seeding (Optional)
When the database is empty, the server automatically runs `scripts/seed.py` on startup to seed `demo-mandate-001`. You can also seed manually:
```bash
python scripts/seed.py
```

### 4. Start the Local Server
```bash
uvicorn gateway.api:app --host 0.0.0.0 --port 8000 --reload
```
Interactive API documentation is accessible at:
- Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
- Health Check: [http://localhost:8000/health](http://localhost:8000/health)

### 5. Run the Smoke Test Suite
With the server running, execute the 7-step smoke test in another terminal:
```bash
python scripts/smoke.py http://localhost:8000
```
This tests:
1. `GET  /health` (Health check)
2. `POST /mandates` (Create and cryptographically sign mandate)
3. `POST /payments` (Legitimate payment approved)
4. `POST /payments` (Payment to unauthorized payee blocked)
5. `POST /payments` (Payment over threshold escalated to pending approval)
6. `POST /pending/{id}/approve` (Human approval executed)
7. `GET  /audit` (Cryptographic hash chain verified valid)

### 6. Run Tests & Linters
```bash
# Run full test suite
pytest -v

# Run benchmark harness
python bench/runner.py --split test --mode combined

# Run linter and formatter
ruff check .
ruff format --check .
```

---

## Deploy to Render

MandateGate is fully configured for zero-friction deployment on [Render](https://render.com) using either **Native Python** or **Docker**.

### Option A: One-Click Blueprint Deployment (`render.yaml`)
1. Push your repository to GitHub or GitLab.
2. In the Render Dashboard, click **New +** -> **Blueprint**.
3. Connect your repository. Render reads `render.yaml` automatically.
4. Set your private secrets in the Render dashboard (see [Environment Variables](#environment-variables)).
5. Click **Apply**.

### Option B: Manual Web Service Setup
1. In the Render Dashboard, click **New +** -> **Web Service**.
2. Select your repository.
3. Configure the service settings:
   - **Environment**: `Python 3` (or `Docker`)
   - **Build Command**: `pip install --upgrade pip && pip install -e .`
   - **Start Command**: `uvicorn gateway.api:app --host 0.0.0.0 --port $PORT`
   - **Health Check Path**: `/health`
4. Add the required and optional environment variables in the **Environment** tab.

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `MANDATE_SIGNING_KEY` | **Yes** | — | Cryptographic secret key (minimum 32 characters) used for HMAC-SHA256 mandate signing. The server **fails startup immediately** if unset or shorter than 32 chars (without logging its value). |
| `PAYPAL_CLIENT_ID` | Optional | `""` | PayPal Sandbox developer application client ID. If omitted, gateway runs in safe `FakeProvider` mode. |
| `PAYPAL_CLIENT_SECRET` | Optional | `""` | PayPal Sandbox developer application secret. Required if `PAYPAL_CLIENT_ID` is set. |
| `PAYPAL_BASE_URL` | Optional | `https://api-m.sandbox.paypal.com` | Sandbox API endpoint. (Live endpoints are strictly prohibited). |
| `LLM_PROVIDER` | Optional | `gemini` | AI Safety Judge provider: `gemini` or `fake` (for testing). |
| `LLM_API_KEY` | Optional | `""` | Google Gemini API key. Required when `LLM_PROVIDER=gemini`. |
| `JUDGE_MODEL` | Optional | `gemini-2.5-flash` | Gemini model variant for advisory evaluations. |
| `CORS_ORIGINS` | Optional | `["*"]` | Allowed origins for React front end. Accepts JSON array (e.g. `["https://app.onrender.com"]`) or comma-separated list (`https://app.onrender.com,http://localhost:3000`). |
| `DB_PATH` | Optional | `mandategate.sqlite3` | SQLite database file location. |
| `PORT` | Auto | `8000` | Port for `uvicorn` HTTP server. Supplied automatically by Render. |
| `PYTHONPATH` | Auto | `apps/gateway:.` | Python import path. Configured in `render.yaml` and `Dockerfile`. |

---

## Render Free Tier & Automatic Seeding

On Render's free tier, the web service spins down after periods of inactivity, and the local disk is ephemeral and resets. 

MandateGate handles this automatically:
- During application startup (`lifespan`), the gateway inspects the database.
- If the database contains zero mandates (`store.count_mandates() == 0`), the startup hook runs `scripts/seed.py` automatically.
- This creates and cryptographically signs `demo-mandate-001` ($500.00 budget, $250.00 threshold) so the application is always ready for live interactive testing immediately after spin-up.

---

## Verifying Deployment with Smoke Test

Once deployed, run the automated smoke verification against your live Render domain:

```bash
python scripts/smoke.py https://<your-service-name>.onrender.com
```

Expected output:
```text
=== MandateGate Smoke Verification ===
Target Base URL: https://mandategate.onrender.com

[PASS] Step 1: Health Check - Status ok, environment=sandbox
[PASS] Step 2: Create Mandate - Mandate 'smoke-mandate-...' registered and signed
[PASS] Step 3: Legitimate Payment - Payment of 1500 minor units approved
[PASS] Step 4: Blocked Payment - Payment correctly blocked by payee allowlist
[PASS] Step 5: Pending Approval - Payment over threshold escalated to pending approval
[PASS] Step 6: Approve Pending - Human approval executed and spend reserved for pending
[PASS] Step 7: Audit Verification - Cryptographic hash chain verified valid across decision records

=============================================
Smoke Test Summary: 7/7 steps PASSED
=============================================

[OK] All smoke verification steps passed successfully.
```
