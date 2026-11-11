"""Global pytest configuration and fixtures for MandateGate."""

from __future__ import annotations

import os

# Set required environment variables before any gateway modules are imported
os.environ.setdefault("MANDATE_SIGNING_KEY", "a" * 32)
os.environ.setdefault("PAYPAL_CLIENT_ID", "mock_client_id")
os.environ.setdefault("PAYPAL_CLIENT_SECRET", "mock_client_secret")
os.environ.setdefault("LLM_PROVIDER", "fake")
