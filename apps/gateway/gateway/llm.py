"""
gateway.llm

LLM client protocol and adapters for MandateGate advisory safety judge.
Enforces:
- Zero temperature for deterministic evaluations.
- Strict timeout configuration.
- Single retry policy on transient transport/server errors.
- Structured JSON output adhering to provided schemas.
- Fail closed on client failures.
- No leakage of API keys or sensitive secrets into logs or stdout.
- No imports of FastAPI or MCP.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Protocol, runtime_checkable

import httpx
from pydantic import BaseModel

logger = logging.getLogger("gateway.llm")


class LLMError(Exception):
    """Base exception for LLM operations. All failures fail closed."""


class LLMTimeoutError(LLMError):
    """LLM request timed out."""


class LLMResponseError(LLMError):
    """LLM response was malformed, invalid JSON, or returned an HTTP error."""


@runtime_checkable
class LLMClient(Protocol):
    """Protocol for LLM structured output completions."""

    async def complete_json(
        self,
        system: str,
        user: str,
        schema: type[BaseModel] | dict[str, Any],
    ) -> dict[str, Any]:
        """Generate structured JSON adhering to the provided schema.

        Parameters
        ----------
        system:
            High-priority system instructions.
        user:
            User prompt / contextual data.
        schema:
            Pydantic model class or JSON Schema dictionary defining expected output.

        Returns
        -------
        dict[str, Any]:
            Parsed JSON object conforming to schema.

        Raises
        ------
        LLMTimeoutError:
            If request exceeds configured timeout after retries.
        LLMResponseError:
            If response is invalid JSON, missing content, or HTTP error.
        LLMError:
            Any other client failure.
        """
        ...


class FakeLLM:
    """Deterministic fake LLM client for testing.

    Can return canned responses, raise programmed errors, and records
    prompt call history for prompt-injection and delimiter verification.
    """

    def __init__(
        self,
        responses: list[dict[str, Any] | str] | dict[str, Any] | str | None = None,
        *,
        error_to_raise: Exception | None = None,
    ) -> None:
        self.history: list[dict[str, Any]] = []
        self._responses: list[dict[str, Any] | str] = []
        if responses is not None:
            if isinstance(responses, list):
                self._responses = list(responses)
            else:
                self._responses = [responses]
        self._error_to_raise = error_to_raise

    def set_responses(self, responses: list[dict[str, Any] | str] | dict[str, Any] | str) -> None:
        """Update canned responses."""
        if isinstance(responses, list):
            self._responses = list(responses)
        else:
            self._responses = [responses]

    def set_error(self, error: Exception | None) -> None:
        """Set or clear exception to raise on next calls."""
        self._error_to_raise = error

    async def complete_json(
        self,
        system: str,
        user: str,
        schema: type[BaseModel] | dict[str, Any],
    ) -> dict[str, Any]:
        """Record the call and return the next programmed canned response."""
        self.history.append(
            {
                "system": system,
                "user": user,
                "schema": schema,
            }
        )

        if self._error_to_raise is not None:
            raise self._error_to_raise

        if not self._responses:
            raise LLMResponseError("FakeLLM ran out of canned responses.")

        next_resp = self._responses.pop(0) if len(self._responses) > 1 else self._responses[0]
        if isinstance(next_resp, dict):
            return dict(next_resp)
        if isinstance(next_resp, str):
            try:
                parsed = json.loads(next_resp)
                if isinstance(parsed, dict):
                    return parsed
                raise LLMResponseError(f"Canned response is not a JSON object: {type(parsed)}")
            except json.JSONDecodeError as exc:
                raise LLMResponseError(f"Canned response contains invalid JSON: {exc}") from exc

        raise LLMResponseError(f"Unsupported canned response type: {type(next_resp)}")


class GeminiLLMClient:
    """Real LLM client for Google Gemini REST API using httpx async client.

    Configuration:
    - Temperature: 0.0 (deterministic)
    - Timeout: 10.0 seconds default
    - One retry on timeout / transient network or 5xx HTTP error
    - responseMimeType: 'application/json'
    - responseSchema: JSON Schema representation
    - Header auth using 'x-goog-api-key' (never passed in query params)
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str = "https://generativelanguage.googleapis.com",
        timeout_seconds: float = 10.0,
        max_retries: int = 1,
    ) -> None:
        self.api_key = api_key or os.environ.get("LLM_API_KEY", "")
        self.model = model or os.environ.get("JUDGE_MODEL", "gemini-2.5-flash")
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def _extract_schema_dict(self, schema: type[BaseModel] | dict[str, Any]) -> dict[str, Any]:
        """Convert Pydantic model class or raw dict into a JSON schema dict."""
        if isinstance(schema, dict):
            return schema
        if hasattr(schema, "model_json_schema") and callable(schema.model_json_schema):
            return schema.model_json_schema()
        raise LLMError(f"Invalid schema specification: {type(schema)}")

    async def complete_json(
        self,
        system: str,
        user: str,
        schema: type[BaseModel] | dict[str, Any],
    ) -> dict[str, Any]:
        """Call Gemini generateContent with structured JSON configuration."""
        if not self.api_key:
            raise LLMError("LLM_API_KEY is not configured for GeminiLLMClient.")

        schema_dict = self._extract_schema_dict(schema)
        endpoint = f"{self.base_url}/v1beta/models/{self.model}:generateContent"

        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key,
        }

        payload: dict[str, Any] = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user}],
                }
            ],
            "system_instruction": {
                "parts": [{"text": system}],
            },
            "generationConfig": {
                "temperature": 0.0,
                "responseMimeType": "application/json",
                "responseSchema": schema_dict,
            },
        }

        attempts = 0
        max_attempts = 1 + max(0, self.max_retries)
        last_error: Exception | None = None

        timeout = httpx.Timeout(self.timeout_seconds)

        async with httpx.AsyncClient(timeout=timeout) as client:
            while attempts < max_attempts:
                attempts += 1
                try:
                    response = await client.post(endpoint, headers=headers, json=payload)

                    if response.status_code >= 500 or response.status_code == 429:
                        # Server side or rate limit failure; can retry once
                        if attempts < max_attempts:
                            await asyncio.sleep(0.5)
                            continue
                        raise LLMResponseError(
                            f"Gemini API returned transient HTTP status {response.status_code}."
                        )

                    if response.status_code != 200:
                        # 4xx client errors (excluding 429) do not retry
                        raise LLMResponseError(
                            f"Gemini API returned error HTTP status {response.status_code}."
                        )

                    try:
                        resp_data = response.json()
                    except Exception as json_err:
                        raise LLMResponseError(
                            "Gemini API response body was not valid JSON."
                        ) from json_err

                    candidates = resp_data.get("candidates", [])
                    if not candidates:
                        raise LLMResponseError("Gemini API response did not contain candidates.")

                    parts = candidates[0].get("content", {}).get("parts", [])
                    if not parts or "text" not in parts[0]:
                        raise LLMResponseError(
                            "Gemini candidate did not contain text content part."
                        )

                    raw_text = parts[0]["text"]
                    parsed = json.loads(raw_text)
                    if not isinstance(parsed, dict):
                        raise LLMResponseError("Extracted text is not a JSON object.")

                    return parsed

                except httpx.TimeoutException as exc:
                    last_error = LLMTimeoutError(
                        f"Gemini API request timed out after {self.timeout_seconds}s."
                    )
                    if attempts < max_attempts:
                        await asyncio.sleep(0.5)
                        continue
                    raise last_error from exc
                except httpx.RequestError as exc:
                    last_error = LLMResponseError(
                        f"Gemini API transport network error: {type(exc).__name__}."
                    )
                    if attempts < max_attempts:
                        await asyncio.sleep(0.5)
                        continue
                    raise last_error from exc

        if last_error is not None:
            raise last_error
        raise LLMResponseError("Gemini request failed without specific exception.")


def get_llm_client() -> LLMClient:
    """Factory creating an LLMClient instance based on environment configuration."""
    provider = os.environ.get("LLM_PROVIDER", "gemini").strip().lower()
    if provider == "gemini":
        return GeminiLLMClient()
    if provider == "fake":
        return FakeLLM()
    raise ValueError(f"Unsupported LLM_PROVIDER: {provider}")
