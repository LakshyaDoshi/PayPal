#!/usr/bin/env python3
"""
sanitize_paypal_response.py

Sanitizes and prints a clean diagnostic summary of a failed PayPal API response.
Redacts secrets, bearer tokens, client credentials, and sensitive payment data.
Extracts HTTP status, PayPal-Debug-Id, error name, message, details, and diagnostic links.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

# Sensitive keys to redact in JSON payloads
SENSITIVE_KEYS = {
    "access_token",
    "refresh_token",
    "client_secret",
    "client_id",
    "authorization",
    "secret",
    "password",
    "card_number",
    "number",
    "security_code",
    "cvv",
    "cvv2",
    "cookie",
    "set-cookie",
}

# Regex patterns for string sanitization
BEARER_PATTERN = re.compile(r"(Bearer\s+)[A-Za-z0-9\-_.]+", re.IGNORECASE)
BASIC_PATTERN = re.compile(r"(Basic\s+)[A-Za-z0-9+/=]+", re.IGNORECASE)


def redact_sensitive_values(data: Any) -> Any:
    """Recursively redact sensitive keys and credential patterns."""
    if isinstance(data, dict):
        sanitized: dict[str, Any] = {}
        for k, v in data.items():
            if str(k).lower() in SENSITIVE_KEYS:
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = redact_sensitive_values(v)
        return sanitized
    elif isinstance(data, list):
        return [redact_sensitive_values(item) for item in data]
    elif isinstance(data, str):
        cleaned = BEARER_PATTERN.sub(r"\1[REDACTED_TOKEN]", data)
        cleaned = BASIC_PATTERN.sub(r"\1[REDACTED_CREDENTIALS]", cleaned)
        return cleaned
    return data


def parse_raw_input(raw: str) -> tuple[int | None, str | None, dict[str, Any]]:
    """
    Parses input which may be:
    - Pure JSON error response
    - Raw HTTP dump with headers and JSON body
    """
    raw = raw.strip()
    status_code: int | None = None
    debug_id: str | None = None
    body_dict: dict[str, Any] = {}

    # Check for HTTP status line e.g., "HTTP/1.1 401 Unauthorized" or "Status: 400"
    status_match = re.search(r"(?:HTTP/[\d.]+|Status:?)\s+(\d{3})", raw)
    if status_match:
        status_code = int(status_match.group(1))

    # Check for Paypal-Debug-Id header
    debug_header_match = re.search(r"paypal-debug-id:\s*([a-zA-Z0-9_\-]+)", raw, re.IGNORECASE)
    if debug_header_match:
        debug_id = debug_header_match.group(1).strip()

    # Locate JSON start
    json_start = raw.find("{")
    if json_start != -1:
        json_str = raw[json_start:]
        try:
            body_dict = json.loads(json_str)
        except json.JSONDecodeError:
            # Try to grab up to the last closing brace
            json_end = raw.rfind("}")
            if json_end > json_start:
                try:
                    body_dict = json.loads(raw[json_start : json_end + 1])
                except json.JSONDecodeError:
                    body_dict = {"raw_content": raw[json_start:]}
            else:
                body_dict = {"raw_content": raw[json_start:]}
    else:
        body_dict = {"raw_content": raw}

    # Also check debug_id in json payload if not in header
    if not debug_id and isinstance(body_dict, dict):
        debug_id = (
            body_dict.get("debug_id")
            or body_dict.get("paypal_debug_id")
            or body_dict.get("Paypal-Debug-Id")
        )

    return status_code, debug_id, body_dict


def summarize_error(status: int | None, debug_id: str | None, data: dict[str, Any]) -> str:
    """Format sanitized PayPal error into a concise diagnostic report."""
    sanitized = redact_sensitive_values(data)

    name = sanitized.get("name") or sanitized.get("error") or "UNKNOWN_ERROR"
    message = (
        sanitized.get("message") or sanitized.get("error_description") or "No message provided."
    )
    details: list[dict[str, Any]] = sanitized.get("details", [])
    links: list[dict[str, Any]] = sanitized.get("links", [])

    lines = [
        "==================================================================",
        "             PAYPAL SANDBOX ERROR DIAGNOSTIC SUMMARY              ",
        "==================================================================",
        f" HTTP Status  : {status if status else 'Not Specified'}",
        f" Debug ID     : {debug_id if debug_id else 'NOT FOUND'}",
        f" Error Name   : {name}",
        f" Message      : {message}",
    ]

    if debug_id:
        lines.append(
            " Log Lookup   : https://developer.paypal.com/dashboard/dashboardSandboxApiCalls"
        )
        lines.append(f"                (Debug ID: {debug_id})")

    if details and isinstance(details, list):
        lines.append("\n Error Details:")
        for idx, item in enumerate(details, start=1):
            if isinstance(item, dict):
                issue = item.get("issue", "N/A")
                field = item.get("field", "N/A")
                desc = item.get("description", "N/A")
                lines.append(f"   [{idx}] Issue : {issue}")
                if field != "N/A":
                    lines.append(f"       Field : {field}")
                lines.append(f"       Desc  : {desc}")
            else:
                lines.append(f"   [{idx}] {item}")

    if links and isinstance(links, list):
        lines.append("\n Diagnostic Links:")
        for link in links:
            if isinstance(link, dict):
                rel = link.get("rel", "")
                href = link.get("href", "")
                method = link.get("method", "GET")
                lines.append(f"   - ({rel}) [{method}] {href}")

    lines.append("==================================================================")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sanitize and summarize a failed PayPal sandbox API response."
    )
    parser.add_argument(
        "file_or_json",
        nargs="?",
        default=None,
        help="Path to response file or raw JSON. If omitted, reads stdin.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Output as sanitized JSON instead of formatted text report.",
    )
    args = parser.parse_args()

    raw_text: str = ""
    if args.file_or_json:
        try:
            with open(args.file_or_json, encoding="utf-8") as f:
                raw_text = f.read()
        except OSError:
            # Treat argument as inline raw JSON/string
            raw_text = args.file_or_json
    else:
        if not sys.stdin.isatty():
            raw_text = sys.stdin.read()
        else:
            print("Enter/paste PayPal error response (Ctrl+D to finish):", file=sys.stderr)
            raw_text = sys.stdin.read()

    if not raw_text.strip():
        print("Error: No input provided to sanitize.", file=sys.stderr)
        return 1

    status, debug_id, data = parse_raw_input(raw_text)
    sanitized_data = redact_sensitive_values(data)

    if args.as_json:
        payload = {
            "http_status": status,
            "paypal_debug_id": debug_id,
            "response": sanitized_data,
        }
        print(json.dumps(payload, indent=2))
    else:
        print(summarize_error(status, debug_id, sanitized_data))

    return 0


if __name__ == "__main__":
    sys.exit(main())
