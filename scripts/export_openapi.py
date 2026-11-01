#!/usr/bin/env python3
"""
scripts/export_openapi.py

Exports the FastAPI OpenAPI JSON schema to /docs/openapi.json
for mock server generation and contract integration.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure repository and apps/gateway are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
GATEWAY_PATH = REPO_ROOT / "apps" / "gateway"

if str(GATEWAY_PATH) not in sys.path:
    sys.path.insert(0, str(GATEWAY_PATH))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from gateway.api import app  # noqa: E402


def export_schema(output_path: Path) -> None:
    """Extract and write the OpenAPI schema JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    schema = app.openapi()

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)

    print(
        f"Successfully exported OpenAPI schema ({len(json.dumps(schema))} bytes) to: {output_path}"
    )


def main() -> int:
    output_path = REPO_ROOT / "docs" / "openapi.json"
    export_schema(output_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
