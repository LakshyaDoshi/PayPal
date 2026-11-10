# syntax=docker/dockerfile:1
FROM python:3.11-slim

# System configuration & Python optimization
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="/app/apps/gateway:/app" \
    PORT=8000

WORKDIR /app

# Install runtime utilities (curl for container healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Layer-cached package installation
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

# Copy application code
COPY . .

# Run as non-root user for security hardening
RUN useradd -m -u 1000 gateway && \
    chown -R gateway:gateway /app
USER gateway

# Render dynamic port exposure (defaults to 8000 for local runs)
EXPOSE 8000

# Docker native healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

# Start uvicorn binding to $PORT dynamically
CMD ["sh", "-c", "uvicorn gateway.api:app --host 0.0.0.0 --port ${PORT:-8000}"]
