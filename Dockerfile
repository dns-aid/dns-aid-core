# DNS-AID MCP Server Docker Image
#
# Build:
#   docker build -t dns-aid-mcp .
#
# Run:
#   docker run -p 8000:8000 dns-aid-mcp
#
# With AWS credentials:
#   docker run -p 8000:8000 \
#     -e AWS_ACCESS_KEY_ID=xxx \
#     -e AWS_SECRET_ACCESS_KEY=xxx \
#     dns-aid-mcp

# Use multi-stage build for smaller final image
# Pin base image with digest for reproducible builds
FROM python:3.11-slim@sha256:6ed5bff4d7396e3244b0f3c2fe578c87862efedd3e5e8cebd14a4428ec39ee5a AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Build wheels instead of editable install
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir --upgrade pip \
    && pip wheel --no-cache-dir --wheel-dir /wheels ".[mcp,route53]" \
    && pip wheel --no-cache-dir --wheel-dir /wheels .

# Production image
FROM python:3.11-slim@sha256:6ed5bff4d7396e3244b0f3c2fe578c87862efedd3e5e8cebd14a4428ec39ee5a AS production

LABEL org.opencontainers.image.title="DNS-AID MCP Server"
LABEL org.opencontainers.image.description="DNS-based Agent Identification and Discovery"
LABEL org.opencontainers.image.source="https://github.com/dns-aid/dns-aid-core"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.sbom="cyclonedx"

# Create non-root user for security
RUN groupadd --gid 1000 dnsaid \
    && useradd --uid 1000 --gid dnsaid --shell /bin/bash --create-home dnsaid

WORKDIR /app

# Install from pre-built wheels (no source code needed)
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

# Switch to non-root user
USER dnsaid

# Expose MCP HTTP port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default environment
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Run MCP server with HTTP transport
# Binds to 0.0.0.0 in container (safe due to container isolation)
ENTRYPOINT ["dns-aid-mcp"]
CMD ["--transport", "http", "--host", "0.0.0.0", "--port", "8000"]
