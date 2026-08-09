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
FROM python:3.11-slim@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Build wheels instead of editable install.
#
# Dependencies come from the committed uv.lock, not from a fresh resolution.
# Previously this ran `pip wheel ".[mcp,route53,akamai-edgedns]"`, which resolved
# every dependency from its declared floor at build time with no lockfile and no
# hashes: image contents differed between builds, and an upstream major release
# could break the image with no change to this repo. That is exactly what
# happened when mcp 2.0.0 removed mcp.server.fastmcp — the image built fine and
# the container then exited at import (#230, #235).
#
# uv is pinned so the export step is itself reproducible; the exported file
# carries per-artifact hashes and --require-hashes makes pip reject anything that
# does not match.
COPY pyproject.toml uv.lock README.md ./
COPY src/ src/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir uv==0.10.4

# --locked, not --frozen: --frozen only means "use uv.lock as-is" and exits 0
# even when the lock no longer matches pyproject.toml, which would let a stale
# lock pin versions the manifest no longer asks for. --locked asserts the lock is
# current and exits 1 otherwise, making a stale lockfile a build failure.
# --no-emit-project excludes dns-aid itself; it is built as a wheel below.
RUN uv export --locked --no-dev \
        --extra mcp --extra route53 --extra akamai-edgedns \
        --no-emit-project --format requirements-txt -o /tmp/requirements.txt \
    && pip wheel --no-cache-dir --require-hashes -r /tmp/requirements.txt --wheel-dir /wheels \
    && pip wheel --no-cache-dir --no-deps --wheel-dir /wheels .

# Production image
FROM python:3.11-slim@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff AS production

LABEL org.opencontainers.image.title="DNS-AID MCP Server"
LABEL org.opencontainers.image.description="DNS-based Agent Identification and Discovery"
LABEL org.opencontainers.image.source="https://github.com/dns-aid/dns-aid-core"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.sbom="cyclonedx"

# Create non-root user for security
RUN groupadd --gid 1000 dnsaid \
    && useradd --uid 1000 --gid dnsaid --shell /bin/bash --create-home dnsaid

WORKDIR /app

# Install from pre-built wheels (no source code needed).
# --no-index forbids reaching the index: everything must come from the wheels the
# builder produced from uv.lock. Without it a missing wheel would be silently
# fetched and resolved fresh, reintroducing the unpinned install this stage exists
# to avoid.
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels /wheels/*.whl \
    && rm -rf /wheels

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
