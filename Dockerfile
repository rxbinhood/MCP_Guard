# syntax=docker/dockerfile:1
# MCPGuard: API + web UI in one image.
# Untrusted MCP servers are NOT run in this container: it drives the host Docker daemon
# (mounted socket) to build and run each target in its own hardened sandbox container.

# ---------- 1. build the frontend ----------
FROM node:22-slim AS ui
RUN npm install -g pnpm@12.9.1
WORKDIR /ui
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

# ---------- 2. runtime ----------
FROM python:3.12-slim
ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# Docker CLI only (the daemon is the host's, via /var/run/docker.sock).
COPY --from=docker:29-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker:29-cli /usr/local/libexec/docker/cli-plugins/docker-buildx /usr/local/libexec/docker/cli-plugins/docker-buildx
# Gitleaks (secret scanner).
RUN arch=$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64) \
 && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY mcpguard ./mcpguard
# Editable install keeps test_servers/ and frontend/dist next to the package.
RUN pip install --no-cache-dir -e ".[scanners]"
COPY test_servers ./test_servers
COPY tests ./tests
COPY scripts ./scripts
COPY --from=ui /ui/dist ./frontend/dist

ENV MCPGUARD_HOME=/data \
    PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1
CMD ["mcpguard", "serve", "--host", "0.0.0.0", "--port", "8000"]
