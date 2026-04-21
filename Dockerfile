# OpenClaw — multi-stage build. Ubuntu 24.04.
# Stage 1: Go toolchain builds all recon binaries (cached)
# Stage 2: final runtime with just the binaries + Python

# ═══════════════════════════════════════════════════════════════
# Stage 1: Go tools build
# ═══════════════════════════════════════════════════════════════
FROM golang:1.25-bookworm AS gotools

ENV GOPATH=/go \
    GOBIN=/go/bin \
    PATH=/go/bin:$PATH

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/ffuf/ffuf/v2@latest \
    && go install -v github.com/tomnomnom/assetfinder@latest \
    && go install -v github.com/tomnomnom/waybackurls@latest \
    && go install -v github.com/gitleaks/gitleaks/v8@latest

# Nuclei templates
RUN /go/bin/nuclei -update-templates -silent || true


# ═══════════════════════════════════════════════════════════════
# Stage 2: final runtime
# ═══════════════════════════════════════════════════════════════
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin

# Runtime deps only (no Go toolchain)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    ca-certificates curl \
    nmap dnsutils jq git \
    && rm -rf /var/lib/apt/lists/*

# Copy built binaries from gotools stage
COPY --from=gotools /go/bin/ /usr/local/bin/
COPY --from=gotools /root/nuclei-templates/ /root/nuclei-templates/

# Python venv
RUN python3 -m venv /opt/venv

WORKDIR /app
COPY requirements.txt .
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY openclaw/ ./openclaw/
COPY scopes/ ./scopes/

RUN mkdir -p /app/data/runs /app/data/continuous

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -fs http://localhost:8501/_stcore/health || exit 1

CMD ["streamlit", "run", "openclaw/ui/streamlit_app.py", \
     "--server.port=8501", "--server.address=0.0.0.0", \
     "--server.headless=true", "--browser.gatherUsageStats=false"]
