# syntax=docker/dockerfile:1.6
# Multi-arch image: linux/amd64 (Intel/AMD) and linux/arm64 (Apple Silicon M1/M2/M3).
#
# Bundled pentest tools:
#   - nuclei     (ProjectDiscovery, Go binary)
#   - ffuf       (Go binary)
#   - dalfox     (Go binary)
#   - nmap       (apt)
#   - sqlmap     (apt)
#   - mitmproxy  (pip)
# Python app runs FastAPI backend.

FROM python:3.12-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        git \
        unzip \
        nmap \
        sqlmap \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Pinned versions (updated manually). Matches the official release naming.
ARG NUCLEI_VERSION=3.3.5
ARG FFUF_VERSION=2.1.0
ARG DALFOX_VERSION=2.9.2

# Map Docker TARGETARCH to the suffix each project uses in its release archive.
#   amd64 -> amd64
#   arm64 -> arm64
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) ARCH_SUFFIX=amd64 ;; \
        arm64) ARCH_SUFFIX=arm64 ;; \
        *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    cd /tmp; \
    \
    # nuclei
    curl -fsSL -o nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH_SUFFIX}.zip"; \
    unzip -q nuclei.zip; \
    install -m 0755 nuclei /usr/local/bin/nuclei; \
    rm -f nuclei nuclei.zip LICENSE.md README*.md; \
    \
    # ffuf
    curl -fsSL -o ffuf.tar.gz \
        "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${ARCH_SUFFIX}.tar.gz"; \
    tar -xzf ffuf.tar.gz; \
    install -m 0755 ffuf /usr/local/bin/ffuf; \
    rm -f ffuf ffuf.tar.gz LICENSE; \
    \
    # dalfox
    curl -fsSL -o dalfox.tar.gz \
        "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox_${DALFOX_VERSION}_linux_${ARCH_SUFFIX}.tar.gz"; \
    tar -xzf dalfox.tar.gz; \
    install -m 0755 dalfox /usr/local/bin/dalfox; \
    rm -f dalfox dalfox.tar.gz LICENSE README*.md

# Pre-download nuclei templates so first scan is fast.
RUN nuclei -update-templates -silent || true

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY app ./app
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 8000 8080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
