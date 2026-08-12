# syntax=docker/dockerfile:1.6
# Isolated runner for untrusted third-party PoCs.
#
# Multi-arch: linux/amd64 and linux/arm64 (Apple Silicon). Nothing here is
# architecture-specific - the base image is multi-arch, apt resolves per-arch,
# and every pinned wheel publishes an aarch64 build, so no compiler is needed.
#
# Kept minimal on purpose: every extra tool in here is a tool a trojaned PoC
# gets to use. No curl, no git, no ssh client, no package manager at runtime.
FROM python:3.12-slim

# iptables to pin egress, gosu to drop privileges after pinning it.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables gosu nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir fastapi==0.115.0 uvicorn==0.32.0 pydantic==2.10.2

# The account the PoC runs as. No shell, no home worth reading, and crucially
# no CAP_NET_ADMIN, so it cannot alter the egress rules that contain it.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin poc

WORKDIR /app
COPY runner.py /app/runner.py
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# /work is a tmpfs at runtime: staged code never touches a disk that survives.
RUN mkdir -p /work && chown poc:poc /work

EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["uvicorn", "runner:app", "--host", "0.0.0.0", "--port", "8090"]
