# allhack

A proxy-first web pentesting platform. You browse the target through a MITM
proxy, mature CLI tools (`nuclei`, `sqlmap`, `ffuf`, `dalfox`, `nmap`) run
against captured endpoints on demand, and an LLM (via OpenRouter, free tier
by default) analyzes traffic, suggests concrete attacks and drafts the
client report.

No custom-written scanners, no agent theatre. Just a solid bench for manual
and assisted pentesting.

## Repo layout

The current, working codebase lives in `v2/`:

```
v2/
  backend/   FastAPI + mitmproxy + bundled CLI tools (Dockerfile, multi-arch)
  frontend/  React + plain CSS, served by nginx (minimalist UI)
  docker-compose.yml
  install.sh            one-shot installer (Ubuntu / Debian / macOS M-series or Intel)
  start.sh              up / stop / restart / --logs
  .env.example          OpenRouter config
  README.md             detailed docs for the stack
```

An older experimental version is kept under `backend/` and `frontend/` at
the repo root for reference, but it has known issues with its custom
scanners and is no longer the recommended entry point.

## Quick start

Requirements: Docker with the Compose plugin (Docker Desktop or OrbStack
on macOS, or `docker-ce` with `docker-compose-plugin` on Ubuntu/Debian),
and an OpenRouter API key (<https://openrouter.ai/keys> - free models are
fine).

```
cd v2
./install.sh       # checks Docker, seeds .env, builds images
# edit v2/.env and set OPENROUTER_API_KEY
./start.sh         # detached; add --logs to tail
```

Services after `start.sh`:

| Service      | URL                          |
| ------------ | ---------------------------- |
| UI           | http://localhost:3000        |
| API          | http://localhost:8000        |
| API docs     | http://localhost:8000/docs   |
| MITM proxy   | http://localhost:8080        |

Next steps are in `v2/README.md`:

- browser / OS CA certificate install for HTTPS interception
- running scans (per-tool target format and options)
- LLM copilot (suggest attacks, explain findings, generate report)
- full API reference

## What is inside

**Phase 0** — Docker stack, OpenRouter client, config introspection.

**Phase 1** — `mitmdump` running alongside the API, every intercepted
request/response persisted to SQLite (WAL mode, shared), Burp-like UI
with filters by host / method / URL, full request + response inspector,
browser CA certificate download.

**Phase 2** — Five CLI tool wrappers with parsers that emit normalized
`Finding` objects: `nuclei -jsonl`, `sqlmap` batch mode, `ffuf -of json`
with a bundled default wordlist, `dalfox --format json`, `nmap -oX -`.
Jobs run async with per-wrapper timeouts, cooperative cancel, stdout/
stderr capped at 1 MiB each.

**Phase 3** — LLM copilot over OpenRouter (default
`qwen/qwen3-coder:free`):
- one-click "Suggest attacks" on any captured flow returning structured
  JSON (suspicious parameters, auth scheme, scan proposals) that can be
  launched as real jobs with a click,
- "Explain findings" button producing a markdown write-up per scan,
- `/reports` page that compiles selected jobs and captured hosts into a
  client-facing markdown pentest report, downloadable as `.md`.

## Legal

For authorized security testing only. Use only on systems you own or have
written permission to test. Unauthorized testing is illegal.

## License

MIT
