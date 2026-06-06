# allhack

An autonomous web-application penetration tester you self-host. You authorize
a target, the agent walks an OWASP-WSTG x MITRE-ATT&CK methodology end to end
(recon -> mapping -> vulnerability analysis -> exploitation), every finding is
confirmed with a **safe** proof-of-exploit, findings are linked into
kill-chains, you watch it live, and you ship a client report.

It orchestrates mature CLI tools (nuclei, sqlmap, ffuf, dalfox, nmap, ...) -
it does not reinvent scanners - and uses an LLM (via OpenRouter, free models
work) to plan, reorder and explain. The whole loop also runs **with no LLM**:
the methodology engine is deterministic; the model only adds judgement on top.

> For authorized testing only. Use it on systems you own or have written
> permission to test.

## Quick start

Requirements: Docker with the Compose plugin (Docker Desktop / OrbStack on
macOS, or `docker-ce` + `docker-compose-plugin` on Ubuntu/Debian). Multi-arch:
`linux/amd64` and `linux/arm64` (Apple Silicon).

```
./install.sh          # checks Docker, seeds .env, builds the images
# (optional) edit .env -> OPENROUTER_API_KEY  — the loop runs without it
./start.sh            # up | stop | restart | --logs
```

| Service    | URL                          |
| ---------- | ---------------------------- |
| UI         | http://localhost:3000        |
| API        | http://localhost:8000        |
| API docs   | http://localhost:8000/docs   |
| MITM proxy | http://localhost:8080        |

## Run an engagement

1. **Engagements** -> enter a target you own, tick the authorization box,
   create. Attestation authorizes it immediately; the scope list bounds what
   gets touched.
2. Open its **live view** -> **Run**. Watch recon -> mapping -> vuln ->
   exploitation -> validation stream in the agent console; if you enabled
   "require approval before exploitation", approve the checkpoint.
3. Download the **report** (`.md` or printable HTML) once findings are
   validated and chains are built.

You can also drive tools manually: browse the target through the MITM proxy
(install its CA from the Proxy page), inspect captured requests, and launch
individual scans from the Scans page.

## How it works

```
            Frontend (React, nginx)
                   |  REST + WebSocket
            API (FastAPI)
         /         |          \
 Engagements   Orchestrator   Proxy capture
 + authz gate   (the brain)    (mitmproxy -> Postgres)
                   |
        Planner -> Executor -> Validator
        (methodology   (arq worker     (safe-PoC
         catalog)       runs tools)     confirmation)
                   |
        Postgres  +  Redis (arq queue)
                   |
        Tool arsenal (in the worker image)
```

- **Authorization gate** — every scan is tied to an authorized engagement
  whose scope allow-list covers the host; out-of-scope requests are refused
  and audited. Attestation is enough for your own domains; DNS-TXT /
  `.well-known` ownership proof is available as a fallback.
- **Methodology engine** — a declarative catalog maps each OWASP WSTG test to
  its MITRE ATT&CK technique(s) and the tool that runs it, gated by what's
  been discovered (`GET /api/methodology/catalog`).
- **Agent loop** — the planner builds the next batch from the catalog filtered
  by live state (assets, fingerprints, coverage), advancing one phase at a
  time; the executor runs each task through the queue and folds results back
  into state, expanding the surface as it learns. An LLM optionally reorders
  the batch (never invents tasks).
- **Validation** — sqlmap/commix/dalfox are tool-confirmed; exposed resources
  (`.git`/`.env`/...) and reflected XSS are re-checked with a single in-scope,
  read-only request and a benign marker. Status is confirmed / likely /
  unconfirmed / false_positive with a tracked FP rate. No destructive payloads.
- **Kill-chains** — confirmed/likely findings are linked into multi-step attack
  paths (deterministic rules + optional LLM).
- **Live view** — the loop emits typed events to Postgres; a WebSocket tails
  them so the operator console, phase timeline and findings update in real time.

## Tools (bundled in the worker image)

Recon: `nmap`, `naabu`, `subfinder`, `dnsx`, `httpx`, `katana`, `gau`.
Fingerprint / WAF: `whatweb`, `httpx`, `wafw00f`.
Content discovery: `ffuf`.
Vuln / CMS / server: `nuclei`, `nikto`, `wpscan`.
Injection: `sqlmap` (SQLi), `commix` (command).
XSS: `dalfox`. TLS: `testssl.sh`. Capture: `mitmproxy`.

`GET /api/scans/tools` reports each tool's category and whether its binary is
present. WordPress CVE correlation needs `WPSCAN_API_TOKEN` (free, optional).

## Configuration (`.env`)

| Variable                       | Purpose                                            |
| ------------------------------ | -------------------------------------------------- |
| `OPENROUTER_API_KEY`           | Enables LLM features (planner reorder, explanations). Optional. |
| `OPENROUTER_MODEL`             | Default `qwen/qwen3-coder:free`.                   |
| `OPENROUTER_FALLBACK_MODELS`   | Tried on 429/5xx from the primary.                |
| `PLANNER/EXECUTOR/VALIDATOR_*` | Optional per-role provider (Z.ai GLM, Moonshot Kimi). Fall back to OpenRouter. |
| `POSTGRES_*`                   | Database credentials (defaults work out of the box). |
| `WPSCAN_API_TOKEN`             | Optional WordPress CVE lookups.                    |

If a role has no key it reuses the OpenRouter config, so the stack works with a
single key (or none).

## Layout

```
backend/         FastAPI app + arq worker (one image, two roles)
  app/
    api/         REST + WebSocket routers
    engagements/ authorization gate + scope
    methodology/ WSTG x ATT&CK test catalog
    orchestrator/ planner, executor, run loop, state, approvals
    scans/       wrappers + queue runner + job storage
    validation/  safe-PoC validators + kill-chaining
    reporting/   client report (Markdown / HTML)
    proxy/       mitmproxy addon + flow storage
    events.py    live event stream
    db.py        Postgres pool
  Dockerfile     multi-arch, bundles all CLI tools
frontend/        React + plain CSS, served by nginx
docker-compose.yml   postgres, redis, backend, worker, frontend
install.sh / start.sh
```

## Architecture notes

- Single Postgres holds everything (engagements, jobs, findings, proxy flows,
  events, audit log); Redis is the arq job queue.
- The backend never spawns tools; it enqueues and a separate **worker**
  container runs them. The autonomous run is itself a long-lived worker task
  that launches scan sub-tasks concurrently.
- The MITM addon writes flows via sync psycopg; everything else uses asyncpg.

## License

MIT
