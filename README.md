# allhack

[![CI](https://github.com/K3E9X/All-Hack/actions/workflows/ci.yml/badge.svg)](https://github.com/K3E9X/All-Hack/actions/workflows/ci.yml)

An autonomous web-application penetration tester you self-host. You authorize
a target, the agent walks an OWASP-WSTG x MITRE-ATT&CK methodology end to end
(recon -> mapping -> vulnerability analysis -> exploitation), every finding is
confirmed with a **safe** proof-of-exploit, findings are linked into
kill-chains, you watch it live, and you ship a client report.

It orchestrates mature CLI tools (nuclei, sqlmap, ffuf, dalfox, nmap, ...) -
it does not reinvent scanners - and uses an LLM to plan, reorder and explain.
Models are per-role and swappable: by default **Z.ai (GLM)** for the
planner/executor/validator, with **Moonshot (Kimi)** as a drop-in alternative
and **OpenRouter** as an optional free fallback. The whole loop also runs
**with no LLM** at all: the methodology engine is deterministic; the model
only adds judgement on top.

> For authorized testing only. Use it on systems you own or have written
> permission to test.

## Quick start

Requirements: Docker with the Compose plugin. Supported hosts:

- **Linux** (Ubuntu/Debian): `docker-ce` + `docker-compose-plugin`.
- **macOS** (Intel or Apple Silicon): Docker Desktop or OrbStack.
- **Windows**: via **WSL2** - see below.

Images are multi-arch (`linux/amd64` and `linux/arm64`).

### Windows (WSL2)

The tool is Linux/Docker only, so on Windows run it inside WSL2:

1. Install WSL2 with a distro: `wsl --install` (PowerShell, admin), reboot.
2. Either install Docker Desktop and enable **Settings -> Resources -> WSL
   integration** for your distro, or install `docker-ce` directly inside the
   WSL distro.
3. Open the WSL shell (Ubuntu), `git clone` the repo **inside** the WSL
   filesystem (e.g. `~/allhack`, not `/mnt/c/...` - native FS is much faster),
   then run `./install.sh` / `./start.sh` exactly as on Linux.
4. Browse to http://localhost:3000 from Windows - WSL2 forwards localhost.

```
./install.sh          # checks Docker, seeds .env, runs `docker compose build`
# edit .env -> set your Z.ai (GLM) or Kimi API key(s); optional, loop runs without
./start.sh            # docker compose up -d   (also: stop | restart | --logs)
```

`install.sh` is just a guarded wrapper around `docker compose build`; `start.sh`
around `docker compose up`. You can run those directly if you prefer.

| Service    | URL                          |
| ---------- | ---------------------------- |
| UI         | http://localhost:3000        |
| API        | http://localhost:8000        |
| API docs   | http://localhost:8000/docs   |
| MITM proxy | http://localhost:8080        |

The operator console (dark "terminal" theme) has eleven screens: Home (status +
toolchain SBOM), Engagements (with a per-area test radar), Live view (consoles,
assets, coverage, jobs, findings, kill-chains), Scans, Findings (deduped,
cross-engagement, triage + HackerOne export), Surface (hosts/ports/endpoints),
Methodology (WSTG x ATT&CK coverage matrix), Sandbox (safe in-scope PoC replay),
Proxy, Reports (md/pdf/json/sarif), and Settings (model router + masked keys,
persisted server-side with keys encrypted at rest).

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

### Authenticated, traffic-driven testing

For real coverage, run it authenticated:

- **Authenticated scan** - paste the primary identity's headers (Cookie /
  Authorization) in the engagement form. They're injected into every scanner
  (nuclei/sqlmap/ffuf/dalfox/katana/...) so it tests *behind the login*.
- **Real surface from the proxy** - browse the app through the MITM proxy
  while logged in; the autonomous run seeds those captured (parameterized)
  requests as scan targets, so sqlmap/dalfox/nuclei-dast hit the endpoints
  you actually exercised.
- **Grey-box IDOR/BOLA/BFLA** - add a *second* (low-privilege) identity's
  headers; the analysis replays captured requests as the other user to prove
  broken object-level authorization and privilege escalation (BFLA).
- **Out-of-band (blind) confirmation** - nuclei confirms blind SSRF/XXE/RCE
  via interactsh. By default it uses ProjectDiscovery's free public servers
  (no infra); set `INTERACTSH_SERVER` in `.env` to self-host.

The **deep analysis** pass (autorun in the validation phase, or on demand via
*Deep analysis* on the live view) mines everything captured through the proxy:

- **Secret & endpoint mining** - scans every captured text response (JS
  bundles, HTML, JSON, source maps) for secrets (cloud keys, tokens, private
  keys, JWTs) and pulls hidden API endpoints out of client code; discovered
  endpoints are seeded as new scan targets.
- **JWT analysis** - flags `alg=none`, cracks weak/known HMAC secrets offline,
  spots `kid`/`jku` injection surface, missing `exp`, and authz claims.
- **Access control in depth** - replays authenticated GETs anonymously to find
  missing-auth/broken-access-control, and flags method-tampering and
  mass-assignment candidates for manual review (writes are never executed).

Findings are partitioned into homogeneous categories (recon, enumeration,
access control, injection, auth & secrets, server & config) in both the live
view and the report.

### Proof of impact (opt-in)

Detection isn't proof. With **"Prove impact"** enabled on the engagement, after
a tool *confirms* an injection the agent demonstrates real impact by running a
**benign, read-only** command through it:

- **RCE / command injection** - re-runs commix with `--os-cmd` executing a
  read-only post-exploitation enumeration in one shot (privilege context,
  host/container detection, listening services & routes, scheduled tasks, SUID
  binaries, users). The output proves execution and maps the blast radius. It
  also **detects (never exploits) local privilege-escalation vectors** -
  passwordless `sudo` and GTFOBins-known SUID binaries - which feed an
  RCE → root kill-chain.
- **SQLi** - re-runs sqlmap in read-only context mode (`--current-user`,
  `--is-dba`, `--banner`, ...); OS command execution through the DB is a
  separate sub-opt-in.
- **Data-breach proof** (separate sub-opt-in) - retrieves a small, **bounded
  sample (≤3 rows)** of likely-sensitive tables via a confirmed SQLi to prove a
  real data exposure - far from a mass exfiltration.

It is **double-gated** (the opt-in flag *and* the exploitation approval
checkpoint), in-scope only, and strictly non-destructive: no writes, deletes,
persistence or lateral movement. The exact command and its raw output are
visible in the Jobs tab.

- **Known-CVE exploitation** - from the fingerprinted stack (WordPress,
  Atlassian, GitLab, Jenkins, Tomcat, Struts, ...) the agent runs the matching
  nuclei CVE templates (vetted public PoCs, out-of-band confirmed). Gated by the
  same `allow_active_exploit` opt-in.
- **Targeted CVE checks** - a curated set of high-value, actively-exploited CVEs
  (Apache 2.4.49/50 path traversal, Citrix, F5 BIG-IP, Pulse Secure, FortiOS file
  read) confirmed with a single read-only in-scope GET and a high-confidence file
  signature - near-zero false positives, no OOB infra. On a hit the CVE is
  reported with a redacted proof snippet.
- **Public-exploit aggregation (all sources)** - for every detected CVE the
  agent gathers the public PoCs that exist across sources - Exploit-DB (offline
  via `searchsploit`), Metasploit, GitHub, NVD, Vulners, Packet Storm - and
  shows them per finding with a runnable tier: `auto` (vetted, run in-scope:
  nuclei / Metasploit check), `sandbox` (raw scripts fetched and staged for an
  approved run in the isolated sandbox), `reference` (links). Raw public code is
  never auto-run - it is reviewed/run only via the approved sandbox.

Confirmed findings are then linked into **kill-chains** automatically:
leaked-secret → server compromise, broken-access-control → bulk data exposure,
weak-JWT → account takeover, SSRF → cloud credential theft, subdomain takeover
→ session theft, GraphQL introspection → authorization abuse (plus an optional
LLM pass for additional chains).

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
| `PLANNER/EXECUTOR/VALIDATOR_BASE_URL` `_API_KEY` `_MODEL` | Per-role LLM. Default `.env` points all three at **Z.ai GLM** (`glm-4.6`); set the key to activate. Swap to **Kimi** (`https://api.moonshot.cn/v1`, `kimi-k2-0905-preview`) per role. |
| `OPENROUTER_API_KEY` / `_MODEL` / `_FALLBACK_MODELS` | **Optional** free fallback aggregator, used only for roles whose own key is blank. |
| `POSTGRES_*`                   | Database credentials (defaults work out of the box). |
| `WPSCAN_API_TOKEN`             | Optional WordPress CVE lookups.                    |

Set a Z.ai (or Kimi) key on each role for the real thing; leave keys blank and
it falls back to OpenRouter's free models, so the stack works with a single key
or none.

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

## Tests

Backend unit tests cover the pure logic (authorization/scope gate, finding
classification, the JS/JWT/CORS/IDOR analyzers, the category taxonomy) without
touching Postgres/Redis:

```
cd backend
pip install -r requirements-dev.txt
pytest
```

CI (GitHub Actions, `.github/workflows/ci.yml`) resolves the full production
requirements (catching dependency conflicts), installs a minimal test set,
byte-compiles, runs `pytest`, and builds the frontend on every push and pull
request - so a dependency conflict or a broken build is caught before it ships.

## Architecture notes

- Single Postgres holds everything (engagements, jobs, findings, proxy flows,
  events, audit log); Redis is the arq job queue.
- The backend never spawns tools; it enqueues and a separate **worker**
  container runs them. The autonomous run is itself a long-lived worker task
  that launches scan sub-tasks concurrently.
- The MITM addon writes flows via sync psycopg; everything else uses asyncpg.

## License

MIT
