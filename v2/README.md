# allhack v2

A proxy-first web pentesting platform. You browse the target through a MITM
proxy, the tool captures the real attack surface, and mature CLI tools
(`nuclei`, `sqlmap`, `ffuf`, `dalfox`, `nmap`) run against it on demand. An
LLM (via OpenRouter, free tier by default) analyzes captured traffic,
suggests attacks, and drafts the client report.

No custom scanners. No reinventing the wheel. No magic "AI that finds
everything for you". Just a solid bench for manual + assisted pentesting.

## Status

Earlier phases (Phase 0-3) built the bench: docker stack, MITM proxy
capture, CLI wrappers (10 tools: nuclei, sqlmap, ffuf, dalfox, nmap,
subfinder, httpx, katana, testssl.sh, wpscan), and a single-LLM copilot
(suggest attacks / explain findings / markdown report).

**Phase 1 of the AutoPentester rewrite (this commit family)** lays the
foundation for the agent system that comes next:

  - Storage moves SQLite -> **Postgres** (asyncpg pool, shared between
    the API, the worker, and the mitmproxy addon via psycopg sync).
  - A **Redis-backed worker queue** (arq) runs scans in an isolated
    container. The backend never spawns subprocesses anymore; it only
    enqueues. Cancel still works via `arq.abort_job`.
  - The LLM client becomes a **per-role router** (planner / executor /
    validator). Each role picks its own OpenAI-compatible provider
    (Z.ai GLM, Moonshot Kimi, OpenRouter, OpenAI, ...). Roles with no
    key fall back to OpenRouter so existing Phase 0-3 flows keep
    working with zero config changes.

**Phase 2 (this commit family)** adds the authorization gate (spec §8):

  - **Engagements**: a scan can only run against a target tied to an
    AUTHORIZED engagement whose scope allow-list covers the host. The
    backend rejects un-authorized or out-of-scope scans with 403.
  - **Ownership verification**: prove control of the target by DNS TXT
    (`allhack-verify=<token>`) or a `.well-known/allhack-<token>.txt`
    file. The verifier is side-effect free and tries DNS first.
  - **Append-only audit log**: every engagement create/authorize/verify-
    fail/close and every scan submit/cancel/block is recorded. Read it
    at `GET /api/audit`.
  - **UI**: a new Engagements tab to create, see the challenge, and
    verify; the Scans tab now requires picking an authorized engagement.

**Phase 3 (this commit family)** broadens the tool arsenal from 10 to 17
wrappers so every major web vuln-class has at least one tool: command
injection (`commix`), web-server misconfig (`nikto`), WAF detection
(`wafw00f`), tech fingerprint (`whatweb`), plus recon expansion (`naabu`,
`dnsx`, `gau`). Each wrapper is tagged with a category surfaced by
`/api/scans/tools`.

**Phase 4 (this commit family)** is the brain - the agent system that turns
the bench into an autonomous pentester (spec §4-5):

  - **Methodology engine**: a declarative test catalog (`GET
    /api/methodology/catalog`) of 16 items, each mapping an OWASP WSTG test
    to its MITRE ATT&CK technique(s), the wrapper that runs it, and an
    `applies_when` condition. Phases are walked in PTES order: recon ->
    mapping -> vuln_analysis -> exploitation.
  - **Engagement state / memory**: discovered assets (hosts/endpoints/
    params), fingerprints, and a (catalog item x asset) coverage matrix.
  - **Planner -> Executor loop**: the planner builds candidate tasks from
    the catalog filtered by the live state, advances one phase at a time,
    and (optionally) has the planner LLM reorder the batch. The executor
    runs each task through the normal scan queue and folds findings back
    into state (fingerprints unlock tech-gated tests; crawled/archived
    URLs unlock parameter-gated tests). It loops until coverage saturates,
    the budget is hit, or you stop it.
  - **Control + state API**: `POST /api/engagements/{id}/run`,
    `/stop`, and `GET /api/engagements/{id}/state` (assets, technologies,
    coverage, aggregated findings). The Engagements tab gets Run/Stop
    buttons and a live state panel.

The loop is fully functional with **no LLM** (pure methodology); a planner
model only reorders batches.

### Running an autonomous engagement

After an engagement is authorized (see above), open its inspector and click
**Run autonomous test**. The loop seeds the verified host + base URL, then
recon/mapping populate assets and fingerprints, which unlock the vuln and
exploitation catalog items. Watch assets, technologies, coverage and
findings update live; click **Stop** at any time.

Next phases (specced, not yet built): the validator agent + safe-PoC
confirmation, kill-chain analysis, the full live operator view (agent
reasoning console, kill-chain graph, approval checkpoints), and the
client report generator.

### Authorization workflow

1. Open the **Engagements** tab, enter the target URL, tick the
   "I am authorized" attestation, create.
2. The engagement shows two proof options. Do **one**:
   - add a DNS TXT record `allhack-verify=<token>` on the target host, or
   - serve `https://<host>/.well-known/allhack-<token>.txt` containing the token.
3. Click **Verify ownership**. On success the engagement becomes
   `authorized`.
4. Go to **Scans**, pick the engagement, and launch tools. Anything
   targeting a host outside the engagement scope is blocked and audited.

## Requirements

- Docker with the Compose plugin (Docker Desktop or OrbStack on macOS, or
  docker-ce with `docker-compose-plugin` on Ubuntu/Debian).
- An OpenRouter API key: <https://openrouter.ai/keys>. Free models work.

Supported hosts: Ubuntu, Debian, macOS (Intel or Apple Silicon). Images are
built multi-arch (`linux/amd64` and `linux/arm64`).

## Install

```
cd v2
./install.sh
```

The script checks your Docker install, copies `.env.example` to `.env`,
creates `./data/`, and builds the two images (backend with all pentest
binaries bundled, frontend served by nginx).

Then edit `.env` and set `OPENROUTER_API_KEY`.

## Start

```
./start.sh           # detached
./start.sh --logs    # detached + tail logs
./start.sh stop      # stop and remove containers
./start.sh restart
```

Services after `./start.sh`:

| Container         | Port (host)          | Role                                       |
| ----------------- | -------------------- | ------------------------------------------ |
| frontend          | 3000                 | Minimal SPA, nginx-served.                 |
| backend (API)     | 8000                 | FastAPI; only enqueues scans, never spawns.|
| backend (MITM)    | 8080                 | mitmdump + addon writing to Postgres.      |
| worker            | -                    | arq, pops scan jobs from Redis and runs them.|
| postgres          | - (internal only)    | Single source of truth.                    |
| redis             | - (internal only)    | arq queue + transient state.               |

## Configuration (`.env`)

| Variable               | Default                                      | Purpose                                     |
| ---------------------- | -------------------------------------------- | ------------------------------------------- |
| `POSTGRES_DB / USER / PASSWORD` | `allhack / allhack / allhack`       | Postgres bootstrap for the compose stack.   |
| `OPENROUTER_API_KEY`   | (empty)                                      | Required to use any LLM feature.            |
| `OPENROUTER_MODEL`     | `qwen/qwen3-coder:free`                      | Any OpenRouter model slug.                  |
| `OPENROUTER_FALLBACK_MODELS` | `meta-llama/llama-3.3-70b-instruct:free,openai/gpt-oss-120b:free,qwen/qwen3-next-80b-a3b-instruct:free` | Comma-separated chain tried on 429/5xx from the primary. |
| `PLANNER_BASE_URL / API_KEY / MODEL`   | (empty -> OpenRouter fallback) | OpenAI-compatible endpoint for the planner role. |
| `EXECUTOR_BASE_URL / API_KEY / MODEL`  | (empty -> OpenRouter fallback) | OpenAI-compatible endpoint for the executor role. |
| `VALIDATOR_BASE_URL / API_KEY / MODEL` | (empty -> OpenRouter fallback) | OpenAI-compatible endpoint for the validator role. |
| `OPENROUTER_APP_NAME`  | `allhack`                                    | Sent as `X-Title` header.                   |
| `CORS_ORIGINS`         | `http://localhost:3000,http://127.0.0.1:3000`| For direct-API access during dev.           |
| `WPSCAN_API_TOKEN`     | (empty)                                      | Optional, enables CVE lookups in wpscan.    |

### Per-role LLM router (Phase 1-D)

Each role is independent and configured via three vars: `{ROLE}_BASE_URL`,
`{ROLE}_API_KEY`, `{ROLE}_MODEL`. Leaving them blank makes the role fall
back to the OpenRouter client (so installs without per-role config still
work). Examples:

```
# Strong reasoner for planning (Z.ai GLM)
PLANNER_BASE_URL=https://api.z.ai/api/paas/v4
PLANNER_API_KEY=zai-...
PLANNER_MODEL=glm-5.1

# Cheap and fast for executing tool calls (Z.ai GLM)
EXECUTOR_BASE_URL=https://api.z.ai/api/paas/v4
EXECUTOR_API_KEY=zai-...
EXECUTOR_MODEL=glm-4.6

# Accurate validator (Moonshot Kimi)
VALIDATOR_BASE_URL=https://api.moonshot.cn/v1
VALIDATOR_API_KEY=sk-...
VALIDATOR_MODEL=kimi-k2.6
```

Verify a role is reachable with `POST /api/llm/ping?role=planner`.

## Using the MITM proxy (Phase 1)

The backend container runs `mitmdump` on port `8080`. To route your traffic
through it:

1. In your browser or OS network settings, set the HTTP and HTTPS proxy to
   `127.0.0.1:8080`.
2. Open <http://localhost:3000/proxy>.
3. Send any HTTPS request. The first request makes mitmproxy generate its
   CA certificate at `./data/mitm/mitmproxy-ca-cert.pem`. The proxy page
   will then show a download link.
4. Install the downloaded `.pem` in your browser / OS trust store so TLS
   interception works without warnings:
   - **Firefox**: Settings -> Privacy & Security -> View Certificates ->
     Authorities -> Import. Tick "Trust this CA to identify websites".
   - **Chrome/Edge (macOS)**: open Keychain Access, drag the `.pem` into
     the **login** keychain, double-click, expand **Trust**, set
     *Always Trust*.
   - **Chrome/Edge (Linux)**: `sudo cp allhack-mitmproxy-ca.pem
     /usr/local/share/ca-certificates/allhack-mitmproxy-ca.crt &&
     sudo update-ca-certificates`.

Only trust this CA on the machine you are testing from; never distribute it.

Once the cert is trusted, browse the target normally. Every request appears
in the Proxy page with headers, body, status, response size and latency.
You can filter by host / method / URL substring and inspect any flow.

## Running scans (Phase 2)

Go to <http://localhost:3000/scans>. Pick a tool, enter a target, optionally
add extra CLI flags, click **Run**. The job appears in the list, polls every
2 s, and the inspector shows parsed findings plus raw stdout/stderr.

Tool-specific notes:

| Tool      | Target form                       | Extra options example                         |
| --------- | --------------------------------- | --------------------------------------------- |
| nuclei    | `https://target.com`              | `-tags cve,exposure -rl 50`                   |
| sqlmap    | `https://target.com/p?id=1`       | `--level=3 --risk=3 --technique=BEUSTQ`       |
| ffuf      | `https://target.com/FUZZ` or just `https://target.com` (auto `/FUZZ`) | `-w /opt/wordlists/common.txt -mc 200,204` |
| dalfox    | `https://target.com/p?x=hi`       | `-p x --deep-domxss`                          |
| nmap      | `example.com` or URL (hostname extracted) | `-p 1-65535 --script vuln`          |
| subfinder | `example.com` or URL (hostname extracted) | `-all -recursive`                    |
| httpx     | `example.com` or URL              | `-status-code -title -tech-detect -ports 80,443,8080` |
| katana    | `https://target.com`              | `-d 4 -jc -kf all` (deeper, JS crawl, known files) |
| testssl   | `example.com[:port]` or URL       | `--full` for deep audit (slow)                |
| wpscan    | `https://wordpress-target.com`    | `--api-token <token>` for CVE correlation     |

FFUF uses `/opt/wordlists/common.txt` (~4.6k entries, dirb classic) by
default. Override with `FFUF_WORDLIST=/path/in/container` in `.env` and a
volume mount in `docker-compose.yml` if you want a larger list (SecLists,
etc.).

API (same endpoints the UI uses):

```
GET    /api/scans/tools                list wrappers + availability
POST   /api/scans                      {"tool":"nuclei","target":"...","options":[]}
GET    /api/scans                      paginated list
GET    /api/scans/{id}                 detail + findings + stdout/stderr tail
POST   /api/scans/{id}/cancel          SIGTERM the subprocess
DELETE /api/scans/{id}                 remove the record
```

## LLM copilot (Phase 3)

All copilot features call OpenRouter; they return 503 with a clear error
if `OPENROUTER_API_KEY` is not set.

- **Suggest attacks** — in the Proxy inspector, any selected flow has a
  "Suggest attacks" button. The model analyzes the captured request and
  returns JSON with: a short summary, the auth scheme it detected, a
  list of suspicious parameters, and a list of concrete scan proposals
  (tool / target / options / rationale). Each proposal has a "Run"
  button that submits a real scan via `POST /api/scans` and takes you to
  the freshly-created job.
- **Explain findings** — in the Scans inspector, "Explain findings"
  produces a markdown write-up per finding: description, exploitation
  path, remediation hints, next steps. The output is a plain pre block
  you can copy.
- **Report** — the /reports page lets you pick jobs to include (all by
  default), add a title and scope note, and generate a markdown pentest
  report compiling proxy hosts + jobs + findings. You can download the
  `.md` or copy it to the clipboard.

API:

```
POST   /api/llm/flows/{flow_id}/suggest   - returns { parsed, raw, parse_error }
POST   /api/llm/jobs/{job_id}/explain     - returns { markdown }
POST   /api/llm/report                    - { title?, scope?, job_ids? }
```

Notes:
- The model default is `qwen/qwen3-coder:free` (see `.env.example`). It
  handles the JSON-only output constraint reliably.
- When the upstream provider rate-limits (429) or 5xx-fails, the client
  automatically retries with the next model in `OPENROUTER_FALLBACK_MODELS`.
  The Home page and the `/api/llm/ping` endpoint show which model actually
  answered (and whether a fallback kicked in).
- OpenRouter rotates which `:free` variants are offered; list the current
  ones with
  `curl -s https://openrouter.ai/api/v1/models | jq -r '.data[] | select(.id | endswith(":free")) | .id'`
  and update `OPENROUTER_MODEL` / `OPENROUTER_FALLBACK_MODELS` if needed.
- Requests are capped: request/response body previews, finding lists and
  header lists are truncated before being sent to the model to fit in
  the free-tier context window.

## Bundled tools (inside the backend image)

Recon: `nmap`, `naabu` (ports), `subfinder` (subdomains), `dnsx` (DNS),
`httpx` (probe), `katana` (crawler), `gau` (historical URLs).
Fingerprint: `whatweb`, `httpx`, `wafw00f` (WAF detection).
Content discovery: `ffuf`.
Vuln / CMS / server: `nuclei`, `nikto`, `wpscan`.
Injection: `sqlmap` (SQLi), `commix` (command injection).
XSS: `dalfox`.
TLS: `testssl.sh`.
Internal: `mitmproxy` (capture, used by the backend).

17 tools total; `GET /api/scans/tools` reports each one's `category` and
whether its binary is present in the running container.

Deferred to later phases (need agent-supplied context): `trufflehog` /
`gitleaks` (secrets - after a `.git`/source is found), `jwt_tool`
(needs an extracted token), `SSTImap` (SSTI), `interactsh` (out-of-band
SSRF/XXE confirmation, wired into the validation layer).

You do not need to install any of these on your host.

## Layout

```
v2/
  backend/
    app/
      config.py        runtime config from .env
      llm/client.py    OpenRouter client (chat + stream)
      main.py          FastAPI entrypoint
      proxy/           mitmproxy addon + flow storage
      scans/
        models.py      Finding / Job dataclasses
        storage.py     JobRepository (shared SQLite)
        runner.py      async subprocess runner
        wrappers/      nuclei / sqlmap / ffuf / dalfox / nmap
      llm/
        client.py      OpenRouter chat + stream
        prompts.py     prompt templates (suggest / explain / report)
        analyzer.py    Analyzer (flow -> JSON, findings -> md, report -> md)
      api/             FastAPI routers (proxy, scans, llm)
    Dockerfile         multi-arch, bundles all binaries
    requirements.txt
  frontend/
    src/
      App.jsx
      pages/Home.jsx
      styles.css
    Dockerfile         build with node, serve with nginx
    nginx.conf         proxies /api and /ws to the backend service
  docker-compose.yml
  install.sh
  start.sh
  .env.example
```

## Legal

Use only on systems you own or have written authorization to test.
