# allhack v2

A proxy-first web pentesting platform. You browse the target through a MITM
proxy, the tool captures the real attack surface, and mature CLI tools
(`nuclei`, `sqlmap`, `ffuf`, `dalfox`, `nmap`) run against it on demand. An
LLM (via OpenRouter, free tier by default) analyzes captured traffic,
suggests attacks, and drafts the client report.

No custom scanners. No reinventing the wheel. No magic "AI that finds
everything for you". Just a solid bench for manual + assisted pentesting.

## Status

Phase 0: repo scaffolding, Docker stack, OpenRouter client wired up.

Phase 1: MITM proxy capture with mitmproxy, flows persisted to SQLite,
list + inspector UI with filters (host, method, URL).

Phase 2: CLI tool wrappers for `nuclei`, `sqlmap`, `ffuf`, `dalfox`, `nmap`.
Each job is launched async, stdout/stderr are stored in SQLite, output is
parsed into normalized `Finding` objects.

Phase 3 (this commit): LLM copilot powered by OpenRouter.
  - Per-flow attack suggestions: the model looks at a captured request
    and proposes concrete scans to run (tool + target + options) as
    structured JSON; one click launches any suggestion as a real job.
  - Per-job explanation: plain-language write-up of scan findings with
    exploitation paths and remediation hints.
  - Markdown pentest report: compiles selected jobs and captured hosts
    into a client-ready document, downloadable as `.md`.

Later: PDF export, HTML rendering of the report preview, template customization.

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

| Service      | URL                          | Notes                                  |
| ------------ | ---------------------------- | -------------------------------------- |
| UI           | http://localhost:3000        | Minimal single-page app.               |
| API          | http://localhost:8000        | FastAPI.                               |
| API docs     | http://localhost:8000/docs   | Auto-generated OpenAPI.                |
| MITM proxy   | http://localhost:8080        | Configure your browser to use this.    |

## Configuration (`.env`)

| Variable               | Default                                      | Purpose                                     |
| ---------------------- | -------------------------------------------- | ------------------------------------------- |
| `OPENROUTER_API_KEY`   | (empty)                                      | Required to use any LLM feature.            |
| `OPENROUTER_MODEL`     | `qwen/qwen3-coder:free`                      | Any OpenRouter model slug.                  |
| `OPENROUTER_FALLBACK_MODELS` | `meta-llama/llama-3.3-70b-instruct:free,openai/gpt-oss-120b:free,qwen/qwen3-next-80b-a3b-instruct:free` | Comma-separated chain tried on 429/5xx from the primary. |
| `OPENROUTER_APP_NAME`  | `allhack`                                    | Sent as `X-Title` header.                   |
| `CORS_ORIGINS`         | `http://localhost:3000,http://127.0.0.1:3000`| For direct-API access during dev.           |

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

- `nuclei` (ProjectDiscovery)
- `subfinder` (ProjectDiscovery) - passive subdomain enumeration
- `httpx` (ProjectDiscovery) - HTTP probe + tech fingerprint
- `katana` (ProjectDiscovery) - crawler / spider
- `ffuf` - directory / parameter fuzzing
- `dalfox` - XSS scanner
- `nmap` - ports + service fingerprint
- `sqlmap` - SQL injection
- `testssl.sh` - TLS / SSL audit
- `wpscan` - WordPress scanner (set `WPSCAN_API_TOKEN` in `.env` for CVE correlation)
- `mitmproxy` (Python library, used by the backend)

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
