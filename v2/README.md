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

Phase 1 (this commit): MITM proxy capture with mitmproxy, flows persisted
to SQLite, list + inspector UI with filters (host, method, URL).

Phase 2 (next): CLI tool wrappers (`nuclei`, `sqlmap`, `ffuf`, `dalfox`,
`nmap`) launched on demand against captured flows.

Later phases: LLM analysis/suggestions on captured traffic, PDF reports.

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
| `OPENROUTER_MODEL`     | `qwen/qwen-2.5-coder-32b-instruct:free`      | Any OpenRouter model slug.                  |
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

## Bundled tools (inside the backend image)

- `nuclei` (ProjectDiscovery)
- `ffuf`
- `dalfox`
- `nmap`
- `sqlmap`
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
      proxy/           (phase 1) mitmproxy hooks + session storage
      wrappers/        (phase 2) nuclei/sqlmap/ffuf/dalfox/nmap wrappers
      api/             (future) route modules
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
