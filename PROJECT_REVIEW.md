# Project Review (2025-11-02 Refresh)

## What changed since the last pass?
- Claude Code’s drop introduced the live phase stepper and richer orchestrator phases, so this refresh re-runs the sanity checks and re-validates the broader flow end to end.【F:backend/app/main.py†L27-L266】【F:frontend/src/components/Scanner.jsx†L1-L214】
- The orchestration layer now chains browser crawling, OSINT enrichment, adaptive exploitation planning, stability snapshots, and post-processing helpers, matching the scope we expect from a senior operator tooling.【F:backend/app/scanner_orchestrator.py†L61-L411】


## Environment sanity checks
- `python -m compileall backend/app` succeeds, so all FastAPI modules import cleanly and the backend should start without syntax errors.【2afdcc†L1-L47】
- `npm install` fails with 403 responses for Tailwind/PostCSS packages, leaving the React workspace without dependencies; the UI cannot be built until these pins are corrected or a registry mirror is used.【db53a3†L1-L6】

## Architecture recap
### Backend
The orchestrator coordinates reconnaissance, OWASP testing, access-control probes, misconfiguration checks, stability sampling, and report/playbook helpers while persisting intermediate state, which mirrors the cadence of a long-form manual pentest.【F:backend/app/scanner_orchestrator.py†L61-L200】【F:backend/app/persistence/scan_storage.py†L13-L200】

FastAPI exposes live progress data—including ordered timeline events, the current step, and a derived phase progression map—so clients can stream what the engine is doing in real time.【F:backend/app/main.py†L27-L266】

### Frontend
The scanner panel now collects advanced options (auth flows, Playwright crawling, schema harvesting, OSINT, stability metrics) and renders the new live feedback from the backend: phase stepper, current step callout, and chronologically sorted event log.【F:frontend/src/components/Scanner.jsx†L1-L421】

## Strengths observed
- **Adaptive workflow** – `ScanBrain` keeps track of attack surface intelligence and adjusts priorities for later phases, helping mimic an expert pentester’s reasoning.【F:backend/app/intelligence/scan_brain.py†L1-L200】
- **Persistence & reporting** – `ScanStorage` auto-saves to disk, restores scans after crashes, and can emit Markdown reports or comparisons between runs, providing durable artifacts for long campaigns.【F:backend/app/persistence/scan_storage.py†L13-L200】
- **Operator visibility** – The combination of backend status metadata and the enriched `Scanner` UI provides continual insight into what the tool is doing, answering the request to watch scans unfold live.【F:backend/app/main.py†L27-L266】【F:frontend/src/components/Scanner.jsx†L1-L421】

## Gaps & risks to address
1. **Browser crawler dependency missing** – The crawler defers to Playwright but the requirements list never installs it, so dynamic route discovery silently skips unless contributors add the package manually.【F:backend/app/scanners/reconnaissance/browser_crawler.py†L14-L45】【F:backend/requirements.txt†L1-L27】
2. **External tool toggles inert** – Request flags for `enable_nuclei` and `enable_sqlmap` are accepted by the API but never consumed, which can mislead operators about coverage.【F:backend/app/models/scan.py†L56-L64】
3. **Hard-coded tool paths** – `settings.TOOLS_DIR` and `WORDLISTS_DIR` point to a specific home directory, breaking portability for other machines. These should become relative paths or environment variables.【F:backend/app/config.py†L35-L37】
4. **Frontend dependency pins unavailable** – Tailwind 4.x artifacts are unpublished, causing `npm install` to fail. Align the UI with stable Tailwind/PostCSS releases so the interface can be built locally.【F:frontend/package.json†L12-L24】【db53a3†L1-L6】
5. **No automated regression checks** – There are still no tests covering the FastAPI routes or React components, so the expanded feature set lacks guardrails against regressions.【c5706b†L1-L2】【176c1a†L1-L2】

## Suggested next steps
1. Add Playwright (or a documented alternative) to the backend dependencies and provide setup guidance so browser crawling is reliably available.【F:backend/app/scanners/reconnaissance/browser_crawler.py†L14-L45】
2. Either wire the `enable_nuclei`/`enable_sqlmap` flags into the orchestrator pipeline or hide them until the integrations exist, avoiding false expectations.【F:backend/app/models/scan.py†L56-L64】
3. Replace hard-coded filesystem paths with config variables (env or relative paths) and document defaults that work out of the box on a clean clone.【F:backend/app/config.py†L35-L37】
4. Downgrade Tailwind/PostCSS to current stable versions (e.g., Tailwind 3.4) and re-run `npm install` to verify the frontend can bootstrap.【F:frontend/package.json†L12-L24】【db53a3†L1-L6】
5. Introduce smoke tests—FastAPI route tests plus a minimal React render test—to ensure the tool remains operational as features evolve.【c5706b†L1-L2】【176c1a†L1-L2】
