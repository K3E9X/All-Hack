# Project Gap Analysis

This document captures the primary gaps and outstanding work needed to stabilize and complete the recent feature expansion.

## Runtime dependencies
- **Missing Playwright installation.** The new browser-based crawler imports Playwright but silently skips when the module is unavailable, and the backend requirements file does not install it. Add the dependency and document its setup so dynamic route discovery actually runs.【F:backend/app/scanners/reconnaissance/browser_crawler.py†L15-L48】【F:backend/requirements.txt†L1-L27】

## Feature completeness
- **External tool toggles are unused.** The scan request exposes `enable_sqlmap` and `enable_nuclei`, yet the orchestrator never checks these flags or launches the corresponding tooling. Implement conditional execution for these controls or remove the dead configuration to avoid misleading users.【F:backend/app/models/scan.py†L55-L64】【787d82†L1-L3】【5b0a5e†L1-L3】

## Configuration hygiene
- **Hard-coded tool paths.** The default configuration still references a specific developer home directory for tooling and wordlists. Replace these with relative paths or environment-driven settings so the project works on other machines out of the box.【F:backend/app/config.py†L27-L40】
- **Orphaned backup sources.** Legacy snapshots such as `scanner_orchestrator.py.backup` and `scanner_orchestrator_old.py` remain in the backend package, which risks confusion when importing modules. Remove or archive them outside the package.【11cb2d†L1-L9】

## Quality assurance
- **No automated tests.** Neither the backend nor the frontend includes unit or integration tests, making it hard to verify the expanded feature set. Introduce baseline tests (e.g., FastAPI route smoke tests and React component rendering) to prevent regressions.【0eea49†L1-L2】【48a951†L1-L2】

## Frontend build
- **Tailwind package blockage.** The frontend pins `@tailwindcss/postcss` and `tailwindcss` to `4.1.16`, which is an unpublished version that triggers 403 errors during `npm install`. Update these dependencies to stable, available releases so the UI can be built and tested locally.【F:frontend/package.json†L12-L24】

Addressing these items will bring the project closer to a production-ready local pentest assistant and ensure the newly added features behave as intended.
