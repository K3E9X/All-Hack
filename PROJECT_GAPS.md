# Project Gaps & Known Limitations

This document catalogues missing dependencies, unimplemented features, configuration issues, and other gaps identified during code review.

## Status: 🟡 Active Development

Last updated: 2025-01-02

---

## 1. Missing Dependencies

### 1.1 Playwright (Browser Crawler) - ⚠️ MEDIUM PRIORITY

**Status:** Optional dependency not installed by default

**Impact:**
- `browser_crawling` feature toggle exists but Playwright is not in `requirements.txt`
- When `browser_crawling=True`, the scanner gracefully skips browser-based discovery
- Dynamic SPA routes (React/Vue/Angular apps) won't be discovered without it

**Current Behavior:**
```python
# In browser_crawler.py
if not async_playwright:
    logger.warning("Playwright is not installed; skipping browser-based crawling")
    return []
```

**Resolution Options:**
1. **Add as optional dependency** (Recommended):
   ```bash
   pip install playwright
   playwright install chromium
   ```
2. **Document as optional** in README
3. **Disable by default** in frontend (`browser_crawling=false`)

**Action Needed:** Add to requirements.txt as optional dependency

---

## 2. Unimplemented Feature Flags

### 2.1 enable_sqlmap - ❌ NOT IMPLEMENTED

**Status:** Flag exists in `ScanRequest` model but is never used

**Current State:**
- ✅ Flag defined in `models/scan.py`
- ❌ No SQLMap integration in orchestrator
- ❌ No error handling if flag is enabled

**Resolution:** Remove flag or add TODO comment

### 2.2 enable_nuclei - ❌ NOT IMPLEMENTED

**Status:** Flag exists in `ScanRequest` model but is never used

**Current State:**
- ✅ Flag defined in `models/scan.py`
- ❌ No Nuclei integration in orchestrator
- ❌ No error handling if flag is enabled

**Resolution:** Remove flag or add TODO comment

---

## 3. Configuration Issues

### 3.1 Hard-coded Tool Paths - 🟡 MEDIUM PRIORITY

**File:** `backend/app/config.py`

**Issue:**
```python
TOOLS_DIR: str = "/home/user/devasc-study-team/backend/app/tools"
WORDLISTS_DIR: str = "/home/user/devasc-study-team/backend/wordlists"
```

**Impact:** Not portable across different installations

**Resolution:** Use relative paths or environment variables

### 3.2 Orphaned Backup Files - 🟢 LOW PRIORITY

**Files to remove:**
- `backend/app/scanner_orchestrator_old.py`
- `backend/app/scanner_orchestrator.py.backup`

**Impact:** Clutters codebase, causes confusion

**Resolution:** Delete backup files

---

## 4. Testing Gaps

### 4.1 No Automated Tests - 🔴 HIGH PRIORITY (FUTURE)

**Status:** Zero test coverage on backend and frontend

**Missing:**
- Unit tests for scanners (OWASP, access control, recon)
- Integration tests for orchestrator
- Frontend component tests
- E2E tests

**Impact:** Difficult to detect regressions, refactoring is risky

**Resolution:** Add pytest tests for backend, Vitest for frontend (future work)

---

## 5. Frontend Issues

### 5.1 Tailwind CSS 4.x Compatibility - ✅ RESOLVED

**Status:** FIXED in commit `8786f3f`

**Previous Issue:**
- Frontend used Tailwind v4 with `@apply` directives
- PostCSS plugin configuration was incorrect
- Build failed on macOS with PostCSS errors

**Resolution Applied:**
- Converted all CSS to pure CSS (removed `@apply`)
- Added `@tailwindcss/postcss` package
- Updated `postcss.config.js` to use new plugin
- Uses `@theme` directive for custom colors

---

## 6. Documentation Gaps

### 6.1 Missing API Documentation - 🟡 MEDIUM PRIORITY

**Status:** FastAPI auto-generates docs at `/docs`, but custom documentation is minimal

**Missing:**
- Architecture diagrams
- Scanner module documentation
- Deployment guide
- Troubleshooting guide

**Resolution:** Add comprehensive docs (future work)

---

## Action Plan - Immediate Fixes

### Priority 1 (Critical - Now):
- [x] Fix Tailwind CSS 4.x issues (DONE)
- [ ] Add Playwright to requirements.txt as optional
- [ ] Remove or document unused flags (enable_sqlmap, enable_nuclei)
- [ ] Clean up backup files

### Priority 2 (High - This Week):
- [ ] Fix hard-coded paths in config.py
- [ ] Add basic unit tests for core scanners
- [ ] Document optional dependencies in README

### Priority 3 (Medium - Future):
- [ ] Implement SQLMap/Nuclei integration or remove flags
- [ ] Add comprehensive test suite
- [ ] Add architecture documentation

---

## Notes

- This document should be updated as gaps are resolved
- New gaps should be added as they're discovered
- Each gap should have a clear resolution path
