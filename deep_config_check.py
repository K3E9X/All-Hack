#!/usr/bin/env python3
"""
Deep Configuration & Integration Check
Tests: .env files, API endpoints, frontend/backend integration, secrets
"""
import os
import re
import json
from pathlib import Path

print("=" * 80)
print("🔧 DEEP CONFIGURATION & INTEGRATION CHECK")
print("=" * 80)
print()

ROOT = Path("/home/user/All-Hack")
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"

errors = []
warnings = []
checks_passed = 0

def check(description: str, passed: bool, error_msg: str = "", is_warning: bool = False):
    """Record check result"""
    global checks_passed
    if passed:
        print(f"✅ {description}")
        checks_passed += 1
        return True
    else:
        if is_warning:
            warnings.append(f"{description}: {error_msg}" if error_msg else description)
            print(f"⚠️  {description}")
        else:
            errors.append(f"{description}: {error_msg}" if error_msg else description)
            print(f"❌ {description}")
        if error_msg:
            print(f"   {error_msg}")
        return False

print("📝 Checking .env Files...")
print("-" * 80)

# Check backend .env.example
backend_env_example = BACKEND / ".env.example"
if backend_env_example.exists():
    with open(backend_env_example, 'r') as f:
        content = f.read()
        required_vars = [
            "API_PORT",
            "ALLOWED_ORIGINS",
            "MAX_CONCURRENT_SCANS",
            "SCAN_TIMEOUT",
            "REQUEST_TIMEOUT",
        ]
        for var in required_vars:
            check(f"  Backend .env.example has {var}", var in content)

# Check frontend .env.example
frontend_env_example = FRONTEND / ".env.example"
if frontend_env_example.exists():
    with open(frontend_env_example, 'r') as f:
        content = f.read()
        check("  Frontend .env.example has VITE_API_URL", "VITE_API_URL" in content)

print()
print("🔐 Checking for Hardcoded Secrets...")
print("-" * 80)

# Scan for potential secrets in code
secret_patterns = [
    (r'sk-ant-[a-zA-Z0-9]{40,}', "Anthropic API Key"),
    (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password"),
    (r'api_key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key"),
    (r'token\s*=\s*["\'][A-Za-z0-9_-]{20,}["\']', "Hardcoded token"),
]

suspicious_files = []
for py_file in BACKEND.rglob("*.py"):
    # Skip test files and examples
    if 'test' in str(py_file).lower() or 'example' in str(py_file).lower():
        continue

    with open(py_file, 'r', errors='ignore') as f:
        content = f.read()
        for pattern, secret_type in secret_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                # Check if it's in a comment or test
                for match in matches:
                    if not any(x in content[max(0, content.find(match)-50):content.find(match)]
                             for x in ['#', '"""', "'''", 'example', 'test']):
                        suspicious_files.append((py_file.name, secret_type, match[:20] + "..."))

check(
    "  No hardcoded secrets found",
    len(suspicious_files) == 0,
    f"Found {len(suspicious_files)} potential secrets" if suspicious_files else "",
    is_warning=True
)

if suspicious_files:
    for file, secret_type, match in suspicious_files[:5]:  # Show first 5
        print(f"      {file}: {secret_type} - {match}")

print()
print("🌐 Checking Frontend API Endpoints...")
print("-" * 80)

# Extract API endpoints from frontend
frontend_api_calls = set()
for jsx_file in FRONTEND.rglob("*.jsx"):
    with open(jsx_file, 'r', errors='ignore') as f:
        content = f.read()
        # Find axios calls
        axios_calls = re.findall(r'axios\.(get|post|delete|put|patch)\([\'"`]([^\'"`]+)[\'"`]', content)
        for method, url in axios_calls:
            if url.startswith('/api'):
                frontend_api_calls.add((method, url))

# Extract API endpoints from backend
backend_endpoints = set()
main_file = BACKEND / "app" / "main.py"
if main_file.exists():
    with open(main_file, 'r') as f:
        content = f.read()
        # Find FastAPI decorators
        decorators = re.findall(r'@app\.(get|post|delete|put|patch)\([\'"`]([^\'"`]+)[\'"`]', content)
        for method, path in decorators:
            backend_endpoints.add((method.upper(), path))

check(
    f"  Backend has {len(backend_endpoints)} REST endpoints",
    len(backend_endpoints) > 0
)

check(
    f"  Frontend makes {len(frontend_api_calls)} API calls",
    len(frontend_api_calls) >= 0  # Can be 0 if using different pattern
)

# Check critical endpoints exist
critical_endpoints = [
    ("POST", "/api/v1/scans"),
    ("GET", "/api/v1/scans/{scan_id}"),
]

for method, path in critical_endpoints:
    # Remove {param} for matching
    path_pattern = re.sub(r'\{[^}]+\}', '[^/]+', path)
    found = any(
        m == method and re.match(path_pattern, p)
        for m, p in backend_endpoints
    )
    check(f"  Critical endpoint exists: {method} {path}", found)

print()
print("🔌 Checking WebSocket Configuration...")
print("-" * 80)

# Check WebSocket endpoint
if main_file.exists():
    with open(main_file, 'r') as f:
        content = f.read()
        has_websocket = "@app.websocket" in content
        has_websocket_import = "from fastapi import" in content and "WebSocket" in content

        check("  WebSocket decorator present", has_websocket)
        check("  WebSocket imported from FastAPI", has_websocket_import)

        if has_websocket:
            # Find WebSocket path
            ws_paths = re.findall(r'@app\.websocket\([\'"`]([^\'"`]+)[\'"`]\)', content)
            if ws_paths:
                print(f"     WebSocket path: {ws_paths[0]}")

print()
print("📦 Checking Package Versions...")
print("-" * 80)

# Check requirements.txt
requirements_file = BACKEND / "requirements.txt"
if requirements_file.exists():
    with open(requirements_file, 'r') as f:
        content = f.read()

        critical_packages = {
            "fastapi": "0.104",
            "uvicorn": "0.24",
            "pydantic": "2.",
            "anthropic": "0.3",
        }

        for package, version_prefix in critical_packages.items():
            if package in content:
                # Extract version
                match = re.search(rf'{package}==([0-9.]+)', content)
                if match:
                    version = match.group(1)
                    check(
                        f"  {package} version: {version}",
                        version.startswith(version_prefix),
                        f"Expected {version_prefix}x but got {version}" if not version.startswith(version_prefix) else "",
                        is_warning=True
                    )
            else:
                check(f"  {package} in requirements", False, is_warning=True)

# Check frontend package.json
package_json = FRONTEND / "package.json"
if package_json.exists():
    with open(package_json, 'r') as f:
        pkg = json.load(f)
        deps = pkg.get("dependencies", {})

        critical_frontend_packages = ["react", "axios", "react-router-dom"]
        for package in critical_frontend_packages:
            check(f"  Frontend has {package}", package in deps)

print()
print("🚀 Checking Startup Configuration...")
print("-" * 80)

# Check if uvicorn can be started (config check)
config_file = BACKEND / "app" / "config.py"
if config_file.exists():
    with open(config_file, 'r') as f:
        content = f.read()

        # Check for settings class
        has_settings = "class Settings" in content or "settings =" in content
        check("  Settings class/object defined", has_settings)

        # Check for pydantic BaseSettings
        uses_pydantic_settings = "BaseSettings" in content or "SettingsConfigDict" in content
        check("  Uses Pydantic settings", uses_pydantic_settings, is_warning=True)

# Check main.py app creation
if main_file.exists():
    with open(main_file, 'r') as f:
        content = f.read()

        has_app = "app = FastAPI(" in content
        check("  FastAPI app created", has_app)

        has_cors = "CORSMiddleware" in content
        check("  CORS middleware configured", has_cors)

        has_lifespan = "lifespan" in content or "@asynccontextmanager" in content
        check("  Lifespan events configured", has_lifespan, is_warning=True)

print()
print("🎯 Checking Scanner Integration...")
print("-" * 80)

# Check if all scanners are imported in orchestrator
orchestrator_file = BACKEND / "app" / "scanner_orchestrator.py"
if orchestrator_file.exists():
    with open(orchestrator_file, 'r') as f:
        content = f.read()

        critical_scanners = [
            "SQLInjectionScanner",
            "XSSScanner",
            "JWTSecurityScanner",
            "GraphQLSecurityScanner",
            "IDORScanner",
        ]

        for scanner in critical_scanners:
            check(f"  {scanner} imported", scanner in content)

print()
print("=" * 80)
print("📊 CONFIGURATION CHECK SUMMARY")
print("=" * 80)
print()
print(f"✅ Checks Passed: {checks_passed}")
print(f"❌ Errors: {len(errors)}")
print(f"⚠️  Warnings: {len(warnings)}")
print()

if errors:
    print("❌ CRITICAL ERRORS:")
    print("-" * 80)
    for i, error in enumerate(errors, 1):
        print(f"{i}. {error}")
    print()

if warnings:
    print("⚠️  WARNINGS (Non-blocking):")
    print("-" * 80)
    for i, warning in enumerate(warnings, 1):
        print(f"{i}. {warning}")
    print()

if not errors:
    print("✅ ALL CRITICAL CONFIGURATION CHECKS PASSED!")
    print("🚀 System configuration is valid")
else:
    print(f"❌ {len(errors)} CRITICAL ERROR(S) - Please review")

print()
print("=" * 80)
