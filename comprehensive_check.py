#!/usr/bin/env python3
"""
Comprehensive System Check - Tests everything except runtime imports
Verifies: syntax, file structure, configurations, code logic
"""
import os
import ast
import json
from pathlib import Path
from typing import List, Dict, Tuple

print("=" * 80)
print("🔍 COMPREHENSIVE SYSTEM CHECK - ALL-HACK v2.0.0")
print("=" * 80)
print()

ROOT = Path("/home/user/All-Hack")
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"

errors = []
warnings = []
checks_passed = 0

def check(description: str, passed: bool, error_msg: str = ""):
    """Record check result"""
    global checks_passed
    if passed:
        print(f"✅ {description}")
        checks_passed += 1
        return True
    else:
        if error_msg:
            errors.append(f"{description}: {error_msg}")
            print(f"❌ {description}")
            print(f"   Error: {error_msg}")
        else:
            warnings.append(description)
            print(f"⚠️  {description}")
        return False

print("📁 Checking Project Structure...")
print("-" * 80)

# Check critical directories exist
check("Backend directory exists", BACKEND.exists())
check("Frontend directory exists", FRONTEND.exists())
check("Backend app directory", (BACKEND / "app").exists())
check("Frontend src directory", (FRONTEND / "src").exists())

print()
print("📦 Checking __init__.py files...")
print("-" * 80)

# Find all directories that should have __init__.py
python_dirs = []
for root, dirs, files in os.walk(BACKEND / "app"):
    if any(f.endswith('.py') for f in files if f != '__init__.py'):
        python_dirs.append(Path(root))

missing_init = []
for dir_path in python_dirs:
    init_file = dir_path / "__init__.py"
    if not init_file.exists():
        missing_init.append(str(dir_path.relative_to(BACKEND)))

check(
    f"All Python packages have __init__.py ({len(python_dirs)} directories)",
    len(missing_init) == 0,
    f"Missing in: {', '.join(missing_init)}" if missing_init else ""
)

print()
print("🐍 Checking Python Syntax...")
print("-" * 80)

# Check syntax of all Python files
python_files = list(BACKEND.rglob("*.py"))
syntax_errors = []

for py_file in python_files:
    try:
        with open(py_file, 'r', encoding='utf-8') as f:
            ast.parse(f.read(), filename=str(py_file))
    except SyntaxError as e:
        syntax_errors.append(f"{py_file.relative_to(ROOT)}: {e}")

check(
    f"All Python files have valid syntax ({len(python_files)} files)",
    len(syntax_errors) == 0,
    f"\n" + "\n".join(syntax_errors) if syntax_errors else ""
)

print()
print("📋 Checking Models Enums...")
print("-" * 80)

# Check ScanMode and ScanDepth enums
models_scan = BACKEND / "app" / "models" / "scan.py"
if models_scan.exists():
    with open(models_scan, 'r') as f:
        content = f.read()
        has_black_box = 'BLACK_BOX = "black_box"' in content
        has_grey_box = 'GREY_BOX = "grey_box"' in content
        has_quick = 'QUICK = "quick"' in content
        has_balanced = 'BALANCED = "balanced"' in content
        has_deep = 'DEEP = "deep"' in content

        check("ScanMode.BLACK_BOX defined", has_black_box)
        check("ScanMode.GREY_BOX defined", has_grey_box)
        check("ScanDepth.QUICK defined", has_quick)
        check("ScanDepth.BALANCED defined", has_balanced)
        check("ScanDepth.DEEP defined", has_deep)

print()
print("🎯 Checking Scanner Files...")
print("-" * 80)

# Check all scanner files exist
scanner_files = [
    ("OWASP", [
        "sql_injection.py", "xss_scanner.py", "command_injection.py",
        "ssrf_scanner.py", "csrf_scanner.py", "path_traversal_scanner.py",
        "xxe_scanner.py"
    ]),
    ("API Security", [
        "jwt_scanner.py", "graphql_scanner.py", "nosql_injection.py",
        "file_upload_scanner.py", "oauth_scanner.py", "saml_scanner.py"
    ]),
    ("Access Control", [
        "idor_scanner.py", "privilege_escalation.py"
    ]),
]

for category, files in scanner_files:
    print(f"  {category}:")
    if category == "OWASP":
        base_path = BACKEND / "app" / "scanners" / "owasp"
    elif category == "API Security":
        base_path = BACKEND / "app" / "scanners" / "api_security"
    else:
        base_path = BACKEND / "app" / "scanners" / "access_control"

    for file in files:
        file_path = base_path / file
        check(f"    {file}", file_path.exists(), f"File not found: {file_path}")

print()
print("🤖 Checking AI Agent Files...")
print("-" * 80)

ai_files = [
    "enhanced_autonomous_agent.py",
    "memory_system.py",
    "payload_generator.py",
    "exploitation_chains.py",
    "report_generator.py",
]

for file in ai_files:
    file_path = BACKEND / "app" / "ai_agent" / file
    check(f"  {file}", file_path.exists())

print()
print("⚙️  Checking Configuration Files...")
print("-" * 80)

# Check configuration files
check("Backend requirements.txt", (BACKEND / "requirements.txt").exists())
check("Backend .env.example", (BACKEND / ".env.example").exists())
check("Frontend package.json", (FRONTEND / "package.json").exists())
check("Frontend .env.example", (FRONTEND / ".env.example").exists())

# Check config.py
config_file = BACKEND / "app" / "config.py"
check("Backend config.py exists", config_file.exists())

if config_file.exists():
    with open(config_file, 'r') as f:
        content = f.read()
        check("  Config has API_PORT", "API_PORT" in content)
        check("  Config has ALLOWED_ORIGINS", "ALLOWED_ORIGINS" in content or "cors_origins" in content)

print()
print("🌐 Checking API Endpoints in main.py...")
print("-" * 80)

main_file = BACKEND / "app" / "main.py"
if main_file.exists():
    with open(main_file, 'r') as f:
        content = f.read()

        # Count endpoints
        endpoint_count = content.count("@app.get") + content.count("@app.post") + \
                        content.count("@app.delete") + content.count("@app.put") + \
                        content.count("@app.patch")

        websocket_count = content.count("@app.websocket")

        check(f"  REST API endpoints defined: {endpoint_count}", endpoint_count > 0)
        check(f"  WebSocket endpoints defined: {websocket_count}", websocket_count > 0)

        # Check critical imports
        check("  Imports AIEnhancedScanOrchestrator",
              "AIEnhancedScanOrchestrator" in content)
        check("  Creates orchestrator instance",
              "orchestrator = AIEnhancedScanOrchestrator()" in content or
              "orchestrator = " in content)

print()
print("🔗 Checking Orchestrator Integration...")
print("-" * 80)

ai_orch_file = BACKEND / "app" / "ai_enhanced_orchestrator.py"
if ai_orch_file.exists():
    with open(ai_orch_file, 'r') as f:
        content = f.read()
        check("  Extends ScanOrchestrator",
              "class AIEnhancedScanOrchestrator(ScanOrchestrator)" in content)
        check("  Imports EnhancedAutonomousPentestAgent",
              "EnhancedAutonomousPentestAgent" in content)
        check("  Initializes AI agent",
              "self.ai_agent" in content)

base_orch_file = BACKEND / "app" / "scanner_orchestrator.py"
if base_orch_file.exists():
    with open(base_orch_file, 'r') as f:
        content = f.read()
        check("  Handles BLACK_BOX mode",
              "ScanMode.BLACK_BOX" in content)
        check("  Handles GREY_BOX mode",
              "ScanMode.GREY_BOX" in content and "auth_token" in content)
        check("  Has scan depth logic",
              "ScanDepth.QUICK" in content or "quick" in content.lower())

print()
print("🧠 Checking Intelligence Layer...")
print("-" * 80)

intel_init = BACKEND / "app" / "intelligence" / "__init__.py"
if intel_init.exists():
    with open(intel_init, 'r') as f:
        content = f.read()
        check("  Exports ScanBrain", '"ScanBrain"' in content or "'ScanBrain'" in content)
        check("  Exports LLMVulnerabilityAnalyst",
              "LLMVulnerabilityAnalyst" in content)
        check("  Exports ChatAgent", "ChatAgent" in content)

print()
print("⚛️  Checking Frontend Components...")
print("-" * 80)

frontend_components = [
    "App.jsx",
    "components/Scanner.jsx",
    "components/Results.jsx",
    "components/Dashboard.jsx",
    "components/ChatInterface.jsx",
]

for component in frontend_components:
    comp_path = FRONTEND / "src" / component
    check(f"  {component}", comp_path.exists())

# Check package.json
package_json = FRONTEND / "package.json"
if package_json.exists():
    with open(package_json, 'r') as f:
        pkg = json.load(f)
        deps = pkg.get("dependencies", {})
        check("  Has react dependency", "react" in deps)
        check("  Has axios dependency", "axios" in deps)
        check("  Has react-router-dom", "react-router-dom" in deps)

print()
print("📝 Checking Documentation...")
print("-" * 80)

docs = [
    ("README.md", ROOT),
    ("AI_TESTING_GUIDE.md", ROOT),
    ("PHASE_2_3_VERIFICATION.md", ROOT),
    ("SYSTEM_VERIFICATION_REPORT.md", ROOT),
]

for doc, base in docs:
    check(f"  {doc}", (base / doc).exists())

print()
print("🔍 Checking for Common Issues...")
print("-" * 80)

# Check for circular imports (basic check)
def check_circular_imports():
    """Simple check for obvious circular imports"""
    issues = []

    # Check if any __init__.py imports from same package before defining modules
    for init_file in BACKEND.rglob("__init__.py"):
        with open(init_file, 'r') as f:
            content = f.read()
            lines = content.split('\n')

            # Look for 'from . import' or 'from .module import' patterns
            for i, line in enumerate(lines):
                if line.strip().startswith('from .') and 'import' in line:
                    # This could be problematic if done before __all__
                    if i < len(lines) - 1:
                        rest = '\n'.join(lines[i+1:])
                        if '__all__' not in rest:
                            issues.append(f"{init_file.name}: potential circular import on line {i+1}")

    return issues

circular_issues = check_circular_imports()
check("  No obvious circular imports",
      len(circular_issues) == 0,
      "\n" + "\n".join(circular_issues) if circular_issues else "")

print()
print("=" * 80)
print("📊 CHECK RESULTS SUMMARY")
print("=" * 80)
print()
print(f"✅ Checks Passed: {checks_passed}")
print(f"❌ Errors: {len(errors)}")
print(f"⚠️  Warnings: {len(warnings)}")
print()

if errors:
    print("❌ CRITICAL ERRORS FOUND:")
    print("-" * 80)
    for i, error in enumerate(errors, 1):
        print(f"{i}. {error}")
    print()

if warnings:
    print("⚠️  WARNINGS:")
    print("-" * 80)
    for i, warning in enumerate(warnings, 1):
        print(f"{i}. {warning}")
    print()

if not errors:
    print("✅ ALL CRITICAL CHECKS PASSED!")
    print("🚀 System is ready for testing")
else:
    print(f"❌ {len(errors)} CRITICAL ERROR(S) - Please review and fix")

print()
print("=" * 80)
