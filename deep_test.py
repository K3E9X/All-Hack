#!/usr/bin/env python3
"""
Deep System Test - Test ALL imports and configurations
Runs BEFORE user testing to catch ALL errors
"""
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

print("=" * 80)
print("🔍 DEEP SYSTEM TEST - ALL-HACK v2.0.0")
print("=" * 80)
print()

errors = []
warnings = []
successes = []

def test_import(module_name, description):
    """Test a single import"""
    try:
        __import__(module_name)
        successes.append(f"✅ {description}: {module_name}")
        print(f"✅ {description}")
        return True
    except ImportError as e:
        errors.append(f"❌ {description}: {module_name} - {str(e)}")
        print(f"❌ {description} - ERROR: {e}")
        return False
    except Exception as e:
        errors.append(f"⚠️  {description}: {module_name} - {str(e)}")
        print(f"⚠️  {description} - WARNING: {e}")
        return False

print("📦 Testing Core Dependencies...")
print("-" * 80)

# Test core dependencies
test_import("fastapi", "FastAPI")
test_import("uvicorn", "Uvicorn")
test_import("pydantic", "Pydantic")
test_import("httpx", "HTTPX")
test_import("aiohttp", "AioHTTP")
test_import("requests", "Requests")

print()
print("🧠 Testing Intelligence Layer...")
print("-" * 80)

# Test intelligence modules
test_import("app.intelligence", "Intelligence Package")
test_import("app.intelligence.scan_brain", "ScanBrain")
test_import("app.intelligence.llm_analyst", "LLM Analyst")
test_import("app.intelligence.ollama_client", "Ollama Client")
test_import("app.intelligence.chat_agent", "Chat Agent")

print()
print("🤖 Testing AI Agent Modules...")
print("-" * 80)

# Test AI agent modules
test_import("app.ai_agent", "AI Agent Package")
test_import("app.ai_agent.enhanced_autonomous_agent", "Enhanced Autonomous Agent")
test_import("app.ai_agent.memory_system", "Memory System")
test_import("app.ai_agent.payload_generator", "Payload Generator")
test_import("app.ai_agent.exploitation_chains", "Exploitation Chains")
test_import("app.ai_agent.report_generator", "Report Generator")

print()
print("📋 Testing Models...")
print("-" * 80)

# Test models
test_import("app.models", "Models Package")
test_import("app.models.scan", "Scan Models")

print()
print("🔧 Testing Utils...")
print("-" * 80)

# Test utils
test_import("app.utils", "Utils Package")
test_import("app.config", "Configuration")

print()
print("🎯 Testing Scanners...")
print("-" * 80)

# Test OWASP scanners
print("  OWASP Scanners:")
test_import("app.scanners.owasp.sql_injection", "  - SQL Injection")
test_import("app.scanners.owasp.xss_scanner", "  - XSS Scanner")
test_import("app.scanners.owasp.command_injection", "  - Command Injection")
test_import("app.scanners.owasp.ssrf_scanner", "  - SSRF Scanner")
test_import("app.scanners.owasp.csrf_scanner", "  - CSRF Scanner")
test_import("app.scanners.owasp.path_traversal_scanner", "  - Path Traversal")
test_import("app.scanners.owasp.xxe_scanner", "  - XXE Scanner")

print()
print("  API Security Scanners:")
test_import("app.scanners.api_security.jwt_scanner", "  - JWT Scanner")
test_import("app.scanners.api_security.graphql_scanner", "  - GraphQL Scanner")
test_import("app.scanners.api_security.nosql_injection", "  - NoSQL Injection")
test_import("app.scanners.api_security.file_upload_scanner", "  - File Upload")
test_import("app.scanners.api_security.oauth_scanner", "  - OAuth Scanner")
test_import("app.scanners.api_security.saml_scanner", "  - SAML Scanner")

print()
print("  Access Control Scanners:")
test_import("app.scanners.access_control.idor_scanner", "  - IDOR Scanner")
test_import("app.scanners.access_control.privilege_escalation", "  - Privilege Escalation")

print()
print("🌐 Testing Orchestrators...")
print("-" * 80)

# Test orchestrators
test_import("app.scanner_orchestrator", "Base Orchestrator")
test_import("app.ai_enhanced_orchestrator", "AI Enhanced Orchestrator")

print()
print("🚀 Testing Main Application...")
print("-" * 80)

# Test main app
test_import("app.main", "Main FastAPI App")

print()
print("=" * 80)
print("📊 TEST RESULTS SUMMARY")
print("=" * 80)
print()
print(f"✅ Successes: {len(successes)}")
print(f"❌ Errors: {len(errors)}")
print(f"⚠️  Warnings: {len(warnings)}")
print()

if errors:
    print("❌ ERRORS FOUND:")
    print("-" * 80)
    for error in errors:
        print(f"  {error}")
    print()

if warnings:
    print("⚠️  WARNINGS:")
    print("-" * 80)
    for warning in warnings:
        print(f"  {warning}")
    print()

if not errors:
    print("✅ ALL TESTS PASSED - System is READY!")
    sys.exit(0)
else:
    print(f"❌ {len(errors)} ERROR(S) FOUND - Please fix before testing!")
    sys.exit(1)
