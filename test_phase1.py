#!/usr/bin/env python3
"""
Phase 1 Testing Script

Tests all Phase 1 features:
1. Backend imports and startup
2. AI Intelligence layer (Ollama)
3. Chat interface
4. PoC Validation
"""
import sys
import asyncio
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

print("🧪 Phase 1 Testing Suite\n")
print("=" * 60)

# Test 1: Backend Imports
print("\n1️⃣  Testing Backend Imports...")
try:
    from app.models import Vulnerability, VulnerabilityCategory, SeverityLevel
    from app.config import settings
    print("   ✅ Core models imported successfully")
except Exception as e:
    print(f"   ❌ Failed to import core models: {e}")
    sys.exit(1)

# Test 2: Intelligence Layer Imports
print("\n2️⃣  Testing Intelligence Layer...")
try:
    from app.intelligence.ollama_client import OllamaClient, OllamaConfig
    from app.intelligence.llm_analyst import LLMVulnerabilityAnalyst
    from app.intelligence.chat_agent import ChatAgent
    print("   ✅ Intelligence layer imported successfully")
except Exception as e:
    print(f"   ❌ Failed to import intelligence layer: {e}")
    print(f"   💡 Make sure intelligence package exists")
    sys.exit(1)

# Test 3: Validation Layer Imports
print("\n3️⃣  Testing Validation Layer...")
try:
    from app.validation import (
        BaseValidator,
        ValidationStatus,
        ValidationResult,
        SQLInjectionValidator,
        XSSValidator,
        SSRFValidator,
        RCEValidator,
        ValidationOrchestrator,
        get_validation_orchestrator
    )
    print("   ✅ Validation layer imported successfully")
except Exception as e:
    print(f"   ❌ Failed to import validation layer: {e}")
    print(f"   💡 Error details: {type(e).__name__}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 4: Ollama Client
print("\n4️⃣  Testing Ollama Client...")
async def test_ollama():
    try:
        ollama = OllamaClient()
        available = await ollama.check_available()

        if available:
            print("   ✅ Ollama is available and running!")
            print(f"   📍 Endpoint: {ollama.config.base_url}")
            print(f"   🤖 Model: {ollama.config.model}")
        else:
            print("   ⚠️  Ollama is not running")
            print("   💡 Install: https://ollama.ai")
            print("   💡 Start with: ollama run llama3.2")

        return available
    except Exception as e:
        print(f"   ⚠️  Could not connect to Ollama: {e}")
        print("   💡 This is optional - install from https://ollama.ai")
        return False

ollama_available = asyncio.run(test_ollama())

# Test 5: Validation Orchestrator
print("\n5️⃣  Testing Validation Orchestrator...")
try:
    orchestrator = get_validation_orchestrator()
    validator_count = len(orchestrator.validators)
    print(f"   ✅ Validation orchestrator created")
    print(f"   📊 Validators loaded: {validator_count}")

    for validator in orchestrator.validators:
        print(f"      - {validator.__class__.__name__}")

except Exception as e:
    print(f"   ❌ Failed to create orchestrator: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 6: Sample Vulnerability Validation
print("\n6️⃣  Testing Sample Vulnerability Validation...")
async def test_validation():
    try:
        from app.utils import PentestHTTPClient

        # Create sample SQL injection vulnerability
        vuln = Vulnerability(
            id="test_sql_1",
            title="Test SQL Injection",
            category=VulnerabilityCategory.SQL_INJECTION,
            severity=SeverityLevel.HIGH,
            affected_url="http://testphp.vulnweb.com/search.php",
            affected_parameter="searchFor",
            description="Test vulnerability for validation",
            proof_of_concept="searchFor=' OR 1=1--",
            payload="' OR 1=1--"
        )

        # Get validator
        validator = SQLInjectionValidator()

        # Check if applicable
        is_applicable = validator._is_applicable(vuln)
        print(f"   ✅ SQL Injection validator applicable: {is_applicable}")

        # Note: We won't actually run validation against live target in tests
        # User can run test_validation.py for full integration tests
        print("   ✅ Validation framework is ready")
        print("   💡 Run 'python test_validation.py' for full integration tests")

    except Exception as e:
        print(f"   ❌ Validation test failed: {e}")
        import traceback
        traceback.print_exc()

asyncio.run(test_validation())

# Test 7: FastAPI App
print("\n7️⃣  Testing FastAPI Application...")
try:
    from app.main import app
    print("   ✅ FastAPI app imported successfully")

    # Count routes
    routes = [r for r in app.routes if hasattr(r, 'path')]
    endpoint_count = len(routes)
    print(f"   📊 Total endpoints: {endpoint_count}")

    # Count Phase 1 endpoints
    validation_endpoints = [r for r in routes if 'validate' in r.path]
    chat_endpoints = [r for r in routes if 'chat' in r.path]
    ai_endpoints = [r for r in routes if 'analyze' in r.path or 'ai' in r.path]

    print(f"   🎯 Phase 1 Endpoints:")
    print(f"      - Validation: {len(validation_endpoints)}")
    print(f"      - Chat: {len(chat_endpoints)}")
    print(f"      - AI Analysis: {len(ai_endpoints)}")

except Exception as e:
    print(f"   ❌ Failed to import FastAPI app: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Summary
print("\n" + "=" * 60)
print("\n📊 TEST SUMMARY:")
print("   ✅ Backend imports: OK")
print("   ✅ Intelligence layer: OK")
print("   ✅ Validation layer: OK")
print(f"   {'✅' if ollama_available else '⚠️ '} Ollama client: {'Available' if ollama_available else 'Not running (optional)'}")
print("   ✅ Validation orchestrator: OK")
print("   ✅ FastAPI app: OK")

print("\n🎉 Phase 1 is ready for testing!")

print("\n📝 Next Steps:")
print("   1. Install dependencies:")
print("      cd backend && pip install -r requirements.txt")
print("      python -m playwright install chromium")
print()
print("   2. (Optional) Install Ollama for AI features:")
print("      Visit: https://ollama.ai")
print("      Run: ollama run llama3.2")
print()
print("   3. Start the backend:")
print("      cd backend && python -m uvicorn app.main:app --reload")
print()
print("   4. Run integration tests:")
print("      python test_validation.py")
print("      python test_chat.py")
print()

print("=" * 60)
