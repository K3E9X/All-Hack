#!/bin/bash
# Phase 1 Verification Script
# Checks that all Phase 1 files are present and correct

echo "🔍 Phase 1 File Verification"
echo "============================================================"
echo ""

MISSING=0
ERRORS=""

# Function to check file exists
check_file() {
    if [ -f "$1" ]; then
        echo "   ✅ $1"
    else
        echo "   ❌ $1 - MISSING"
        MISSING=$((MISSING + 1))
        ERRORS="$ERRORS\n- Missing: $1"
    fi
}

# Intelligence Layer
echo "1️⃣  Intelligence Layer Files:"
check_file "backend/app/intelligence/__init__.py"
check_file "backend/app/intelligence/ollama_client.py"
check_file "backend/app/intelligence/llm_analyst.py"
check_file "backend/app/intelligence/chat_agent.py"
check_file "backend/app/intelligence/prompts/vulnerability_analysis.py"
check_file "backend/app/intelligence/prompts/chat_prompts.py"

echo ""

# Validation Layer
echo "2️⃣  Validation Layer Files:"
check_file "backend/app/validation/__init__.py"
check_file "backend/app/validation/base_validator.py"
check_file "backend/app/validation/sql_validator.py"
check_file "backend/app/validation/xss_validator.py"
check_file "backend/app/validation/ssrf_validator.py"
check_file "backend/app/validation/rce_validator.py"
check_file "backend/app/validation/validation_orchestrator.py"

echo ""

# Documentation
echo "3️⃣  Documentation Files:"
check_file "OLLAMA_SETUP.md"
check_file "CHAT_GUIDE.md"
check_file "POC_VALIDATION_GUIDE.md"
check_file "AI_ROADMAP.md"
check_file "QUICK_START.md"

echo ""

# Test Scripts
echo "4️⃣  Test Scripts:"
check_file "test_validation.py"
check_file "test_chat.py"
check_file "test_phase1.py"

echo ""

# Main App
echo "5️⃣  Main Application:"
check_file "backend/app/main.py"
check_file "backend/requirements.txt"

echo ""

# Check Python syntax
echo "6️⃣  Python Syntax Check:"
echo "   Checking validation modules..."

cd backend 2>/dev/null || cd .

python3 -m py_compile app/validation/base_validator.py 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✅ base_validator.py - syntax OK"
else
    echo "   ❌ base_validator.py - syntax error"
    MISSING=$((MISSING + 1))
fi

python3 -m py_compile app/validation/sql_validator.py 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✅ sql_validator.py - syntax OK"
else
    echo "   ❌ sql_validator.py - syntax error"
    MISSING=$((MISSING + 1))
fi

python3 -m py_compile app/validation/xss_validator.py 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✅ xss_validator.py - syntax OK"
else
    echo "   ❌ xss_validator.py - syntax error"
    MISSING=$((MISSING + 1))
fi

python3 -m py_compile app/validation/ssrf_validator.py 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✅ ssrf_validator.py - syntax OK"
else
    echo "   ❌ ssrf_validator.py - syntax error"
    MISSING=$((MISSING + 1))
fi

python3 -m py_compile app/validation/rce_validator.py 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✅ rce_validator.py - syntax OK"
else
    echo "   ❌ rce_validator.py - syntax error"
    MISSING=$((MISSING + 1))
fi

python3 -m py_compile app/validation/validation_orchestrator.py 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✅ validation_orchestrator.py - syntax OK"
else
    echo "   ❌ validation_orchestrator.py - syntax error"
    MISSING=$((MISSING + 1))
fi

cd - >/dev/null 2>&1

echo ""
echo "============================================================"

# Summary
if [ $MISSING -eq 0 ]; then
    echo ""
    echo "🎉 SUCCESS! All Phase 1 files are present and correct!"
    echo ""
    echo "📊 Summary:"
    echo "   - Intelligence Layer: 6 files ✅"
    echo "   - Validation Layer: 7 files ✅"
    echo "   - Documentation: 5 files ✅"
    echo "   - Test Scripts: 3 files ✅"
    echo "   - Main App: 2 files ✅"
    echo ""
    echo "🚀 Next Steps:"
    echo "   1. Install dependencies:"
    echo "      cd backend && pip install -r requirements.txt"
    echo "      python -m playwright install chromium"
    echo ""
    echo "   2. (Optional) Install Ollama:"
    echo "      https://ollama.ai"
    echo ""
    echo "   3. Start backend:"
    echo "      cd backend && python -m uvicorn app.main:app --reload"
    echo ""
    echo "   4. Test Phase 1:"
    echo "      python test_validation.py"
    echo ""
    echo "📚 See QUICK_START.md for detailed instructions"
    echo ""
    exit 0
else
    echo ""
    echo "❌ ERRORS FOUND: $MISSING file(s) missing or invalid"
    echo -e "$ERRORS"
    echo ""
    exit 1
fi
