# 🚀 Quick Start Guide - All-Hack Phase 1

**AI-Powered Pentesting Tool with Intelligence & Validation**

---

## ⚡ Installation (5 minutes)

### 1. Install Python Dependencies

```bash
# Navigate to backend
cd backend

# Install all dependencies
pip install -r requirements.txt

# Install Playwright browsers for XSS validation
python -m playwright install chromium
```

### 2. (Optional) Install Ollama for AI Features

**Ollama provides $0 cost AI analysis (runs locally)**

```bash
# macOS/Linux
curl -fsSL https://ollama.com/install.sh | sh

# Or download from: https://ollama.ai

# Pull the AI model (llama3.2)
ollama pull llama3.2

# Verify Ollama is running
ollama run llama3.2
# Type: exit
```

**Windows:**
- Download from https://ollama.ai
- Install and run
- Open PowerShell: `ollama pull llama3.2`

---

## 🎯 Start the Backend

```bash
# From backend directory
cd backend

# Start with uvicorn
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**You should see:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

**API is ready at:** http://localhost:8000

**Interactive docs:** http://localhost:8000/docs

---

## 🧪 Test Phase 1 Features

### Option A: Quick API Test (cURL)

```bash
# 1. Check health
curl http://localhost:8000/health

# 2. Check AI status
curl http://localhost:8000/api/v1/ai/status

# 3. Start a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://testphp.vulnweb.com",
    "mode": "black_box"
  }'

# You'll get: {"scan_id": "scan_xxx", ...}

# 4. Wait ~30 seconds, then get results
curl http://localhost:8000/api/v1/scans/scan_xxx

# 5. Validate vulnerabilities with PoC
curl -X POST http://localhost:8000/api/v1/scans/scan_xxx/validate

# 6. Get only confirmed vulnerabilities
curl "http://localhost:8000/api/v1/scans/scan_xxx/confirmed-vulnerabilities?min_confidence=0.8"

# 7. (If Ollama installed) Get AI analysis
curl -X POST http://localhost:8000/api/v1/scans/scan_xxx/analyze
```

### Option B: Automated Test Scripts

```bash
# From project root

# Test validation system
python test_validation.py

# Test chat interface (requires Ollama)
python test_chat.py

# Test all Phase 1 imports
python test_phase1.py
```

---

## 📊 Interactive API Documentation

Open in browser: **http://localhost:8000/docs**

You can test all endpoints directly from the browser:
- 16 Phase 1 endpoints
- WebSocket chat interface
- AI analysis endpoints
- PoC validation endpoints

---

## 🎯 Phase 1 Features to Test

### 1. 🧠 AI Vulnerability Analysis

**Endpoint:** `POST /api/v1/scans/{scan_id}/analyze`

**What it does:**
- Analyzes all vulnerabilities with local LLM
- Provides root cause analysis
- Rates exploitation complexity
- Assesses business impact
- Generates framework-specific fixes

**Requirements:** Ollama running with llama3.2

**Test:**
```bash
SCAN_ID="your_scan_id"
curl -X POST http://localhost:8000/api/v1/scans/$SCAN_ID/analyze
```

---

### 2. 💬 Interactive Chat Interface

**WebSocket:** `ws://localhost:8000/ws/chat/{scan_id}`

**What it does:**
- Real-time chat about scan results
- Streaming AI responses
- Context-aware (knows about the scan)
- Natural language queries

**Requirements:** Ollama running

**Test with Python:**
```python
python test_chat.py
```

**Test with JavaScript:**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/chat/scan_xxx');

ws.onopen = () => {
  ws.send(JSON.stringify({
    message: "What are the critical vulnerabilities?"
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data.content);
};
```

---

### 3. ✅ Automatic PoC Validation

**Endpoint:** `POST /api/v1/scans/{scan_id}/validate`

**What it does:**
- Validates vulnerabilities with real exploits
- SQL Injection: Extracts database version
- XSS: Executes JavaScript in headless browser
- SSRF: Detects callbacks
- RCE: Safe command execution
- Returns confidence scores (0.0 to 1.0)
- Eliminates false positives

**No requirements** - runs locally, $0 cost

**Test:**
```bash
SCAN_ID="your_scan_id"

# Validate all vulnerabilities
curl -X POST http://localhost:8000/api/v1/scans/$SCAN_ID/validate

# Get validation statistics
curl http://localhost:8000/api/v1/scans/$SCAN_ID/validation-stats

# Get only confirmed (high-confidence) vulnerabilities
curl "http://localhost:8000/api/v1/scans/$SCAN_ID/confirmed-vulnerabilities?min_confidence=0.8"
```

---

## 🔍 Complete Workflow Example

```bash
# 1. Start a scan
SCAN_RESPONSE=$(curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://testphp.vulnweb.com", "mode": "black_box"}')

SCAN_ID=$(echo $SCAN_RESPONSE | jq -r '.scan_id')
echo "Scan ID: $SCAN_ID"

# 2. Wait for scan to complete (check status)
while true; do
  STATUS=$(curl -s http://localhost:8000/api/v1/scans/$SCAN_ID | jq -r '.status')
  echo "Status: $STATUS"
  [ "$STATUS" = "completed" ] && break
  sleep 5
done

# 3. Validate vulnerabilities with PoC
echo "Validating vulnerabilities..."
curl -X POST http://localhost:8000/api/v1/scans/$SCAN_ID/validate | jq

# 4. Get only confirmed vulnerabilities
echo "Getting confirmed vulnerabilities..."
curl "http://localhost:8000/api/v1/scans/$SCAN_ID/confirmed-vulnerabilities?min_confidence=0.8" | jq

# 5. (If Ollama installed) Get AI analysis
echo "Getting AI analysis..."
curl -X POST http://localhost:8000/api/v1/scans/$SCAN_ID/analyze | jq

# 6. Chat about results (WebSocket - use test_chat.py or browser)
python test_chat.py
```

---

## 📚 Documentation

**Phase 1 Guides:**
- `OLLAMA_SETUP.md` - AI analysis setup (500+ lines)
- `CHAT_GUIDE.md` - Chat interface guide (500+ lines)
- `POC_VALIDATION_GUIDE.md` - Validation system guide (500+ lines)
- `AI_ROADMAP.md` - Full roadmap and features

**Architecture:**
- `backend/app/intelligence/*` - AI analysis & chat (1200+ lines)
- `backend/app/validation/*` - PoC validation (1100+ lines)

---

## 🐛 Troubleshooting

### Issue: "Ollama not available"

**Solution:**
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If not running, start it
ollama serve

# Pull model if needed
ollama pull llama3.2
```

### Issue: "Playwright not installed"

**Solution:**
```bash
pip install playwright
python -m playwright install chromium
```

### Issue: "Port 8000 already in use"

**Solution:**
```bash
# Use different port
python -m uvicorn app.main:app --reload --port 8001

# Or kill process on port 8000
lsof -ti:8000 | xargs kill -9
```

### Issue: Scan fails with "Connection refused"

**Solution:**
- Make sure target URL is reachable
- Use test target: http://testphp.vulnweb.com
- Check firewall settings

---

## 🎯 What to Test

### ✅ Must Test:
1. **Backend startup** - `uvicorn app.main:app --reload`
2. **API docs** - http://localhost:8000/docs
3. **Basic scan** - Test with http://testphp.vulnweb.com
4. **PoC Validation** - Validate scan results
5. **Get confirmed vulnerabilities** - Filter by confidence

### 🟡 Optional (requires Ollama):
6. **AI Analysis** - Analyze vulnerabilities with LLM
7. **Chat Interface** - Ask questions about scan results
8. **Attack Chains** - Identify multi-step attack paths

---

## 📊 Expected Results

### After a successful scan on testphp.vulnweb.com:

**Vulnerabilities found:** ~15-30
- SQL Injection: 3-5
- XSS: 5-10
- Path Traversal: 2-3
- Missing security headers: 5-10

**After PoC Validation:**
- Confirmed: ~40-60% (high confidence)
- Likely: ~20-30%
- Unconfirmed: ~10-20%
- False Positives: ~5-10%

**Validation confidence scores:**
- SQL Injection: 0.95-1.0
- XSS: 1.0 (if executed in browser)
- SSRF: 0.65-1.0
- RCE: 0.65-1.0

---

## 🚀 Next Steps After Testing

Once Phase 1 works:

### Phase 2: Multi-Agent System
- Orchestrator Agent
- Recon Agent (intelligent enumeration)
- Exploitation Agent (adaptive payloads)
- Analysis Agent (vulnerability correlation)
- Reporting Agent
- Long-term memory (pgvector)

### Phase 3: Frontend
- Web UI for scans
- Real-time chat interface
- Dashboard with visualizations
- Report generator

---

## 💡 Pro Tips

1. **Use test targets:**
   - http://testphp.vulnweb.com (intentionally vulnerable)
   - http://demo.testfire.net
   - Your own test applications

2. **Start small:**
   - Test one endpoint at a time
   - Use `/docs` for interactive testing
   - Check logs for errors

3. **Monitor performance:**
   - Validation takes 30-120 seconds
   - AI analysis takes 10-60 seconds per vulnerability
   - Chat responses stream in real-time

4. **Combine features:**
   - Scan → Validate → AI Analysis → Chat
   - This gives you the full experience

---

## 📞 Need Help?

- **Documentation:** Check the 3 comprehensive guides
- **API Reference:** http://localhost:8000/docs
- **Test Scripts:** `test_validation.py`, `test_chat.py`, `test_phase1.py`
- **GitHub Issues:** https://github.com/K3E9X/devasc-study-team/issues

---

**🎉 Enjoy testing All-Hack Phase 1!**

**Built with:**
- FastAPI (backend)
- Ollama (local AI, $0 cost)
- Playwright (headless browser)
- WebSocket (real-time chat)
- PoC validation (4 validators)
