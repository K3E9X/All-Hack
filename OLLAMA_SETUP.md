# 🤖 Ollama Setup Guide - AI-Powered Analysis for All-Hack

## 🎯 What is Ollama?

**Ollama** is a tool that lets you run large language models (LLMs) locally on your machine.

**Benefits**:
- ✅ **$0 cost** - Completely free
- ✅ **100% privacy** - No data leaves your machine
- ✅ **Offline capable** - Works without internet
- ✅ **No rate limits** - Unlimited requests
- ✅ **Fast** - Low latency responses

---

## 📦 Installation

### 🐧 Linux / WSL

```bash
# Download and install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Verify installation
ollama --version
```

### 🍎 macOS

```bash
# Download from https://ollama.ai/download/mac
# Or use Homebrew
brew install ollama
```

### 🪟 Windows

Download from: https://ollama.ai/download/windows

---

## 🚀 Quick Start

### 1. Start Ollama Server

```bash
# Start the server (runs on localhost:11434)
ollama serve
```

Keep this terminal open!

### 2. Pull AI Model

In a **new terminal**:

```bash
# Download llama3.2 (8B parameters, ~4.7GB)
ollama pull llama3.2

# This takes 5-10 minutes depending on your internet speed
```

### 3. Test Model

```bash
# Quick test
ollama run llama3.2 "Explain SQL injection in 2 sentences"
```

Expected output:
```
SQL injection is a security vulnerability where attackers insert malicious SQL code
into application queries to manipulate databases. This allows unauthorized data access,
modification, or deletion by exploiting poor input validation.
```

If this works, you're ready! ✅

---

## 🧪 Test with All-Hack

### 1. Start All-Hack Backend

```bash
cd backend
python -m uvicorn app.main:app --reload
```

### 2. Check AI Status

```bash
# Check if Ollama is detected
curl http://localhost:8000/api/v1/ai/status
```

Expected response:
```json
{
  "available": true,
  "provider": "Ollama (local)",
  "model": "llama3.2",
  "endpoint": "http://localhost:11434",
  "cost": "$0 (free)"
}
```

### 3. Run a Scan

```bash
# Start a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://testphp.vulnweb.com",
    "mode": "black_box",
    "scan_depth": "quick"
  }'

# Save the scan_id from the response
```

### 4. Analyze with AI

```bash
# Analyze all vulnerabilities found
curl -X POST http://localhost:8000/api/v1/scans/{scan_id}/analyze
```

This will:
- Analyze each vulnerability with AI
- Provide root cause analysis
- Rate exploitation complexity
- Generate remediation code
- Create strategic summary

---

## 📊 Available Models

### Recommended Models:

| Model | Size | RAM Required | Speed | Quality | Use Case |
|-------|------|--------------|-------|---------|----------|
| **llama3.2** | 8B | 8GB | Fast | Good | **Default - Best balance** |
| llama3.2:70b | 70B | 40GB | Slow | Excellent | High-quality analysis |
| mistral | 7B | 6GB | Very Fast | Good | Quick analysis |
| codellama | 7B | 6GB | Fast | Excellent | Code-focused analysis |
| phi3 | 3.8B | 4GB | Very Fast | Decent | Low-resource systems |

### Pull a Different Model:

```bash
# Pull model
ollama pull codellama

# Update All-Hack config (optional)
export OLLAMA_MODEL=codellama

# Restart backend to use new model
```

---

## 🔧 API Endpoints

### Check AI Status
```bash
GET /api/v1/ai/status
```

### Analyze Entire Scan
```bash
POST /api/v1/scans/{scan_id}/analyze
```
Returns AI analysis for all vulnerabilities.

### Analyze Single Vulnerability
```bash
GET /api/v1/vulnerabilities/{vuln_id}/analyze?scan_id={scan_id}
```

### Get Exploitation Guide
```bash
POST /api/v1/vulnerabilities/{vuln_id}/exploit-guide?scan_id={scan_id}&question=How+to+exploit
```

### Generate Code Fix
```bash
POST /api/v1/vulnerabilities/{vuln_id}/generate-fix?scan_id={scan_id}
```

### Identify Attack Chains
```bash
GET /api/v1/scans/{scan_id}/attack-chains
```

---

## 💡 Example Workflow

### Full AI-Powered Pentest:

```bash
# 1. Start scan
SCAN_ID=$(curl -s -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://testphp.vulnweb.com", "mode": "black_box"}' \
  | jq -r '.scan_id')

echo "Scan ID: $SCAN_ID"

# 2. Wait for scan to complete (check status)
while true; do
  STATUS=$(curl -s http://localhost:8000/api/v1/scans/$SCAN_ID/status | jq -r '.status')
  echo "Status: $STATUS"
  [ "$STATUS" = "completed" ] && break
  sleep 10
done

# 3. Get scan results
curl http://localhost:8000/api/v1/scans/$SCAN_ID | jq

# 4. AI Analysis
curl -X POST http://localhost:8000/api/v1/scans/$SCAN_ID/analyze | jq

# 5. Identify attack chains
curl http://localhost:8000/api/v1/scans/$SCAN_ID/attack-chains | jq

# 6. Get exploitation guide for first vuln
VULN_ID=$(curl -s http://localhost:8000/api/v1/scans/$SCAN_ID/vulnerabilities \
  | jq -r '.vulnerabilities[0].id')

curl -X POST "http://localhost:8000/api/v1/vulnerabilities/$VULN_ID/exploit-guide?scan_id=$SCAN_ID&question=How+to+exploit+this" \
  | jq -r '.exploitation_guide'

# 7. Generate code fix
curl -X POST "http://localhost:8000/api/v1/vulnerabilities/$VULN_ID/generate-fix?scan_id=$SCAN_ID" \
  | jq -r '.code_fix'
```

---

## 🎨 Example AI Analysis Output

### Input Vulnerability:
```json
{
  "title": "SQL Injection",
  "severity": "critical",
  "affected_url": "http://example.com/search?q=test",
  "payload": "1' OR '1'='1"
}
```

### AI Analysis Output:
```markdown
## Root Cause Analysis

The application directly concatenates user input into SQL queries without
proper sanitization or parameterization. The 'q' parameter accepts SQL
metacharacters that alter the query logic.

## Exploitation Complexity: Trivial

- **Skill Required**: Basic SQL knowledge
- **Tools**: Web browser or curl
- **Time to Exploit**: < 5 minutes
- **Detection Risk**: Low (appears as normal search)

## Business Impact

**Critical severity** - Complete database compromise possible:
- Extraction of all database contents including user credentials
- Potential remote code execution via xp_cmdshell (SQL Server)
- Data modification or deletion
- Regulatory violations (GDPR, PCI-DSS if payment data exposed)
- Estimated breach cost: $50,000 - $500,000

## Remediation Code

**Framework: Django**

BEFORE (Vulnerable):
```python
# views.py
def search(request):
    query = request.GET.get('q')
    results = User.objects.raw(f"SELECT * FROM users WHERE name LIKE '%{query}%'")
    return render(request, 'results.html', {'results': results})
```

AFTER (Secure):
```python
# views.py
def search(request):
    query = request.GET.get('q')
    # Use parameterized query
    results = User.objects.raw(
        "SELECT * FROM users WHERE name LIKE %s",
        [f'%{query}%']
    )
    return render(request, 'results.html', {'results': results})
```

**Key Changes:**
- Replaced f-string concatenation with parameterized query
- Django's ORM safely escapes the parameter
- SQL metacharacters now treated as literal data

## Next Steps

1. **Immediate**: Patch the vulnerability (deploy fix above)
2. **Testing**: Run SQLMap to verify fix: `sqlmap -u "http://example.com/search?q=test" --batch`
3. **Audit**: Review all database queries in codebase for similar patterns
4. **Prevention**: Implement code review checklist for SQL injection
5. **Monitoring**: Enable database query logging to detect exploitation attempts
```

---

## 🛠️ Troubleshooting

### Problem: "Ollama not available"

**Solution**:
```bash
# Check if Ollama is running
ps aux | grep ollama

# If not running, start it
ollama serve

# Check if accessible
curl http://localhost:11434/api/tags
```

### Problem: "Model not found"

**Solution**:
```bash
# List installed models
ollama list

# Pull the model
ollama pull llama3.2

# Verify
ollama list
```

### Problem: "Connection refused"

**Solution**:
```bash
# Check Ollama port
lsof -i :11434

# If nothing, start Ollama
ollama serve

# Check firewall (Linux)
sudo ufw allow 11434
```

### Problem: "Out of memory"

**Solution**:
```bash
# Use smaller model
ollama pull phi3

# Or increase Docker memory (if using Docker)
# Docker Desktop > Settings > Resources > Memory: 8GB+
```

### Problem: "Slow responses"

**Solution**:
```bash
# Use smaller/faster model
ollama pull mistral

# Or enable GPU acceleration (if available)
# Ollama automatically uses GPU if detected

# Check GPU usage
nvidia-smi  # For NVIDIA GPUs
```

---

## 🔒 Security & Privacy

### Data Privacy:

✅ **All data stays local**
- No API keys required
- No cloud services
- No telemetry/tracking
- Suitable for confidential pentests

### Network Isolation:

```bash
# Ollama only listens on localhost by default
# To restrict further, use firewall rules

# Linux (UFW)
sudo ufw deny 11434
sudo ufw allow from 127.0.0.1 to any port 11434

# Or bind to localhost only (edit systemd service)
# OLLAMA_HOST=127.0.0.1:11434
```

---

## 📈 Performance Tuning

### Speed Up Analysis:

```bash
# 1. Use faster model
ollama pull mistral

# 2. Reduce context window (edit code)
# in backend/app/intelligence/ollama_client.py:
# max_tokens: int = 2048  # Reduce from 4096

# 3. Enable GPU (automatic if available)
# Ollama will use NVIDIA/AMD GPUs automatically

# 4. Increase concurrent requests
# Edit backend code to analyze vulnerabilities in parallel
```

### Check Performance:

```bash
# Monitor Ollama resource usage
docker stats ollama  # If running in Docker

# Or system monitor
htop
nvidia-smi  # For GPU usage
```

---

## 🚀 Next Steps

Now that Ollama is set up, you can:

1. ✅ Run scans and get AI analysis automatically
2. ✅ Ask questions about vulnerabilities
3. ✅ Generate framework-specific code fixes
4. ✅ Identify attack chains

**Want more AI features?**
- See `AI_ROADMAP.md` for upcoming features:
  - Interactive chat interface
  - Multi-agent system
  - Automatic PoC validation
  - Long-term memory

---

## 📚 Resources

- **Ollama Documentation**: https://github.com/ollama/ollama
- **Model Library**: https://ollama.ai/library
- **All-Hack AI Roadmap**: `AI_ROADMAP.md`
- **Feature Comparison**: `FEATURE_COMPARISON.md`

---

**🎉 You're all set! Start using AI-powered vulnerability analysis with $0 cost!**
