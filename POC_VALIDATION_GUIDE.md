# 🎯 PoC Validation System Guide

**Automatic Proof-of-Concept Testing for Vulnerability Validation**

---

## 🚀 Overview

The PoC Validation System automatically validates detected vulnerabilities by executing **safe, read-only exploits** to confirm they are exploitable. This eliminates false positives and increases report credibility.

### Key Features

✅ **Automatic Validation** - Validates vulnerabilities without manual intervention
🎯 **High Accuracy** - Confidence scores from 0.0 to 1.0
🔒 **Safe Testing** - Only read-only operations, no destructive actions
💰 **Cost-Free** - Runs completely locally ($0 cost)
📊 **Detailed Evidence** - Provides actual proof of exploitation

### Supported Vulnerability Types

| Vulnerability | Validation Method | Confidence |
|--------------|-------------------|------------|
| **SQL Injection** | Database version/data extraction | 0.95 - 1.0 |
| **XSS** | JavaScript execution in headless browser | 1.0 |
| **SSRF** | Out-of-band callback detection | 1.0 |
| **RCE/Command Injection** | Safe command execution + timing | 0.65 - 1.0 |

---

## 📦 Installation

### Prerequisites

```bash
# 1. Install Python dependencies
pip install httpx playwright asyncio

# 2. Install Playwright browsers (for XSS validation)
python -m playwright install chromium

# 3. (Optional) Setup callback server for SSRF validation
# Use Burp Collaborator, interact.sh, or your own server
```

### Verify Installation

```bash
# Run test script
python test_validation.py
```

---

## 🔧 API Endpoints

### 1. Validate All Vulnerabilities

**Endpoint:** `POST /api/v1/scans/{scan_id}/validate`

Validates all vulnerabilities in a scan with PoC testing.

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/scans/scan_123/validate
```

**Response:**
```json
{
  "scan_id": "scan_123",
  "validated": 15,
  "statistics": {
    "total": 15,
    "confirmed": 8,
    "likely": 4,
    "unconfirmed": 2,
    "false_positives": 1,
    "average_confidence": 0.78,
    "confirmation_rate": 53.3
  },
  "results": [
    {
      "vulnerability": {
        "id": "vuln_001",
        "title": "SQL Injection in search parameter",
        "severity": "high",
        "category": "sql_injection",
        "affected_url": "https://target.com/search.php",
        "affected_parameter": "q"
      },
      "validation": {
        "status": "confirmed",
        "confidence": 0.95,
        "evidence": "Successfully extracted database version: MySQL 8.0.32",
        "validated_at": "2025-11-27T12:34:56Z",
        "validator": "SQLInjectionValidator",
        "details": {
          "extracted_data": "MySQL 8.0.32",
          "payload": "' UNION SELECT @@version--",
          "method": "version_extraction"
        }
      }
    }
  ]
}
```

---

### 2. Validate Single Vulnerability

**Endpoint:** `POST /api/v1/vulnerabilities/{vuln_id}/validate?scan_id={scan_id}`

Validates a specific vulnerability.

**Request:**
```bash
curl -X POST "http://localhost:8000/api/v1/vulnerabilities/vuln_001/validate?scan_id=scan_123"
```

**Response:**
```json
{
  "vulnerability": {
    "id": "vuln_001",
    "title": "SQL Injection in search parameter"
  },
  "validation": {
    "status": "confirmed",
    "confidence": 0.95,
    "evidence": "Successfully extracted database version: MySQL 8.0.32",
    "validated_at": "2025-11-27T12:34:56Z",
    "validator": "SQLInjectionValidator",
    "details": {
      "extracted_data": "MySQL 8.0.32",
      "payload": "' UNION SELECT @@version--"
    }
  }
}
```

---

### 3. Get Validation Statistics

**Endpoint:** `GET /api/v1/scans/{scan_id}/validation-stats`

Returns aggregated validation statistics.

**Request:**
```bash
curl http://localhost:8000/api/v1/scans/scan_123/validation-stats
```

**Response:**
```json
{
  "scan_id": "scan_123",
  "validation_statistics": {
    "total": 15,
    "confirmed": 8,
    "likely": 4,
    "unconfirmed": 2,
    "false_positives": 1,
    "average_confidence": 0.78,
    "confirmation_rate": 53.3
  }
}
```

---

### 4. Get Confirmed Vulnerabilities Only

**Endpoint:** `GET /api/v1/scans/{scan_id}/confirmed-vulnerabilities?min_confidence=0.8`

Returns only high-confidence, validated vulnerabilities.

**Request:**
```bash
curl "http://localhost:8000/api/v1/scans/scan_123/confirmed-vulnerabilities?min_confidence=0.8"
```

**Response:**
```json
{
  "scan_id": "scan_123",
  "total_vulnerabilities": 15,
  "confirmed_vulnerabilities": 8,
  "min_confidence": 0.8,
  "vulnerabilities": [
    {
      "id": "vuln_001",
      "title": "SQL Injection",
      "severity": "high",
      "confidence_score": 0.95,
      "validation_status": "confirmed",
      "poc_evidence": "Extracted: MySQL 8.0.32"
    }
  ]
}
```

---

## 🧪 Validation Methods

### 1. SQL Injection Validator

**How it works:**
1. Injects `UNION SELECT` payloads to extract database metadata
2. Attempts to extract: version, current user, database name
3. Looks for database-specific patterns in responses

**Example Payloads:**
```sql
' UNION SELECT @@version--
' UNION SELECT version()--
' UNION SELECT user()--
' UNION SELECT database()--
```

**Confidence Levels:**
- **1.0**: Database version extracted
- **0.85**: Database user extracted
- **0.80**: Database name extracted
- **0.70**: SQL syntax error detected (likely vulnerable)

---

### 2. XSS Validator

**How it works:**
1. Injects JavaScript payloads with `alert()`, `confirm()`, `prompt()`
2. Loads page in headless Chromium browser (Playwright)
3. Detects JavaScript dialog execution
4. Falls back to response analysis if browser unavailable

**Example Payloads:**
```javascript
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

**Confidence Levels:**
- **1.0**: JavaScript executed in browser
- **0.75**: Payload reflected unescaped in HTML
- **0.50**: Payload partially reflected

---

### 3. SSRF Validator

**How it works:**
1. Generates unique callback URL (e.g., Burp Collaborator)
2. Injects callback URL into vulnerable parameter
3. Waits for out-of-band HTTP request
4. Falls back to internal endpoint testing (AWS metadata, localhost)

**Example Targets:**
```
http://169.254.169.254/latest/meta-data/  # AWS metadata
http://metadata.google.internal/           # GCP metadata
http://127.0.0.1/admin                     # Localhost
http://callback.yourserver.com/unique_id   # Callback server
```

**Confidence Levels:**
- **1.0**: Callback received
- **0.80**: Internal metadata detected in response
- **0.65**: Localhost reference detected

---

### 4. RCE/Command Injection Validator

**How it works:**
1. **Marker Injection**: Injects unique echo commands, checks for marker in response
2. **Command Output Detection**: Executes `whoami`, `id`, `pwd`, checks for expected patterns
3. **Timing Attack**: Injects `sleep 5`, measures response delay

**Example Payloads:**
```bash
; echo RCE_MARKER_abc123
| whoami
&& id
; sleep 5
```

**Confidence Levels:**
- **1.0**: Unique marker detected
- **0.80**: Command output pattern detected
- **0.65**: Timing delay detected (5+ seconds)

---

## 🔒 Safety Guarantees

### What We Do:
✅ Execute **read-only** commands only (`whoami`, `id`, `pwd`, `version()`)
✅ Use **unique markers** to avoid false positives
✅ Respect **rate limits** and timeouts
✅ Test against **dedicated test targets** only

### What We DON'T Do:
❌ Modify or delete data
❌ Execute destructive commands (`rm`, `drop`, `delete`)
❌ Create backdoors or persistence
❌ Exfiltrate sensitive data beyond PoC
❌ Perform DoS attacks

---

## 📊 Validation Status Types

| Status | Description | Confidence Range | Action |
|--------|-------------|------------------|--------|
| **CONFIRMED** | PoC succeeded, vulnerability is exploitable | 0.95 - 1.0 | **Fix immediately** |
| **LIKELY** | Strong evidence, but not definitive proof | 0.65 - 0.94 | Manual verification recommended |
| **UNCONFIRMED** | Could not confirm with PoC | 0.0 - 0.64 | Manual testing required |
| **FALSE_POSITIVE** | Not vulnerable (scanner error) | 0.0 | Exclude from report |

---

## 🛠️ Python Client Example

```python
import httpx
import asyncio

async def validate_scan(scan_id: str):
    """Validate all vulnerabilities in a scan"""
    async with httpx.AsyncClient() as client:
        # Start validation
        response = await client.post(
            f"http://localhost:8000/api/v1/scans/{scan_id}/validate"
        )

        data = response.json()

        # Print statistics
        stats = data["statistics"]
        print(f"Confirmed: {stats['confirmed']}")
        print(f"Likely: {stats['likely']}")
        print(f"False Positives: {stats['false_positives']}")

        # Get only confirmed vulnerabilities
        confirmed_response = await client.get(
            f"http://localhost:8000/api/v1/scans/{scan_id}/confirmed-vulnerabilities",
            params={"min_confidence": 0.8}
        )

        confirmed = confirmed_response.json()
        print(f"High-confidence vulnerabilities: {confirmed['confirmed_vulnerabilities']}")

asyncio.run(validate_scan("scan_123"))
```

---

## 📝 JavaScript Client Example

```javascript
// Validate scan
async function validateScan(scanId) {
  const response = await fetch(`/api/v1/scans/${scanId}/validate`, {
    method: 'POST'
  });

  const data = await response.json();

  console.log('Validation Statistics:', data.statistics);
  console.log(`Confirmed: ${data.statistics.confirmed}`);
  console.log(`False Positives: ${data.statistics.false_positives}`);

  // Get confirmed vulnerabilities only
  const confirmedResponse = await fetch(
    `/api/v1/scans/${scanId}/confirmed-vulnerabilities?min_confidence=0.8`
  );

  const confirmed = await confirmedResponse.json();
  console.log('Confirmed vulnerabilities:', confirmed.vulnerabilities);
}

validateScan('scan_123');
```

---

## 🧪 Testing

### Run Full Test Suite

```bash
# Test with API endpoints
python test_validation.py

# Test with sample data (requires backend running)
python test_validation.py --sample
```

### Test Individual Validator

```python
from app.validation import SQLInjectionValidator, get_validation_orchestrator
from app.models import Vulnerability
from app.utils import PentestHTTPClient

# Create sample vulnerability
vuln = Vulnerability(
    id="test_1",
    title="SQL Injection",
    category="sql_injection",
    affected_url="http://testphp.vulnweb.com/search.php",
    affected_parameter="searchFor"
)

# Validate
validator = SQLInjectionValidator()
client = PentestHTTPClient(base_url="http://testphp.vulnweb.com")

result = await validator.validate(
    vulnerability=vuln,
    target_url="http://testphp.vulnweb.com",
    client=client
)

print(f"Status: {result.status.value}")
print(f"Confidence: {result.confidence}")
print(f"Evidence: {result.evidence}")
```

---

## 🎯 Best Practices

### 1. Use Validation in CI/CD

```yaml
# .github/workflows/security-scan.yml
- name: Run Security Scan
  run: |
    # Start scan
    SCAN_ID=$(curl -X POST http://localhost:8000/api/v1/scans \
      -d '{"target_url":"${{ github.server_url }}/${{ github.repository }}"}' \
      | jq -r '.scan_id')

    # Wait for completion
    while [ "$(curl http://localhost:8000/api/v1/scans/$SCAN_ID | jq -r '.status')" != "completed" ]; do
      sleep 5
    done

    # Validate vulnerabilities
    curl -X POST http://localhost:8000/api/v1/scans/$SCAN_ID/validate

    # Get confirmed vulnerabilities
    CONFIRMED=$(curl "http://localhost:8000/api/v1/scans/$SCAN_ID/confirmed-vulnerabilities?min_confidence=0.8" \
      | jq '.confirmed_vulnerabilities')

    # Fail if critical vulnerabilities found
    if [ "$CONFIRMED" -gt 0 ]; then
      echo "❌ Found $CONFIRMED confirmed vulnerabilities!"
      exit 1
    fi
```

### 2. Filter False Positives

Always exclude false positives from reports:

```python
# Get only real vulnerabilities
confirmed_response = await client.get(
    f"/api/v1/scans/{scan_id}/confirmed-vulnerabilities",
    params={"min_confidence": 0.8}
)

confirmed_vulns = confirmed_response.json()["vulnerabilities"]

# These are real, exploitable vulnerabilities
for vuln in confirmed_vulns:
    print(f"CRITICAL: {vuln['title']}")
```

### 3. Combine with AI Analysis

For best results, use both validation and AI analysis:

```python
# 1. Validate vulnerabilities
validation_response = await client.post(f"/api/v1/scans/{scan_id}/validate")
validated = validation_response.json()

# 2. Get AI analysis for confirmed vulnerabilities
for result in validated["results"]:
    if result["validation"]["status"] == "confirmed":
        vuln_id = result["vulnerability"]["id"]

        # Get AI remediation guidance
        ai_response = await client.post(
            f"/api/v1/vulnerabilities/{vuln_id}/generate-fix",
            params={"scan_id": scan_id}
        )

        code_fix = ai_response.json()["code_fix"]
        print(f"Fix for {vuln_id}:")
        print(code_fix)
```

---

## 🐛 Troubleshooting

### Issue: XSS validation fails with "Playwright not installed"

**Solution:**
```bash
pip install playwright
python -m playwright install chromium
```

### Issue: SSRF validation always returns "unconfirmed"

**Solution:**
The default callback server is a mock. For production:

1. Use Burp Collaborator: https://portswigger.net/burp/documentation/collaborator
2. Use interact.sh: https://github.com/projectdiscovery/interactsh
3. Setup your own callback server

Edit `backend/app/validation/ssrf_validator.py`:
```python
def generate_callback_url(self, identifier: str) -> str:
    return f"http://your-callback-server.com/{identifier}"
```

### Issue: SQL validation returns false positives

**Solution:**
Check if the target uses parameterized queries. Some false positives occur when:
- Database errors are hidden
- Input is sanitized but error messages leak info
- WAF blocks SQL payloads

Review the `details` field in validation results for debugging.

---

## 📊 Performance

**Typical validation times:**
- SQL Injection: 2-5 seconds
- XSS: 5-10 seconds (browser launch)
- SSRF: 5-15 seconds (callback wait)
- RCE: 5-10 seconds (timing tests)

**Full scan validation:** 30-120 seconds for 20 vulnerabilities

---

## 🚀 Roadmap

### Planned Validators:
- [ ] Path Traversal (file read confirmation)
- [ ] XXE (external entity resolution)
- [ ] CSRF (cross-origin request detection)
- [ ] Clickjacking (X-Frame-Options check)
- [ ] Insecure Deserialization (code execution)

### Planned Features:
- [ ] Parallel validation (validate multiple vulns simultaneously)
- [ ] Validation caching (avoid re-validating same endpoint)
- [ ] Custom validator plugins
- [ ] Validation replay (re-test after fixes)

---

## 📚 References

- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- HackerOne Vulnerability Disclosure: https://www.hackerone.com/disclosure-guidelines

---

**Need Help?**

- GitHub Issues: https://github.com/K3E9X/devasc-study-team/issues
- Documentation: See `AI_ROADMAP.md` for AI-powered features

---

**⚠️ Legal Notice:**

This tool is intended for **authorized security testing only**. Always obtain explicit permission before testing any system you do not own. Unauthorized access is illegal and unethical.
