# 🚀 New Features - API Security & AI Agent

This document describes the major new features added to the automated penetration testing tool.

## 📋 Table of Contents
- [API Security Testing](#api-security-testing)
- [AI Agent - Autonomous Pentesting](#ai-agent---autonomous-pentesting)
- [Email Notifications](#email-notifications)
- [Setup Guide](#setup-guide)

---

## 🔐 API Security Testing

We've added comprehensive API security testing capabilities to detect modern web application vulnerabilities.

### New Scanners

#### 1. **JWT Security Scanner**
Tests JSON Web Token implementations for common vulnerabilities:
- ✅ Algorithm confusion attacks (`alg: none`, HS256 vs RS256)
- ✅ Weak secret detection (brute-force common secrets)
- ✅ Missing or excessive expiration times
- ✅ Claims manipulation (privilege escalation)
- ✅ Signature bypass attempts

**Example Vulnerabilities Detected:**
```json
{
  "title": "JWT 'none' Algorithm Accepted",
  "severity": "CRITICAL",
  "description": "Application accepts JWT with 'alg': 'none', bypassing signature verification",
  "remediation": "Reject JWT with 'none' algorithm, enforce algorithm whitelist"
}
```

#### 2. **GraphQL Security Scanner**
Tests GraphQL implementations for security issues:
- ✅ Introspection enabled in production (schema disclosure)
- ✅ Batching/aliasing attacks (rate limit bypass)
- ✅ Deep nested query DoS attacks
- ✅ Injection flaws in resolvers
- ✅ Information disclosure via error messages

**Example Vulnerabilities Detected:**
```json
{
  "title": "GraphQL Introspection Enabled",
  "severity": "MEDIUM",
  "description": "Full API schema exposed via introspection query",
  "remediation": "Disable introspection in production"
}
```

#### 3. **NoSQL Injection Scanner**
Tests for MongoDB and other NoSQL database injection:
- ✅ MongoDB operator injection (`$ne`, `$gt`, `$regex`, etc.)
- ✅ Authentication bypass via operators
- ✅ JSON payload manipulation
- ✅ Query parameter injection
- ✅ POST body injection

**Example Vulnerabilities Detected:**
```json
{
  "title": "NoSQL Injection - Authentication Bypass",
  "severity": "CRITICAL",
  "description": "MongoDB operator '$ne' bypassed authentication",
  "payload": "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}"
}
```

#### 4. **File Upload Security Scanner**
Tests file upload functionality for security flaws:
- ✅ Dangerous extension bypass (`.php`, `.asp`, `.jsp`, etc.)
- ✅ MIME type validation bypass
- ✅ Path traversal in filenames (`../../../shell.php`)
- ✅ Missing file size limits
- ✅ Content validation bypass

**Example Vulnerabilities Detected:**
```json
{
  "title": "Unrestricted File Upload - .php Extension Allowed",
  "severity": "CRITICAL",
  "description": "Application accepts PHP files, allowing webshell upload",
  "remediation": "Implement whitelist of allowed extensions, validate file content"
}
```

### Integration

These scanners are automatically integrated into **Phase 2.5** of the scan process:

```
Phase 0 - Infrastructure      : Port scanning, SSL/TLS, Subdomain enum
Phase 1 - Reconnaissance      : Tech detection, Endpoint crawling
Phase 2 - OWASP Testing       : SQL, XSS, Command Injection, SSRF
Phase 2.5 - API Security      : JWT, GraphQL, NoSQL, File Upload (NEW!)
Phase 3 - Access Control      : IDOR, Privilege escalation
Phase 4 - Misconfiguration    : Security headers, CORS
```

---

## 🤖 AI Agent - Autonomous Pentesting

The **Autonomous Pentest Agent** uses Claude AI to analyze scan results in real-time and intelligently decide which tests to perform next.

### Features

#### 🧠 **Intelligent Decision Making**
- Analyzes vulnerabilities found during scan
- Identifies patterns and related vulnerability types
- Prioritizes tests based on technology stack detected
- Suggests exploitation strategies

#### 🔄 **Autonomous Operation**
- Runs iteratively without human intervention
- Adapts testing strategy based on findings
- Continues testing while you sleep 💤
- Stops automatically when no more tests are recommended

#### 📊 **Context-Aware Testing**
The AI agent considers:
- Current vulnerabilities discovered
- Technologies detected (Node.js, PHP, MongoDB, etc.)
- Endpoints and API structure
- Severity and impact of findings

### Example AI Decision

```json
{
  "next_actions": [
    {
      "test": "jwt_deep_analysis",
      "target": "/api/auth",
      "priority": "critical",
      "reason": "Found JWT tokens in responses, need to test for algorithm confusion and weak secrets"
    },
    {
      "test": "nosql_advanced",
      "target": "/api/users",
      "priority": "high",
      "reason": "MongoDB detected, SQL injection found on /api/login suggests poor input validation across the board"
    }
  ],
  "reasoning": "The application uses MongoDB and has weak input validation. After finding SQL injection, I'm prioritizing NoSQL injection tests and JWT security analysis since auth tokens were discovered.",
  "confidence": 0.85,
  "estimated_time_minutes": 15
}
```

### How It Works

1. **Initial Scan**: Regular automated scan runs (Phases 0-4)
2. **AI Analysis**: Claude analyzes all findings
3. **Decision**: AI recommends 2-5 high-impact tests
4. **Execution**: Tests are automatically executed
5. **Iteration**: Process repeats up to 10 times
6. **Completion**: Scan finishes when AI finds no more relevant tests

### Autonomous Scan Loop

```python
# Pseudocode
while iteration < max_iterations:
    # AI analyzes current results
    decision = ai_agent.analyze_and_decide(scan_result)

    # Execute AI-recommended tests
    for action in decision['next_actions']:
        new_vulnerabilities = execute_test(action)
        scan_result.add(new_vulnerabilities)

    # AI decides if we should continue
    if no_more_tests_recommended:
        break

# Send notification when done
notify_user_via_email()
```

---

## 📧 Email Notifications

Get notified when your scans complete, even if you're away from your computer!

### Features

#### ✉️ **Beautiful HTML Emails**
- Professional design with color-coded severity levels
- Summary of findings (Critical, High, Medium, Low)
- Top 5 critical vulnerabilities highlighted
- Direct link to view full results in dashboard
- Mobile-responsive design

#### 🔔 **Multiple Notification Channels**
1. **Email** (SMTP)
2. **Webhook** (Custom integrations)
3. **Slack** (Team notifications)

### Email Example

```
Subject: 🎯 Pentest Complete: https://target.com

╔══════════════════════════════════════╗
║   🎯 Penetration Test Complete       ║
╚══════════════════════════════════════╝

Target: https://target.com
Overall Risk: 🔴 CRITICAL

┌─────────────────────────────────────┐
│ Vulnerabilities Found               │
├─────────────────────────────────────┤
│ Total:    47                        │
│ Critical: 5                         │
│ High:     12                        │
│ Medium:   23                        │
│ Low:      7                         │
└─────────────────────────────────────┘

⚠️ Top Critical Vulnerabilities:

1. JWT 'none' Algorithm Accepted
   URL: https://target.com/api/auth
   Category: Broken Authentication

2. NoSQL Injection - Authentication Bypass
   URL: https://target.com/api/login
   Category: Injection

[View Full Results] → http://localhost:5173/results?scan_id=abc123
```

### Slack Integration

Sends a formatted message to your Slack channel:

```
🚨 Pentest Complete: https://target.com

Target: https://target.com
Scan ID: abc-123-def-456

Total Vulns: 47
Critical: 5
High: 12
Endpoints: 250
```

---

## 🛠️ Setup Guide

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

**New dependency added:**
- `anthropic==0.39.0` - Claude AI SDK

### 2. Configure Environment Variables

Copy the example environment file:
```bash
cp .env.example .env
```

#### AI Agent Configuration

Get your Claude API key from https://console.anthropic.com/

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-api03-xxx
ENABLE_AI_AGENT=true
AI_AGENT_MAX_ITERATIONS=10
```

#### Email Notifications

For Gmail, generate an App Password: https://myaccount.google.com/apppasswords

```bash
# .env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=true

NOTIFICATION_EMAIL_FROM=pentest-bot@company.com
NOTIFICATION_EMAIL_TO=security-team@company.com
```

#### Slack Notifications (Optional)

Get webhook URL: https://api.slack.com/messaging/webhooks

```bash
# .env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### 3. Test the Features

#### Test API Security Scanners

```bash
# Start the backend
cd backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8001
```

Launch a scan via the frontend and watch for **Phase 2.5 - API Security Testing** in the logs.

#### Test AI Agent

```bash
# Make sure ANTHROPIC_API_KEY is set
export ANTHROPIC_API_KEY=sk-ant-api03-xxx
export ENABLE_AI_AGENT=true

# Start scan - AI agent will run automatically
# You can go to sleep 💤 and wake up to completed results!
```

#### Test Notifications

```bash
# Configure email in .env
export SMTP_HOST=smtp.gmail.com
export SMTP_USERNAME=your-email@gmail.com
export SMTP_PASSWORD=your-app-password
export NOTIFICATION_EMAIL_TO=your-email@gmail.com

# Run a scan - you'll get an email when it completes!
```

---

## 📊 Scan Time Estimates (Updated)

With new features included:

### QUICK Mode (20-40 minutes)
- Phase 0: 5-10 min
- Phase 1: 10-15 min
- Phase 2: 5-10 min (reduced payloads)
- **Phase 2.5**: 5-10 min (API Security - NEW!)
- Phase 3: 5 min
- **AI Agent**: 0-15 min (if enabled - NEW!)

### BALANCED Mode (1-2 hours)
- Phase 0: 30-60 min
- Phase 1: 1-2 hours
- Phase 2: 2-4 hours
- **Phase 2.5**: 30-60 min (API Security - NEW!)
- Phase 3: 1-2 hours
- **AI Agent**: 0-30 min (if enabled - NEW!)

### DEEP Mode (4-8 hours)
- Full comprehensive testing
- All payloads, maximum coverage
- **AI Agent**: Up to 2 hours autonomous testing

---

## 🎯 Usage Examples

### Example 1: Standard Scan with AI Agent

```bash
# 1. Configure AI agent
export ANTHROPIC_API_KEY=sk-ant-api03-xxx
export ENABLE_AI_AGENT=true

# 2. Start scan via UI (BALANCED mode)

# 3. Go to sleep 💤

# 4. Wake up to email notification with results!
```

### Example 2: API-Focused Scan

Target a GraphQL or REST API:

```bash
# Scan will automatically detect:
# - JWT tokens in responses
# - GraphQL endpoints
# - MongoDB/NoSQL usage
# - File upload forms

# Then run specialized tests automatically
```

### Example 3: Team Collaboration

```bash
# Configure Slack webhook
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX

# Everyone on the team gets notified when scans complete!
# Share results in your #security channel
```

---

## 🚀 What's Next?

Planned features:
- [ ] Business Logic Testing (race conditions, price manipulation)
- [ ] Session Management Testing
- [ ] Rate Limiting / Account Enumeration
- [ ] Template Injection (SSTI)
- [ ] LDAP Injection
- [ ] XML External Entity (XXE)
- [ ] AI-powered exploit generation
- [ ] Automated report generation with Claude
- [ ] Integration with JIRA/Linear for vulnerability tracking

---

## 📚 Resources

- **Claude AI Documentation**: https://docs.anthropic.com/
- **OWASP API Security Top 10**: https://owasp.org/www-project-api-security/
- **JWT Security Best Practices**: https://tools.ietf.org/html/rfc8725
- **GraphQL Security**: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- **NoSQL Injection**: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection

---

**Happy Hacking! 🎯**
