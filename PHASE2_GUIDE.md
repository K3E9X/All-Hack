# 🤖 Phase 2: Multi-Agent System Guide

**AI-Powered Autonomous Pentesting with Learning**

---

## 🎯 Overview

Phase 2 introduces a **multi-agent architecture** where specialized AI agents work together to perform coordinated security testing. The system **learns from previous scans** to improve over time.

### Key Features:
- ✅ 5 Specialized AI Agents
- ✅ Agent Coordination & Messaging
- ✅ Long-Term Memory System
- ✅ Learning from Past Scans
- ✅ 8 New API Endpoints

---

## 🤖 The Agents

### 1. Orchestrator Agent 🎼
**Role**: Master Coordinator

**Responsibilities:**
- Coordinates workflow between all agents
- Manages scan lifecycle (start → recon → exploit → analyze → report)
- Prioritizes tasks based on findings
- Monitors progress and handles failures
- Decides when to call which agent

**Workflow Phases:**
1. Recon Phase
2. Exploitation Phase
3. Validation Phase
4. Analysis Phase
5. Reporting Phase

---

### 2. Recon Agent 🔍
**Role**: Intelligent Reconnaissance

**Responsibilities:**
- Enumerate endpoints and parameters
- Identify technologies and frameworks
- Discover hidden resources
- Map attack surface
- Prioritize targets based on risk
- Learn from previous scans

**Uses AI For:**
- Tech stack identification
- Smart prioritization
- Attack surface mapping

---

### 3. Exploitation Agent 💥
**Role**: Adaptive Exploitation

**Responsibilities:**
- Generate context-aware payloads
- Test vulnerabilities with intelligent fuzzing
- Adapt payloads based on WAF detection
- Chain exploits for complex attacks
- Learn from successful/failed attempts

**Features:**
- AI-powered payload generation
- WAF bypass techniques
- Exploit chaining
- Learning from failures

---

### 4. Analysis Agent 🧠
**Role**: Deep Analysis & Correlation

**Responsibilities:**
- Correlate vulnerabilities across different endpoints
- Identify attack chains and escalation paths
- Assess business impact
- Prioritize remediation
- Generate risk scores

**Capabilities:**
- Vulnerability correlation
- Attack chain identification
- Risk assessment
- Remediation prioritization

---

### 5. Reporting Agent 📄
**Role**: Report Generation

**Responsibilities:**
- Generate executive summaries
- Create technical reports
- Produce compliance reports (PCI-DSS, OWASP, etc.)
- Generate remediation roadmaps
- Export in multiple formats

**Report Types:**
- Executive Summary (for C-level)
- Technical Report (detailed findings)
- Compliance Report (OWASP, PCI-DSS)
- Remediation Roadmap (phased approach)

---

## 📚 Memory System

### Scan Memory
**Purpose**: Learn from historical scans

**Stores:**
- Target information (URL, domain)
- Technologies detected
- Vulnerabilities found
- Successful payloads
- Failed payloads
- Scan duration

**Benefits:**
- Faster scans on similar targets
- Reuse successful payloads
- Avoid known failures
- Smart prioritization

---

### Vector Memory
**Purpose**: Semantic search (Phase 3: will upgrade to pgvector)

**Current**: Simple JSON-based storage
**Future**: PostgreSQL + pgvector for production-grade semantic search

**Use Cases:**
- Find similar vulnerabilities
- Recommend attack vectors
- Learn patterns

---

## 🚀 API Endpoints

### 1. Start Multi-Agent Scan
```bash
POST /api/v1/agents/scan

# Body
{
  "target_url": "http://example.com",
  "mode": "black_box"
}

# Response
{
  "scan_id": "scan_123",
  "message": "Multi-agent scan started",
  "workflow": { ... },
  "similar_scans_found": 2,
  "learning_enabled": true,
  "agents": {
    "orchestrator": "coordinating",
    "recon": "pending",
    ...
  }
}
```

---

### 2. Get Workflow Status
```bash
GET /api/v1/agents/scan/{scan_id}/workflow

# Response
{
  "scan_id": "scan_123",
  "workflow": {
    "current_phase": "recon",
    "status": "in_progress",
    "findings_count": 5,
    "errors_count": 0,
    "phases": {
      "recon": {"status": "in_progress", "agent": "recon"},
      "exploitation": {"status": "pending", "agent": "exploitation"},
      ...
    }
  },
  "agents": { ... }
}
```

---

### 3. Execute Agent Task
```bash
POST /api/v1/agents/{agent_id}/task

# Body
{
  "type": "enumerate_endpoints",
  "target_url": "http://example.com"
}

# Response
{
  "agent_id": "recon",
  "task_type": "enumerate_endpoints",
  "result": { ... }
}
```

---

### 4. Get All Agents Status
```bash
GET /api/v1/agents/status

# Response
{
  "total_agents": 5,
  "agents": {
    "orchestrator": {
      "agent_id": "orchestrator",
      "capabilities": ["orchestration"],
      "queue_size": 0,
      "state": { ... }
    },
    ...
  },
  "coordinator_active": true
}
```

---

### 5. Get Memory Statistics
```bash
GET /api/v1/memory/stats

# Response
{
  "scan_memory": {
    "total_scans": 15,
    "unique_domains": 8,
    "total_vulnerabilities": 42,
    "most_common_vulnerabilities": [
      {"type": "sql_injection", "count": 12},
      {"type": "xss", "count": 8}
    ]
  },
  "vector_memory": {
    "total_vectors": 150,
    "implementation": "JSON (Phase 2)"
  },
  "learning_enabled": true
}
```

---

### 6. Find Similar Scans
```bash
GET /api/v1/memory/similar?target_url=http://example.com&limit=5

# Response
{
  "target_url": "http://example.com",
  "similar_scans_found": 3,
  "similar_scans": [
    {
      "scan_id": "scan_001",
      "target_domain": "example.com",
      "technologies": ["nginx", "php"],
      "vulnerabilities_found": 8,
      "timestamp": "2025-11-20T10:30:00"
    },
    ...
  ]
}
```

---

### 7. Get Successful Payloads
```bash
GET /api/v1/memory/payloads/{vuln_type}?technology=php

# Response
{
  "vulnerability_type": "sql_injection",
  "technology": "php",
  "successful_payloads": [
    {
      "payload": "' OR 1=1--",
      "success_rate": 0.85,
      "target_count": 12
    },
    ...
  ],
  "count": 5
}
```

---

### 8. Store Scan in Memory
```bash
POST /api/v1/memory/store/{scan_id}

# Response
{
  "scan_id": "scan_123",
  "message": "Scan stored in memory",
  "memory_enabled": true
}
```

---

## 💡 Usage Examples

### Example 1: Multi-Agent Scan Workflow

```bash
# 1. Start multi-agent scan
SCAN_RESPONSE=$(curl -X POST http://localhost:8000/api/v1/agents/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://testphp.vulnweb.com", "mode": "black_box"}')

SCAN_ID=$(echo $SCAN_RESPONSE | jq -r '.scan_id')

# 2. Monitor workflow status
while true; do
  STATUS=$(curl -s http://localhost:8000/api/v1/agents/scan/$SCAN_ID/workflow | jq -r '.workflow.status')
  PHASE=$(curl -s http://localhost:8000/api/v1/agents/scan/$SCAN_ID/workflow | jq -r '.workflow.current_phase')

  echo "Status: $STATUS | Phase: $PHASE"

  [ "$STATUS" = "completed" ] && break
  sleep 5
done

# 3. Get final results
curl http://localhost:8000/api/v1/scans/$SCAN_ID

# 4. Store in memory for learning
curl -X POST http://localhost:8000/api/v1/memory/store/$SCAN_ID
```

---

### Example 2: Using Memory to Optimize Scans

```python
import httpx

API_BASE = "http://localhost:8000/api/v1"

async def smart_scan(target_url: str):
    async with httpx.AsyncClient() as client:
        # 1. Check memory for similar scans
        similar_response = await client.get(
            f"{API_BASE}/memory/similar",
            params={"target_url": target_url, "limit": 3}
        )

        similar = similar_response.json()
        print(f"Found {similar['similar_scans_found']} similar scans")

        # 2. Get successful payloads from memory
        if similar['similar_scans_found'] > 0:
            techs = similar['similar_scans'][0]['technologies']

            for tech in techs:
                payloads_response = await client.get(
                    f"{API_BASE}/memory/payloads/sql_injection",
                    params={"technology": tech}
                )

                payloads = payloads_response.json()
                print(f"Found {payloads['count']} successful payloads for {tech}")

        # 3. Start optimized scan
        scan_response = await client.post(
            f"{API_BASE}/agents/scan",
            json={"target_url": target_url, "mode": "black_box"}
        )

        return scan_response.json()
```

---

## 🏗️ Architecture

### Agent Communication

```
┌─────────────────────────────────────┐
│     Agent Coordinator               │
│  (Routes messages between agents)   │
└──────────────┬──────────────────────┘
               │
       ┌───────┴───────┐
       │               │
┌──────▼──────┐  ┌────▼─────────┐
│ Orchestrator│  │  Recon Agent  │
│   Agent     │  │               │
└──────┬──────┘  └────┬──────────┘
       │              │
       │   Messages   │
       ▼              ▼
┌─────────────┐  ┌──────────────┐
│Exploitation │  │Analysis Agent│
│   Agent     │  │              │
└─────────────┘  └──────────────┘
       │
       ▼
┌──────────────┐
│Reporting     │
│ Agent        │
└──────────────┘
```

### Workflow Example

```
User Request
     │
     ▼
Orchestrator ──► Recon Agent ──► Discovery Phase
     │                             (endpoints, tech stack)
     ▼
Orchestrator ──► Exploitation ──► Testing Phase
     │           Agent            (payloads, fuzzing)
     ▼
Orchestrator ──► Validation  ──► Confirmation Phase
     │           (Phase 1)       (PoC testing)
     ▼
Orchestrator ──► Analysis    ──► Correlation Phase
     │           Agent           (attack chains, impact)
     ▼
Orchestrator ──► Reporting   ──► Report Generation
     │           Agent           (executive, technical)
     ▼
   Results + Stored in Memory
```

---

## 🚀 Getting Started

### 1. Start Backend
```bash
cd backend
python -m uvicorn app.main:app --reload
```

### 2. Run Multi-Agent Scan
```bash
curl -X POST http://localhost:8000/api/v1/agents/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://testphp.vulnweb.com",
    "mode": "black_box"
  }'
```

### 3. Monitor Progress
```bash
# Get workflow status
curl http://localhost:8000/api/v1/agents/scan/{scan_id}/workflow

# Get agent states
curl http://localhost:8000/api/v1/agents/status

# Get memory stats
curl http://localhost:8000/api/v1/memory/stats
```

---

## 📊 Benefits Over Phase 1

| Feature | Phase 1 | Phase 2 |
|---------|---------|---------|
| **Scanning** | Single-threaded | Multi-agent parallel |
| **Learning** | No memory | Learns from past scans |
| **Payloads** | Static | AI-generated, adaptive |
| **Analysis** | Single-pass | Correlation & chaining |
| **Reporting** | Basic | Executive + Technical |
| **Optimization** | None | Uses historical data |

---

## 🎯 Next Steps

After Phase 2:
- **Phase 3**: PostgreSQL + pgvector for production-grade memory
- **External Tools**: SQLMap, Nuclei, Burp, Metasploit integration
- **CI/CD**: GitHub Actions integration
- **Monitoring**: Prometheus + Grafana

---

## 📚 Documentation

- **Phase 1**: See `OLLAMA_SETUP.md`, `CHAT_GUIDE.md`, `POC_VALIDATION_GUIDE.md`
- **Phase 2**: This guide
- **API Docs**: http://localhost:8000/docs

---

**🎉 Phase 2 Complete! Autonomous AI agents are ready!**

Cost: $0 (runs locally with Ollama)
