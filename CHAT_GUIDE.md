# 💬 Chat Interface Guide - Conversational Pentesting

## 🎯 What is it?

**Interactive chat interface** that lets you talk about scan results in natural language. Ask questions, get exploitation guidance, generate reports - all in real-time conversation.

**Think ChatGPT, but for pentesting.** 🔥

---

## ✨ Features

- 💬 **Natural language queries** - Ask questions in plain English
- ⚡ **Real-time streaming** - Responses appear as they're generated
- 🧠 **Context-aware** - Knows everything about your scan
- 📝 **Message history** - Maintains conversation context
- 🔒 **100% local** - Uses Ollama (no cloud, $0 cost)
- 🚀 **WebSocket** - Low latency, real-time updates

---

## 🚀 Quick Start

### 1. Start Ollama (if not already running)

```bash
ollama serve
```

### 2. Run a scan

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://testphp.vulnweb.com",
    "mode": "black_box",
    "scan_depth": "quick"
  }'

# Save the scan_id
```

### 3. Create chat session

```bash
curl -X POST http://localhost:8000/api/v1/chat/{scan_id}/session
```

### 4. Connect to WebSocket

```javascript
// JavaScript example
const ws = new WebSocket('ws://localhost:8000/ws/chat/scan_123');

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);

    if (data.type === 'assistant_chunk') {
        // Streaming response chunk
        console.log(data.content);
    } else if (data.type === 'assistant_complete') {
        // Response complete
        console.log('Done!');
    }
};

// Send a message
ws.send(JSON.stringify({
    message: "What are the critical vulnerabilities?"
}));
```

---

## 📡 API Endpoints

### WebSocket Endpoint

```
WS /ws/chat/{scan_id}
```

**Connect and chat in real-time.**

#### Message Format:

**Send (Client → Server)**:
```json
{
    "message": "Your question here"
}
```

Or just plain text:
```
"Your question here"
```

**Receive (Server → Client)**:
```json
// System message (welcome)
{
    "type": "system",
    "content": "Chat session started..."
}

// User message echo
{
    "type": "user",
    "content": "Your question"
}

// Assistant response chunk (streaming)
{
    "type": "assistant_chunk",
    "content": "Part of "
}

// Response complete
{
    "type": "assistant_complete"
}

// Error
{
    "type": "error",
    "content": "Error message"
}
```

---

### REST API (Non-Streaming)

For simple requests without WebSocket complexity.

#### Create Session
```bash
POST /api/v1/chat/{scan_id}/session
```

**Response**:
```json
{
    "scan_id": "abc123",
    "session_created": "2025-11-27T10:00:00",
    "websocket_url": "ws://localhost:8000/ws/chat/abc123"
}
```

#### Send Message (Non-Streaming)
```bash
POST /api/v1/chat/{scan_id}/message?message=What+are+the+critical+issues
```

**Response**:
```json
{
    "scan_id": "abc123",
    "user_message": "What are the critical issues?",
    "assistant_response": "I found 3 critical vulnerabilities:\n1. SQL Injection..."
}
```

#### Get History
```bash
GET /api/v1/chat/{scan_id}/history?limit=20
```

**Response**:
```json
{
    "scan_id": "abc123",
    "message_count": 10,
    "messages": [
        {
            "role": "user",
            "content": "What are the critical issues?",
            "timestamp": "2025-11-27T10:00:00"
        },
        {
            "role": "assistant",
            "content": "I found 3 critical vulnerabilities...",
            "timestamp": "2025-11-27T10:00:05"
        }
    ]
}
```

#### Delete Session
```bash
DELETE /api/v1/chat/{scan_id}
```

---

## 💡 Example Questions

### Security Analysis
```
"What are the critical vulnerabilities?"
"Which vulnerabilities should I fix first?"
"How severe is the SQL injection?"
"What's the business impact of these issues?"
```

### Exploitation Guidance
```
"How do I exploit the XSS vulnerability?"
"Show me how to test the CSRF vulnerability"
"What tools should I use for the SQL injection?"
"Give me a step-by-step exploitation guide"
```

### Remediation
```
"How do I fix the SQL injection?"
"Generate a code fix for the XSS vulnerability"
"What's the remediation for CSRF?"
"Show me secure code examples"
```

### Reports & Summaries
```
"Summarize the scan results"
"Create an executive summary"
"What are the common patterns in these vulnerabilities?"
"Generate a prioritized fix list"
```

### Technical Details
```
"Explain the root cause of the SQL injection"
"What's the attack chain for these vulnerabilities?"
"How does the SSRF vulnerability work?"
"What makes this vulnerability critical?"
```

---

## 🧪 Testing

### Python Test Script

```bash
# Install websockets
pip install websockets

# Run test
python test_chat.py {scan_id}
```

The test script will:
1. Connect to WebSocket
2. Ask 3 predefined questions
3. Display streaming responses
4. Show complete conversation

### Manual Testing (curl)

```bash
# Non-streaming endpoint
curl -X POST "http://localhost:8000/api/v1/chat/{scan_id}/message?message=What+vulnerabilities+did+you+find"
```

### Browser Console Test

```javascript
// Open browser console on http://localhost:8000
const ws = new WebSocket('ws://localhost:8000/ws/chat/your_scan_id');

ws.onopen = () => {
    console.log('Connected!');
    ws.send('What are the critical vulnerabilities?');
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log(data);
};
```

---

## 🎨 Example Conversation

```
💬 User: What did you find in the scan?

🤖 Assistant: I analyzed http://testphp.vulnweb.com and found:

**Critical Issues (2)**:
1. SQL Injection in /search endpoint
   - Exploitable with: 1' OR '1'='1
   - Impact: Full database access

2. Unrestricted File Upload
   - Impact: Remote code execution possible

**High Issues (3)**:
1. Cross-Site Scripting (XSS) in /comment
2. Missing CSRF protection
3. Weak session management

Total: 2 critical, 3 high, 5 medium issues

---

💬 User: How do I exploit the SQL injection?

🤖 Assistant: Here's a step-by-step exploitation guide for the SQL injection:

**Step 1: Confirm the vulnerability**
```bash
curl "http://testphp.vulnweb.com/search?q=1' OR '1'='1"
```
Expected: Returns all records (bypasses WHERE clause)

**Step 2: Extract database version**
```bash
curl "http://testphp.vulnweb.com/search?q=1' UNION SELECT @@version--"
```

**Step 3: Enumerate tables**
```bash
# Using SQLMap (automated)
sqlmap -u "http://testphp.vulnweb.com/search?q=test" --dbs
```

**Step 4: Extract data**
```bash
sqlmap -u "http://testphp.vulnweb.com/search?q=test" -D database_name --dump
```

⚠️ **Note**: Only test on applications you own or have authorization to test.

---

💬 User: Generate a fix for this

🤖 Assistant: Here's the secure code fix:

**BEFORE (Vulnerable)**:
```python
# search.py
def search(request):
    query = request.GET.get('q')
    results = db.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")
    return results
```

**AFTER (Secure)**:
```python
# search.py
def search(request):
    query = request.GET.get('q')
    # Use parameterized query
    results = db.execute(
        "SELECT * FROM products WHERE name LIKE %s",
        [f'%{query}%']
    )
    return results
```

**Key Changes**:
- Removed string concatenation
- Used parameterized query with placeholder %s
- Database driver now escapes the input safely

**Test the fix**:
```bash
# This should now fail:
curl "http://testphp.vulnweb.com/search?q=1' OR '1'='1"
```
```

---

## 🔧 Advanced Usage

### Streaming Responses (JavaScript Frontend)

```javascript
class ChatClient {
    constructor(scanId) {
        this.scanId = scanId;
        this.ws = null;
        this.currentResponse = "";
    }

    connect() {
        this.ws = new WebSocket(`ws://localhost:8000/ws/chat/${this.scanId}`);

        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleMessage(data);
        };
    }

    handleMessage(data) {
        switch(data.type) {
            case 'system':
                console.log('System:', data.content);
                break;

            case 'assistant_chunk':
                // Append chunk to current response
                this.currentResponse += data.content;
                this.updateUI(this.currentResponse);
                break;

            case 'assistant_complete':
                // Response done
                console.log('Response complete');
                this.currentResponse = "";
                break;

            case 'error':
                console.error('Error:', data.content);
                break;
        }
    }

    sendMessage(message) {
        this.ws.send(JSON.stringify({ message }));
    }

    updateUI(content) {
        // Update your UI with streaming content
        document.getElementById('response').textContent = content;
    }
}

// Usage
const chat = new ChatClient('scan_123');
chat.connect();
chat.sendMessage('What are the critical vulnerabilities?');
```

### Python Client

```python
import asyncio
import websockets
import json

async def chat_with_scan(scan_id: str):
    uri = f"ws://localhost:8000/ws/chat/{scan_id}"

    async with websockets.connect(uri) as ws:
        # Receive welcome
        welcome = await ws.recv()
        print(json.loads(welcome)['content'])

        while True:
            # Get user input
            question = input("\nYou: ")
            if question.lower() == 'quit':
                break

            # Send message
            await ws.send(json.dumps({"message": question}))

            # Receive streaming response
            print("Assistant: ", end="", flush=True)

            while True:
                msg = await ws.recv()
                data = json.loads(msg)

                if data['type'] == 'assistant_chunk':
                    print(data['content'], end="", flush=True)
                elif data['type'] == 'assistant_complete':
                    print()  # New line
                    break

asyncio.run(chat_with_scan('your_scan_id'))
```

---

## 🛠️ Troubleshooting

### Problem: "Chat agent not available"

**Solution**:
```bash
# Start Ollama
ollama serve

# Pull model
ollama pull llama3.2

# Verify
curl http://localhost:8000/api/v1/ai/status
```

### Problem: WebSocket connection refused

**Solution**:
```bash
# Check if backend is running
curl http://localhost:8000/health

# Check WebSocket support
# Make sure you're using ws:// not wss:// for local dev
```

### Problem: Slow responses

**Solution**:
```bash
# Use faster model
ollama pull mistral

# Or reduce context in prompts
# Edit backend/app/intelligence/prompts/chat_prompts.py
```

### Problem: Out of context errors

**Solution**:
The chat maintains last 5 messages in history. For longer conversations, the agent automatically summarizes context. If you need to start fresh:

```bash
# Clear chat session
curl -X DELETE http://localhost:8000/api/v1/chat/{scan_id}

# Create new session
curl -X POST http://localhost:8000/api/v1/chat/{scan_id}/session
```

---

## 📊 Performance

| Metric | Value |
|--------|-------|
| **Response Time** | 1-3 seconds (first token) |
| **Streaming Latency** | 50-100ms per chunk |
| **Context Window** | ~4000 tokens |
| **Memory per Session** | ~50MB |
| **Concurrent Users** | 10+ (limited by Ollama) |

---

## 🔐 Security Notes

1. **Local Only**: Chat runs locally via Ollama
2. **No Cloud**: No data sent to external APIs
3. **Privacy**: Suitable for confidential pentests
4. **Authorization**: Chat inherits scan permissions
5. **Rate Limiting**: Consider adding for production

---

## 🚀 Next Steps

**Now that chat is working, you can**:

1. ✅ Ask questions about any scan
2. ✅ Get real-time exploitation guidance
3. ✅ Generate custom reports via conversation
4. ✅ Learn from the AI analyst

**Want more?**
- Build a frontend chat UI (React component)
- Add voice input/output
- Multi-scan conversations
- Custom personas (aggressive tester, compliance auditor, etc.)

---

## 📚 See Also

- `OLLAMA_SETUP.md` - Ollama installation guide
- `AI_ROADMAP.md` - Future AI features
- `test_chat.py` - Test script
- `/ws/chat/{scan_id}` - WebSocket endpoint

---

**🎉 Start chatting with your scan results now!** 💬🔥
