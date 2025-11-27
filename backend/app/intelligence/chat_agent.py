"""
Chat Agent - Conversational pentesting assistant
"""
import logging
from typing import Optional, List, Dict, AsyncGenerator
from datetime import datetime

from app.models import ScanResult
from app.intelligence.ollama_client import get_ollama_client, OllamaClient
from app.intelligence.prompts.chat_prompts import (
    CHAT_SYSTEM_PROMPT,
    format_chat_context
)

logger = logging.getLogger(__name__)

class ChatMessage:
    """Chat message"""
    def __init__(self, role: str, content: str, timestamp: Optional[datetime] = None):
        self.role = role  # 'user' or 'assistant'
        self.content = content
        self.timestamp = timestamp or datetime.utcnow()

    def to_dict(self):
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp.isoformat()
        }

class ChatSession:
    """Chat session with history"""
    def __init__(self, scan_id: str, scan_result: ScanResult):
        self.scan_id = scan_id
        self.scan_result = scan_result
        self.messages: List[ChatMessage] = []
        self.created_at = datetime.utcnow()

    def add_message(self, role: str, content: str):
        """Add message to history"""
        msg = ChatMessage(role, content)
        self.messages.append(msg)
        return msg

    def get_history(self, limit: int = 10) -> List[Dict]:
        """Get recent message history"""
        recent = self.messages[-limit:] if len(self.messages) > limit else self.messages
        return [msg.to_dict() for msg in recent]

    def clear_history(self):
        """Clear message history"""
        self.messages.clear()

class ChatAgent:
    """
    Conversational agent for pentesting

    Features:
    - Context-aware responses (knows about scan results)
    - Message history
    - Streaming responses
    - Specialized prompts for security questions
    """

    def __init__(self, ollama_client: Optional[OllamaClient] = None):
        self.ollama = ollama_client or get_ollama_client()
        self.sessions: Dict[str, ChatSession] = {}
        self.available = False

    async def initialize(self) -> bool:
        """Check if agent is ready"""
        self.available = await self.ollama.check_available()
        if self.available:
            logger.info("✅ Chat Agent initialized")
        else:
            logger.warning("⚠️  Chat Agent unavailable - Ollama not running")
        return self.available

    def create_session(self, scan_id: str, scan_result: ScanResult) -> ChatSession:
        """Create new chat session"""
        session = ChatSession(scan_id, scan_result)
        self.sessions[scan_id] = session
        logger.info(f"💬 Chat session created for scan {scan_id}")
        return session

    def get_session(self, scan_id: str) -> Optional[ChatSession]:
        """Get existing chat session"""
        return self.sessions.get(scan_id)

    async def chat(
        self,
        scan_id: str,
        user_message: str,
        stream: bool = True
    ) -> AsyncGenerator[str, None]:
        """
        Chat with streaming response

        Args:
            scan_id: Scan ID for context
            user_message: User's message
            stream: Enable streaming

        Yields:
            Response chunks (if streaming) or complete response
        """
        if not self.available:
            yield "❌ Chat agent not available. Please install Ollama: https://ollama.ai"
            return

        # Get or create session
        session = self.get_session(scan_id)
        if not session:
            yield "❌ Chat session not found. Please create a session first."
            return

        # Add user message to history
        session.add_message("user", user_message)

        try:
            # Build context-aware prompt
            context_prompt = format_chat_context(session.scan_result, user_message)

            # Build conversation history for LLM
            messages = [
                {"role": "system", "content": CHAT_SYSTEM_PROMPT}
            ]

            # Add recent history (last 5 messages)
            for msg in session.messages[-5:]:
                messages.append({
                    "role": msg.role,
                    "content": msg.content
                })

            # Replace last user message with context-enriched version
            messages[-1]["content"] = context_prompt

            # Get response from LLM
            if stream:
                # Streaming response
                assistant_message = ""
                async for chunk in self._chat_stream(messages):
                    assistant_message += chunk
                    yield chunk

                # Save complete assistant response
                session.add_message("assistant", assistant_message)

            else:
                # Non-streaming
                response = await self.ollama.chat(messages, stream=False)
                session.add_message("assistant", response)
                yield response

        except Exception as e:
            error_msg = f"❌ Chat error: {str(e)}"
            logger.error(error_msg)
            yield error_msg

    async def _chat_stream(self, messages: List[Dict]) -> AsyncGenerator[str, None]:
        """Stream chat response from Ollama"""
        import httpx
        import json

        payload = {
            "model": self.ollama.config.model,
            "messages": messages,
            "stream": True,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
            }
        }

        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream(
                "POST",
                f"{self.ollama.config.base_url}/api/chat",
                json=payload
            ) as response:
                async for line in response.aiter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            if "message" in data:
                                content = data["message"].get("content", "")
                                if content:
                                    yield content
                        except json.JSONDecodeError:
                            continue

    async def ask_quick(
        self,
        scan_id: str,
        question: str
    ) -> str:
        """
        Quick question without streaming (for API calls)

        Args:
            scan_id: Scan ID
            question: User question

        Returns:
            Complete response
        """
        response_parts = []
        async for chunk in self.chat(scan_id, question, stream=False):
            response_parts.append(chunk)

        return "".join(response_parts)

    def get_session_history(self, scan_id: str, limit: int = 20) -> List[Dict]:
        """Get chat history for session"""
        session = self.get_session(scan_id)
        if not session:
            return []
        return session.get_history(limit)

    def clear_session(self, scan_id: str) -> bool:
        """Clear chat session"""
        session = self.get_session(scan_id)
        if session:
            session.clear_history()
            logger.info(f"🗑️  Chat history cleared for scan {scan_id}")
            return True
        return False

    def delete_session(self, scan_id: str) -> bool:
        """Delete chat session"""
        if scan_id in self.sessions:
            del self.sessions[scan_id]
            logger.info(f"🗑️  Chat session deleted for scan {scan_id}")
            return True
        return False


# Singleton instance
_chat_agent: Optional[ChatAgent] = None

async def get_chat_agent() -> ChatAgent:
    """Get or create chat agent singleton"""
    global _chat_agent
    if _chat_agent is None:
        _chat_agent = ChatAgent()
        await _chat_agent.initialize()
    return _chat_agent
