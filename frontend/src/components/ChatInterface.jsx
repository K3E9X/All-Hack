import { useState, useEffect, useRef } from 'react';
import { PaperAirplaneIcon, ChatBubbleLeftRightIcon } from '@heroicons/react/24/outline';

const WS_BASE = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

export default function ChatInterface({ scanId }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(false);
  const ws = useRef(null);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    // Connect to WebSocket
    const websocket = new WebSocket(`${WS_BASE}/ws/chat/${scanId}`);

    websocket.onopen = () => {
      console.log('WebSocket connected');
      setConnected(true);
      setMessages((prev) => [
        ...prev,
        {
          type: 'system',
          content: `💬 Chat session started for scan ${scanId}\n\nAsk me anything about the scan results!`,
          timestamp: new Date(),
        },
      ]);
    };

    websocket.onmessage = (event) => {
      const data = JSON.parse(event.data);

      if (data.type === 'assistant_chunk') {
        // Streaming chunk from AI
        setMessages((prev) => {
          const last = prev[prev.length - 1];
          if (last && last.type === 'assistant' && !last.complete) {
            // Append to existing message
            return [
              ...prev.slice(0, -1),
              { ...last, content: last.content + data.content },
            ];
          } else {
            // Start new message
            return [
              ...prev,
              {
                type: 'assistant',
                content: data.content,
                timestamp: new Date(),
                complete: false,
              },
            ];
          }
        });
      } else if (data.type === 'assistant_complete') {
        // Mark message as complete
        setMessages((prev) => {
          const last = prev[prev.length - 1];
          if (last && last.type === 'assistant') {
            return [...prev.slice(0, -1), { ...last, complete: true }];
          }
          return prev;
        });
        setLoading(false);
      } else if (data.type === 'error') {
        setMessages((prev) => [
          ...prev,
          {
            type: 'error',
            content: `Error: ${data.content}`,
            timestamp: new Date(),
          },
        ]);
        setLoading(false);
      }
    };

    websocket.onerror = (error) => {
      console.error('WebSocket error:', error);
      setConnected(false);
    };

    websocket.onclose = () => {
      console.log('🔌 WebSocket disconnected');
      setConnected(false);
    };

    ws.current = websocket;

    return () => {
      websocket.close();
    };
  }, [scanId]);

  const sendMessage = () => {
    if (!input.trim() || !connected || loading) return;

    // Add user message
    setMessages((prev) => [
      ...prev,
      {
        type: 'user',
        content: input,
        timestamp: new Date(),
      },
    ]);

    // Send to backend
    ws.current.send(JSON.stringify({ message: input }));

    setInput('');
    setLoading(true);
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const quickQuestions = [
    'What are the critical vulnerabilities?',
    'How can I exploit the SQL injection?',
    'What should I fix first?',
    'Explain the XSS vulnerability',
    'Generate a remediation plan',
  ];

  return (
    <div className="flex flex-col h-full bg-gray-800 rounded-lg border border-gray-700">
      {/* Header */}
      <div className="p-4 border-b border-gray-700 flex items-center justify-between">
        <div className="flex items-center">
          <ChatBubbleLeftRightIcon className="w-6 h-6 mr-2 text-purple-400" />
          <h3 className="text-lg font-semibold">AI Chat Assistant</h3>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`}
          />
          <span className="text-sm text-gray-400">
            {connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg, idx) => (
          <div
            key={idx}
            className={`flex ${msg.type === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-[80%] rounded-lg p-3 ${
                msg.type === 'user'
                  ? 'bg-blue-600 text-white'
                  : msg.type === 'assistant'
                  ? 'bg-gray-700 text-white'
                  : msg.type === 'error'
                  ? 'bg-red-600 text-white'
                  : 'bg-gray-600 text-gray-200'
              }`}
            >
              <div className="whitespace-pre-wrap">{msg.content}</div>
              <div className="text-xs opacity-70 mt-1">
                {msg.timestamp.toLocaleTimeString()}
              </div>
            </div>
          </div>
        ))}
        {loading && (
          <div className="flex justify-start">
            <div className="bg-gray-700 rounded-lg p-3">
              <div className="flex gap-1">
                <span className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" />
                <span className="w-2 h-2 bg-gray-400 rounded-full animate-bounce delay-100" />
                <span className="w-2 h-2 bg-gray-400 rounded-full animate-bounce delay-200" />
              </div>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Quick Questions */}
      {messages.length <= 1 && (
        <div className="p-4 border-t border-gray-700">
          <p className="text-sm text-gray-400 mb-2">Quick questions:</p>
          <div className="flex flex-wrap gap-2">
            {quickQuestions.map((q, idx) => (
              <button
                key={idx}
                onClick={() => setInput(q)}
                className="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm transition-colors"
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Input */}
      <div className="p-4 border-t border-gray-700">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Ask about the scan results..."
            disabled={!connected || loading}
            className="flex-1 px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:border-purple-500 disabled:opacity-50"
          />
          <button
            onClick={sendMessage}
            disabled={!input.trim() || !connected || loading}
            className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <PaperAirplaneIcon className="w-5 h-5" />
          </button>
        </div>
      </div>
    </div>
  );
}
