import { useState, useRef, useEffect } from 'react';
import { Send, Bot, User, Loader } from 'lucide-react';
import clsx from 'clsx';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

export default function ChatView() {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: 'Hello! I can help you analyze scan results, explain vulnerabilities, or suggest exploitation strategies. What would you like to know?'
    }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [scanContext, setScanContext] = useState(null);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const sendMessage = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage = { role: 'user', content: input };
    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      const response = await fetch(`${API_URL}/api/v1/chat/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: input,
          context: scanContext
        })
      });

      if (response.ok) {
        const data = await response.json();
        setMessages(prev => [...prev, {
          role: 'assistant',
          content: data.response || 'I apologize, but I could not generate a response.'
        }]);
      } else {
        throw new Error('Failed to get response');
      }
    } catch (error) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: 'Sorry, I encountered an error. Please check that the backend is running and try again.'
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <header className="flex items-center justify-between px-4 h-10 border-b border-border bg-surface">
        <h1 className="text-xs font-medium tracking-wider uppercase">CHAT</h1>
        <span className="text-xs text-secondary font-mono">
          {scanContext ? `CTX:${scanContext}` : 'NO CTX'}
        </span>
      </header>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 bg-background">
        <div className="max-w-3xl mx-auto space-y-4">
          {messages.map((message, i) => (
            <div
              key={i}
              className={clsx(
                'flex gap-3',
                message.role === 'user' && 'justify-end'
              )}
            >
              {message.role === 'assistant' && (
                <div className="w-6 h-6 border border-accent flex items-center justify-center shrink-0">
                  <Bot className="w-3 h-3 text-accent" />
                </div>
              )}

              <div className={clsx(
                'max-w-[80%] p-3 text-sm',
                message.role === 'user'
                  ? 'bg-accent text-background border border-accent'
                  : 'bg-surface border border-border'
              )}>
                <p className="whitespace-pre-wrap">{message.content}</p>
              </div>

              {message.role === 'user' && (
                <div className="w-6 h-6 border border-border flex items-center justify-center shrink-0">
                  <User className="w-3 h-3 text-secondary" />
                </div>
              )}
            </div>
          ))}

          {isLoading && (
            <div className="flex gap-3">
              <div className="w-6 h-6 border border-accent flex items-center justify-center shrink-0">
                <Bot className="w-3 h-3 text-accent" />
              </div>
              <div className="p-3 bg-surface border border-border">
                <Loader className="w-4 h-4 animate-spin text-secondary" />
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>
      </div>

      {/* Input */}
      <div className="p-3 border-t border-border bg-surface">
        <div className="max-w-3xl mx-auto flex gap-2">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Ask about vulnerabilities, exploitation, scan results..."
            rows={1}
            className="flex-1 px-3 py-2 border border-border bg-background resize-none text-sm"
            style={{ minHeight: '40px', maxHeight: '160px' }}
          />
          <button
            onClick={sendMessage}
            disabled={!input.trim() || isLoading}
            className="btn btn-primary px-3 disabled:opacity-50"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
