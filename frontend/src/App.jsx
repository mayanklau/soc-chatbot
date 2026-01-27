import React, { useState, useRef, useEffect } from 'react';
import { 
  Send, Shield, AlertTriangle, Search, Terminal, 
  Activity, Zap, Database, Clock, Bot, User,
  ChevronRight, RefreshCw, Cpu, Network
} from 'lucide-react';

// API Configuration
const API_BASE = '/api';

// Agent type mappings
const AGENT_INFO = {
  orchestrator: { name: 'Orchestrator', color: 'text-purple-400', bg: 'bg-purple-500/20' },
  query: { name: 'Query', color: 'text-cyan-400', bg: 'bg-cyan-500/20', icon: Search },
  triage: { name: 'Triage', color: 'text-orange-400', bg: 'bg-orange-500/20', icon: AlertTriangle },
  threat_intel: { name: 'Threat Intel', color: 'text-red-400', bg: 'bg-red-500/20', icon: Shield },
  incident_response: { name: 'IR', color: 'text-green-400', bg: 'bg-green-500/20', icon: Zap }
};

// Generate session ID
const generateSessionId = () => {
  return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
};

// Message Component
const Message = ({ message, isUser }) => {
  const formatContent = (content) => {
    // Simple markdown-like formatting
    return content
      .split('\n')
      .map((line, i) => {
        // Headers
        if (line.startsWith('**') && line.endsWith('**')) {
          return <div key={i} className="font-semibold text-white my-2">{line.replace(/\*\*/g, '')}</div>;
        }
        // Bold text inline
        const parts = line.split(/(\*\*[^*]+\*\*)/g);
        return (
          <div key={i} className="my-1">
            {parts.map((part, j) => {
              if (part.startsWith('**') && part.endsWith('**')) {
                return <span key={j} className="font-semibold text-white">{part.replace(/\*\*/g, '')}</span>;
              }
              // Code blocks
              if (part.includes('`')) {
                const codeParts = part.split(/(`[^`]+`)/g);
                return codeParts.map((cp, k) => {
                  if (cp.startsWith('`') && cp.endsWith('`')) {
                    return <code key={k} className="bg-black/30 px-1.5 py-0.5 rounded text-cyan-400 font-mono text-sm">{cp.replace(/`/g, '')}</code>;
                  }
                  return cp;
                });
              }
              return part;
            })}
          </div>
        );
      });
  };

  return (
    <div className={`flex gap-3 mb-4 ${isUser ? 'flex-row-reverse' : ''}`}>
      {/* Avatar */}
      <div className={`flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center ${
        isUser ? 'bg-blue-500/20 border border-blue-500/30' : 'bg-green-500/20 border border-green-500/30'
      }`}>
        {isUser ? (
          <User className="w-5 h-5 text-blue-400" />
        ) : (
          <Bot className="w-5 h-5 text-green-400" />
        )}
      </div>

      {/* Content */}
      <div className={`flex-1 max-w-[80%] ${isUser ? 'text-right' : ''}`}>
        <div className={`inline-block text-left rounded-lg px-4 py-3 ${
          isUser 
            ? 'message-user' 
            : 'message-assistant'
        }`}>
          <div className="text-sm leading-relaxed whitespace-pre-wrap">
            {formatContent(message.content)}
          </div>
        </div>
        
        {/* Metadata */}
        <div className={`mt-1 text-xs text-gray-500 flex items-center gap-2 ${isUser ? 'justify-end' : ''}`}>
          <Clock className="w-3 h-3" />
          {new Date(message.timestamp).toLocaleTimeString()}
          {message.agents && message.agents.length > 0 && (
            <div className="flex gap-1">
              {message.agents.map((agent, i) => {
                const info = AGENT_INFO[agent] || AGENT_INFO.orchestrator;
                return (
                  <span key={i} className={`agent-badge ${info.bg} ${info.color}`}>
                    {info.name}
                  </span>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Typing Indicator
const TypingIndicator = () => (
  <div className="flex gap-3 mb-4">
    <div className="w-10 h-10 rounded-lg bg-green-500/20 border border-green-500/30 flex items-center justify-center">
      <Bot className="w-5 h-5 text-green-400" />
    </div>
    <div className="message-assistant rounded-lg px-4 py-3">
      <div className="flex items-center gap-2">
        <div className="flex gap-1">
          <div className="w-2 h-2 rounded-full bg-green-400 typing-dot" />
          <div className="w-2 h-2 rounded-full bg-green-400 typing-dot" />
          <div className="w-2 h-2 rounded-full bg-green-400 typing-dot" />
        </div>
        <span className="text-sm text-gray-400 ml-2">Agents processing...</span>
      </div>
    </div>
  </div>
);

// Stats Panel
const StatsPanel = ({ stats }) => (
  <div className="grid grid-cols-4 gap-3 mb-4">
    <div className="bg-cyber-surface border border-cyber-border rounded-lg p-3">
      <div className="flex items-center gap-2 mb-1">
        <Database className="w-4 h-4 text-cyan-400" />
        <span className="text-xs text-gray-400">Events</span>
      </div>
      <div className="text-xl font-mono text-cyan-400">{stats.total_events?.toLocaleString() || '—'}</div>
    </div>
    <div className="bg-cyber-surface border border-cyber-border rounded-lg p-3">
      <div className="flex items-center gap-2 mb-1">
        <AlertTriangle className="w-4 h-4 text-orange-400" />
        <span className="text-xs text-gray-400">Open Alerts</span>
      </div>
      <div className="text-xl font-mono text-orange-400">{stats.open_alerts || '—'}</div>
    </div>
    <div className="bg-cyber-surface border border-cyber-border rounded-lg p-3">
      <div className="flex items-center gap-2 mb-1">
        <Zap className="w-4 h-4 text-red-400" />
        <span className="text-xs text-gray-400">Critical</span>
      </div>
      <div className="text-xl font-mono text-red-400">{stats.critical_alerts || '—'}</div>
    </div>
    <div className="bg-cyber-surface border border-cyber-border rounded-lg p-3">
      <div className="flex items-center gap-2 mb-1">
        <Activity className="w-4 h-4 text-green-400" />
        <span className="text-xs text-gray-400">24h Events</span>
      </div>
      <div className="text-xl font-mono text-green-400">{stats.events_last_24h?.toLocaleString() || '—'}</div>
    </div>
  </div>
);

// Quick Actions
const QuickActions = ({ onAction }) => {
  const actions = [
    { label: 'Triage Alerts', query: 'Triage my open alerts', icon: AlertTriangle },
    { label: 'Statistics', query: 'Show me data lake statistics', icon: Database },
    { label: 'Critical Events', query: 'Show me all critical events from today', icon: Zap },
    { label: 'Threat Landscape', query: 'What is the current threat landscape?', icon: Shield }
  ];

  return (
    <div className="flex flex-wrap gap-2 mb-4">
      {actions.map((action, i) => (
        <button
          key={i}
          onClick={() => onAction(action.query)}
          className="flex items-center gap-2 px-3 py-1.5 bg-cyber-surface border border-cyber-border rounded-lg text-sm text-gray-300 hover:border-cyber-accent hover:text-cyber-accent transition-colors"
        >
          <action.icon className="w-4 h-4" />
          {action.label}
        </button>
      ))}
    </div>
  );
};

// Main App Component
export default function App() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [sessionId] = useState(generateSessionId);
  const [stats, setStats] = useState({});
  const [isConnected, setIsConnected] = useState(true);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  // Scroll to bottom
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Fetch stats on mount
  useEffect(() => {
    fetchStats();
    // Add welcome message
    setMessages([{
      id: 'welcome',
      content: `👋 **Welcome to SOC Chatbot**

I'm your AI-powered security operations assistant. I coordinate multiple specialized agents to help you:

🔍 **Query** - Search and analyze security events
🎯 **Triage** - Prioritize alerts and assess threats  
🔐 **Threat Intel** - Enrich IOCs and get threat context
🚨 **Incident Response** - Guide response playbooks

Try asking me something like:
• "Show me open alerts"
• "What do we know about IP 185.220.101.1?"
• "How should I respond to credential theft?"

What would you like to investigate?`,
      timestamp: new Date().toISOString(),
      isUser: false,
      agents: ['orchestrator']
    }]);
  }, []);

  // Fetch statistics
  const fetchStats = async () => {
    try {
      const response = await fetch(`${API_BASE}/data-lake/statistics`);
      if (response.ok) {
        const data = await response.json();
        setStats(data);
        setIsConnected(true);
      }
    } catch (error) {
      console.error('Failed to fetch stats:', error);
      setIsConnected(false);
    }
  };

  // Send message
  const sendMessage = async (messageText) => {
    if (!messageText.trim() || isLoading) return;

    const userMessage = {
      id: Date.now(),
      content: messageText,
      timestamp: new Date().toISOString(),
      isUser: true
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      const response = await fetch(`${API_BASE}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: messageText,
          session_id: sessionId,
          context: {}
        })
      });

      if (!response.ok) throw new Error('Chat request failed');

      const data = await response.json();

      const assistantMessage = {
        id: Date.now() + 1,
        content: data.response,
        timestamp: data.timestamp || new Date().toISOString(),
        isUser: false,
        agents: data.agents_involved || [],
        processingTime: data.processing_time_ms,
        eventsAnalyzed: data.events_analyzed
      };

      setMessages(prev => [...prev, assistantMessage]);
      setIsConnected(true);
    } catch (error) {
      console.error('Chat error:', error);
      setMessages(prev => [...prev, {
        id: Date.now() + 1,
        content: '❌ **Connection Error**\n\nUnable to reach the SOC backend. Please ensure the API server is running on port 8000.',
        timestamp: new Date().toISOString(),
        isUser: false,
        agents: []
      }]);
      setIsConnected(false);
    } finally {
      setIsLoading(false);
      inputRef.current?.focus();
    }
  };

  // Handle form submit
  const handleSubmit = (e) => {
    e.preventDefault();
    sendMessage(input);
  };

  // Handle quick action
  const handleQuickAction = (query) => {
    sendMessage(query);
  };

  return (
    <div className="h-screen flex flex-col bg-cyber-bg grid-pattern">
      {/* Scanlines overlay */}
      <div className="scanlines" />

      {/* Header */}
      <header className="flex-shrink-0 bg-cyber-surface/80 backdrop-blur border-b border-cyber-border px-6 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-green-500 to-cyan-500 flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-white font-mono tracking-tight">SOC CHATBOT</h1>
              <p className="text-xs text-gray-400">Multi-Agent Security Assistant</p>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className={`status-dot ${isConnected ? 'status-online' : 'status-error'}`} />
              <span className="text-xs text-gray-400">{isConnected ? 'Connected' : 'Disconnected'}</span>
            </div>
            <button 
              onClick={fetchStats}
              className="p-2 hover:bg-cyber-border rounded-lg transition-colors"
              title="Refresh Stats"
            >
              <RefreshCw className="w-4 h-4 text-gray-400" />
            </button>
          </div>
        </div>
      </header>

      {/* Main content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Chat area */}
        <main className="flex-1 flex flex-col">
          {/* Stats */}
          <div className="px-6 pt-4">
            <StatsPanel stats={stats} />
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto px-6 py-4">
            {messages.map((message) => (
              <Message key={message.id} message={message} isUser={message.isUser} />
            ))}
            {isLoading && <TypingIndicator />}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick actions */}
          <div className="px-6">
            <QuickActions onAction={handleQuickAction} />
          </div>

          {/* Input */}
          <div className="flex-shrink-0 px-6 pb-6">
            <form onSubmit={handleSubmit} className="relative">
              <div className="flex items-center gap-3 bg-cyber-surface border border-cyber-border rounded-xl px-4 py-3 focus-within:border-cyber-accent focus-within:glow-border transition-all">
                <Terminal className="w-5 h-5 text-gray-500" />
                <input
                  ref={inputRef}
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Ask about alerts, threats, or events..."
                  className="flex-1 bg-transparent border-none outline-none text-white placeholder-gray-500 font-mono text-sm"
                  disabled={isLoading}
                />
                <button
                  type="submit"
                  disabled={isLoading || !input.trim()}
                  className="p-2 rounded-lg bg-cyber-accent/20 text-cyber-accent hover:bg-cyber-accent/30 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  <Send className="w-5 h-5" />
                </button>
              </div>
            </form>
            <div className="mt-2 text-center text-xs text-gray-500">
              <span className="font-mono">SESSION:</span> {sessionId.slice(0, 20)}...
            </div>
          </div>
        </main>

        {/* Sidebar - Agent status */}
        <aside className="w-64 bg-cyber-surface/50 border-l border-cyber-border p-4 hidden lg:block">
          <h2 className="text-sm font-semibold text-gray-400 mb-4 flex items-center gap-2">
            <Cpu className="w-4 h-4" />
            ACTIVE AGENTS
          </h2>
          
          <div className="space-y-3">
            {Object.entries(AGENT_INFO).map(([key, info]) => {
              const Icon = info.icon || Bot;
              return (
                <div 
                  key={key}
                  className="flex items-center gap-3 p-3 bg-cyber-bg/50 rounded-lg border border-cyber-border"
                >
                  <div className={`w-8 h-8 rounded-lg ${info.bg} flex items-center justify-center`}>
                    <Icon className={`w-4 h-4 ${info.color}`} />
                  </div>
                  <div className="flex-1">
                    <div className={`text-sm font-medium ${info.color}`}>{info.name}</div>
                    <div className="text-xs text-gray-500">Ready</div>
                  </div>
                  <div className="status-dot status-online" />
                </div>
              );
            })}
          </div>

          <div className="mt-6 pt-4 border-t border-cyber-border">
            <h2 className="text-sm font-semibold text-gray-400 mb-3 flex items-center gap-2">
              <Network className="w-4 h-4" />
              DATA SOURCES
            </h2>
            <div className="space-y-2 text-xs text-gray-400">
              {stats.sources?.slice(0, 5).map((source, i) => (
                <div key={i} className="flex items-center gap-2">
                  <ChevronRight className="w-3 h-3 text-green-400" />
                  <span className="font-mono">{source}</span>
                </div>
              ))}
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
