import React, { useState, useRef, useEffect } from 'react';
import { Bot, Send, Sparkles, Terminal, ShieldAlert, AlertCircle, Copy, Check } from 'lucide-react';
import { AIChatMessage, AIChatResponse } from '../types';
import { request } from '../services/api';
import { Badge } from '../components/common/Badge';

export const AIAssistant: React.FC = () => {
  const [messages, setMessages] = useState<AIChatMessage[]>([
    {
      role: 'assistant',
      content: 
        'Greetings, SOC Analyst. I am the SentinelGraph-AI Security Copilot. I analyze security telemetry, correlate multi-hop graph blast radiuses, map adversary actions to MITRE ATT&CK, and generate rapid containment procedures. How can I assist your investigation?'
    }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [modelInfo, setModelInfo] = useState<{ model: string; isFallback: boolean }>({
    model: 'Sentinel-Copilot (Ready)',
    isFallback: false
  });
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async (textToSend?: string) => {
    const query = textToSend || input;
    if (!query.trim() || isLoading) return;

    const userMsg: AIChatMessage = { role: 'user', content: query };
    const updatedHistory = [...messages, userMsg];
    setMessages(updatedHistory);
    if (!textToSend) setInput('');
    setIsLoading(true);

    try {
      const res = await request<AIChatResponse>('/ai/chat', {
        method: 'POST',
        body: JSON.stringify({
          message: query,
          history: updatedHistory
        })
      });

      setModelInfo({ model: res.model_used, isFallback: res.is_fallback });
      setMessages((prev) => [...prev, { role: 'assistant', content: res.response }]);
    } catch (e: any) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `Security Copilot communication error: ${e.message || 'Service offline'}. Operating in local offline advisory mode.`
        }
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  };

  const promptSuggestions = [
    'How do I block an attacker IP via Linux iptables?',
    'Explain the MITRE ATT&CK technique for brute-force attacks',
    'How does SentinelGraph verify SHA-256 log integrity?',
    'Provide step-by-step containment for a compromised database server'
  ];

  return (
    <div className="max-w-5xl mx-auto space-y-4 animate-fadeIn pb-12">
      {/* Header with Model Badge */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-900/30">
            <Bot className="w-5 h-5 text-white" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <span>SentinelGraph-AI Copilot</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                ACTIVE
              </span>
            </h3>
            <p className="text-xs text-slate-400">Context-aware conversational assistant for SOC analysts</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-mono">Engine: {modelInfo.model}</span>
          <Badge
            variant={modelInfo.isFallback ? 'INVESTIGATING' : 'RESOLVED'}
            label={modelInfo.isFallback ? 'Expert Rules Fallback' : 'Ollama Local LLM'}
            size="sm"
          />
        </div>
      </div>

      {/* Advisory Guardrail Notice */}
      <div className="p-3 bg-indigo-950/20 border border-indigo-500/30 rounded-xl flex items-center gap-2.5 text-xs text-indigo-300">
        <AlertCircle className="w-4 h-4 shrink-0 text-cyan-400" />
        <span>
          Compliance Guardrail: AI suggestions are advisory recommendations. All actions must be verified against actual cryptographic log evidence before executing containment procedures.
        </span>
      </div>

      {/* Chat Messages Container */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-6 shadow-xl min-h-[460px] max-h-[560px] overflow-y-auto space-y-4">
        {messages.map((msg, idx) => (
          <div
            key={idx}
            className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            {msg.role === 'assistant' && (
              <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center shrink-0 mt-0.5">
                <Sparkles className="w-4 h-4 text-cyan-400" />
              </div>
            )}

            <div
              className={`max-w-2xl rounded-2xl p-4 text-xs leading-relaxed space-y-2 relative group ${
                msg.role === 'user'
                  ? 'bg-gradient-to-r from-cyan-600 to-indigo-600 text-white shadow-md'
                  : 'bg-slate-950/80 border border-slate-800/80 text-slate-200'
              }`}
            >
              <div className="whitespace-pre-wrap">{msg.content}</div>

              {msg.role === 'assistant' && (
                <button
                  onClick={() => copyToClipboard(msg.content, idx)}
                  className="absolute top-2 right-2 p-1 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-white opacity-0 group-hover:opacity-100 transition"
                  title="Copy response"
                >
                  {copiedIdx === idx ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              )}
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="flex gap-3 items-center">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center">
              <Sparkles className="w-4 h-4 text-cyan-400 animate-spin" />
            </div>
            <div className="bg-slate-950 border border-slate-800 p-3 rounded-xl text-xs text-slate-400 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
              <span>Analyzing telemetry & compiling mitigation recommendation...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Suggested Prompts */}
      <div className="flex flex-wrap gap-2">
        {promptSuggestions.map((prompt, i) => (
          <button
            key={i}
            onClick={() => handleSend(prompt)}
            disabled={isLoading}
            className="text-xs px-3 py-1.5 rounded-xl bg-slate-900/80 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800/80 transition disabled:opacity-50"
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* Input Box */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-2 shadow-lg flex items-center gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              handleSend();
            }
          }}
          placeholder="Ask AI Copilot for threat explanation, firewall rules, or investigation triage..."
          className="flex-1 bg-transparent px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none font-sans"
        />
        <button
          onClick={() => handleSend()}
          disabled={isLoading || !input.trim()}
          className="p-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white shadow-md disabled:opacity-40 transition"
        >
          <Send className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
