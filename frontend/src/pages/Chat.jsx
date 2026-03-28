import { useState, useRef, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { streamChat } from '../lib/api'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

const WELCOME_CARDS = [
  { label: 'CRITICAL RESEARCH', question: 'What are the most critical OpenSSL vulnerabilities?' },
  { label: 'CVE LOOKUP',        question: 'Explain CVE-2021-44228 Log4Shell' },
  { label: 'VENDOR ANALYSIS',   question: 'Which Django CVEs involve SQL injection?' },
]

const SEV_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

// Minimal markdown renderer: **bold** and newlines only
function MessageText({ text }) {
  const parts = text.split(/(\*\*[^*]+\*\*)/g)
  return (
    <span className="whitespace-pre-wrap break-words">
      {parts.map((part, i) =>
        part.startsWith('**') && part.endsWith('**')
          ? <strong key={i}>{part.slice(2, -2)}</strong>
          : <span key={i}>{part}</span>
      )}
    </span>
  )
}

function TypingDots() {
  return (
    <span className="inline-flex items-center gap-1 px-1">
      {[0, 1, 2].map(i => (
        <span
          key={i}
          className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce"
          style={{ animationDelay: `${i * 0.15}s` }}
        />
      ))}
    </span>
  )
}

function SourceChips({ sources, onNavigate }) {
  if (!sources?.length) return null
  return (
    <div className="flex flex-wrap gap-1 mt-1">
      {sources.map(id => (
        <button
          key={id}
          onClick={() => onNavigate(`/advisor?cve=${id}`)}
          className="text-xs px-2 py-0.5 rounded-full bg-brand/20 text-brand hover:bg-brand/40 transition-colors"
        >
          {id}
        </button>
      ))}
    </div>
  )
}

export default function Chat() {
  const navigate = useNavigate()
  const [messages, setMessages]       = useState([])
  const [input, setInput]             = useState('')
  const [isStreaming, setIsStreaming]  = useState(false)
  const [showFilters, setShowFilters] = useState(false)
  const [filters, setFilters]         = useState({
    severities: [],
    year_from: '',
    year_to: '',
    vendor: '',
  })

  const bottomRef  = useRef(null)
  const inputRef   = useRef(null)
  const textareaRef = useRef(null)

  // Auto-scroll on new content
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const toggleSeverity = (sev) => {
    setFilters(f => ({
      ...f,
      severities: f.severities.includes(sev)
        ? f.severities.filter(s => s !== sev)
        : [...f.severities, sev],
    }))
  }

  const buildFilters = () => {
    const out = {}
    if (filters.severities.length) out.severities = filters.severities
    if (filters.year_from)         out.year_from  = Number(filters.year_from)
    if (filters.year_to)           out.year_to    = Number(filters.year_to)
    if (filters.vendor.trim())     out.vendor     = filters.vendor.trim()
    return out
  }

  const sendMessage = useCallback((text) => {
    const trimmed = (text ?? input).trim()
    if (!trimmed || isStreaming) return

    const userMsg = { role: 'user', content: trimmed, sources: null }
    const assistantMsg = { role: 'assistant', content: '', sources: null, loading: true }

    setMessages(prev => {
      const next = [...prev, userMsg, assistantMsg]
      // build history from all prior messages (exclude the two we just added)
      return next
    })
    setInput('')
    setIsStreaming(true)

    // history = all messages before the new user message
    const history = messages.map(m => ({ role: m.role, content: m.content }))

    streamChat(
      trimmed,
      history,
      buildFilters(),
      // onToken
      (token) => {
        setMessages(prev => {
          const next = [...prev]
          const last = { ...next[next.length - 1] }
          last.content += token
          last.loading = false
          next[next.length - 1] = last
          return next
        })
      },
      // onSources
      (ids) => {
        setMessages(prev => {
          const next = [...prev]
          const last = { ...next[next.length - 1], sources: ids, loading: false }
          next[next.length - 1] = last
          return next
        })
        setIsStreaming(false)
      },
      // onError
      (err) => {
        setMessages(prev => {
          const next = [...prev]
          const last = { ...next[next.length - 1], content: `Error: ${err}`, error: true, loading: false }
          next[next.length - 1] = last
          return next
        })
        setIsStreaming(false)
      },
      // onDone — fires when stream closes without a [SOURCES] line (zero results)
      () => {
        setMessages(prev => {
          const next = [...prev]
          const last = { ...next[next.length - 1], loading: false }
          next[next.length - 1] = last
          return next
        })
        setIsStreaming(false)
      },
    )
  }, [input, isStreaming, messages, filters])

  // Handle stream ending without sources event
  useEffect(() => {
    if (!isStreaming) return
    // fallback: if last message stopped loading but isStreaming is still true, clear it
    const last = messages[messages.length - 1]
    if (last?.role === 'assistant' && !last.loading && last.content && !last.sources) {
      // sources may not come — we'll rely on onSources / onError to reset isStreaming
    }
  }, [messages, isStreaming])

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  const SEV_COLORS = { CRITICAL: 'text-critical', HIGH: 'text-high', MEDIUM: 'text-medium', LOW: 'text-low' }

  const markdownComponents = {
    h2: ({children}) => (
      <h2 className="text-indigo-400 font-bold uppercase tracking-widest text-base mt-6 mb-2 pb-1 border-b border-slate-600">{children}</h2>
    ),
    h3: ({children}) => (
      <h3 className="text-slate-200 font-semibold text-sm mt-4 mb-1">{children}</h3>
    ),
    p: ({children}) => (
      <p className="text-slate-300 leading-relaxed mb-3">{children}</p>
    ),
    ol: ({children}) => (
      <ol className="list-decimal list-outside ml-5 space-y-2 text-slate-300 mb-4">{children}</ol>
    ),
    ul: ({children}) => (
      <ul className="list-disc list-outside ml-5 space-y-1 text-slate-300 mb-4">{children}</ul>
    ),
    li: ({children}) => (
      <li className="text-slate-300 leading-relaxed pl-1">{children}</li>
    ),
    strong: ({children}) => (
      <strong className="text-white font-semibold">{children}</strong>
    ),
    code: ({children}) => (
      <code className="bg-slate-700 text-indigo-300 px-1.5 py-0.5 rounded text-xs font-mono">{children}</code>
    ),
    table: ({children}) => (
      <div className="overflow-x-auto my-4 rounded-lg border border-slate-600">
        <table className="w-full text-sm text-left">{children}</table>
      </div>
    ),
    thead: ({children}) => (
      <thead className="bg-slate-700/80 text-indigo-300 text-xs uppercase tracking-wider">{children}</thead>
    ),
    tbody: ({children}) => (
      <tbody className="divide-y divide-slate-700/50">{children}</tbody>
    ),
    tr: ({children}) => (
      <tr className="hover:bg-slate-700/30 transition-colors">{children}</tr>
    ),
    th: ({children}) => (
      <th className="px-4 py-3 font-semibold text-slate-200">{children}</th>
    ),
    td: ({children}) => (
      <td className="px-4 py-3 text-slate-300">{children}</td>
    ),
    blockquote: ({children}) => (
      <blockquote className="border-l-4 border-indigo-500 pl-4 my-3 text-slate-400 italic bg-slate-800/50 py-2 rounded-r">{children}</blockquote>
    ),
    hr: () => <hr className="border-slate-600 my-5" />,
  }

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)] lg:h-[calc(100vh-1.5rem)] animate-fadein">

      {/* Message history */}
      <div className="flex-1 overflow-y-auto px-2 py-4 space-y-4">
        {messages.length === 0 ? (
          <div className="flex flex-col items-end h-full">
            <div className="flex flex-col items-center text-center w-full max-w-xl mx-auto pb-8 mt-auto">
              {/* Brand */}
              <div className="flex items-center gap-2 mb-2">
                <div style={{
                  background: 'linear-gradient(135deg, #3b82f6, #ef4444)',
                  color: '#fff',
                  fontWeight: 700,
                  borderRadius: '5px',
                  fontSize: '0.7rem',
                  padding: '3px 5px',
                  lineHeight: 1,
                }}>VL</div>
                <span style={{ color: '#fff', fontWeight: 600, fontSize: '1rem' }}>VulnLens</span>
              </div>

              {/* Heading */}
              <p style={{ fontSize: '1.25rem', fontWeight: 600, color: '#fff', marginBottom: '6px' }}>
                Ask anything about CVEs
              </p>

              {/* Subtitle */}
              <p style={{ fontSize: '0.8rem', color: '#64748b', marginBottom: '24px' }}>
                Answers grounded in real NVD data — no hallucinated CVEs
              </p>

              {/* Example cards */}
              <div className="flex gap-3 w-full" style={{ flexWrap: 'nowrap' }}>
                {WELCOME_CARDS.map(({ label, question }) => (
                  <button
                    key={label}
                    onClick={() => setInput(question)}
                    style={{
                      flex: 1,
                      textAlign: 'left',
                      background: '#1e293b',
                      border: '1px solid #334155',
                      borderRadius: '10px',
                      padding: '12px 16px',
                      cursor: 'pointer',
                      transition: 'border-color 0.15s, background 0.15s',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = '#3b82f6'; e.currentTarget.style.background = '#263548' }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = '#334155'; e.currentTarget.style.background = '#1e293b' }}
                  >
                    <p style={{
                      fontSize: '0.65rem',
                      fontFamily: "'Consolas','Courier New',monospace",
                      textTransform: 'uppercase',
                      letterSpacing: '0.08em',
                      color: '#3b82f6',
                      marginBottom: '4px',
                    }}>{label}</p>
                    <p style={{ fontSize: '0.85rem', color: '#cbd5e1', lineHeight: 1.4 }}>{question}</p>
                  </button>
                ))}
              </div>

              {/* Footer */}
              <p style={{ fontSize: '0.65rem', color: '#475569', marginTop: '16px' }}>
                Powered by RAG · ChromaDB · Groq LLaMA 3.3
              </p>
            </div>
          </div>
        ) : (
          messages.map((msg, i) => (
            <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[80%] rounded-2xl px-4 py-2.5 text-sm leading-relaxed ${
                msg.role === 'user'
                  ? 'bg-brand text-white rounded-br-sm'
                  : msg.error
                    ? 'bg-critical/20 border border-critical/40 text-red-300 rounded-bl-sm'
                    : 'bg-card border border-border text-slate-200 rounded-bl-sm'
              }`}>
                {msg.loading && !msg.content
                  ? <TypingDots />
                  : msg.role === 'assistant'
                    ? <ReactMarkdown remarkPlugins={[remarkGfm]} components={markdownComponents}>{msg.content}</ReactMarkdown>
                    : <MessageText text={msg.content} />
                }
                {msg.role === 'assistant' && msg.sources && (
                  <SourceChips sources={msg.sources} onNavigate={navigate} />
                )}
              </div>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input area */}
      <div className="border-t border-border bg-surface px-3 py-3 flex flex-col gap-2">

        {/* Filter panel */}
        {showFilters && (
          <div className="bg-card border border-border rounded-xl p-4 flex flex-col gap-3">
            {/* Severity */}
            <div>
              <p className="text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wider">Severity</p>
              <div className="flex flex-wrap gap-2">
                {SEV_OPTIONS.map(s => (
                  <label key={s} className="flex items-center gap-1.5 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={filters.severities.includes(s)}
                      onChange={() => toggleSeverity(s)}
                      className="accent-brand"
                    />
                    <span className={`text-xs font-semibold ${SEV_COLORS[s]}`}>{s}</span>
                  </label>
                ))}
              </div>
            </div>
            {/* Year + Vendor */}
            <div className="flex flex-wrap gap-3">
              <div className="flex items-center gap-1.5">
                <label className="text-xs text-slate-400">Year from</label>
                <input
                  type="number" min="2000" max="2026"
                  value={filters.year_from}
                  onChange={e => setFilters(f => ({ ...f, year_from: e.target.value }))}
                  className="w-20 bg-surface border border-border rounded-lg px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-brand"
                  placeholder="2021"
                />
              </div>
              <div className="flex items-center gap-1.5">
                <label className="text-xs text-slate-400">to</label>
                <input
                  type="number" min="2000" max="2026"
                  value={filters.year_to}
                  onChange={e => setFilters(f => ({ ...f, year_to: e.target.value }))}
                  className="w-20 bg-surface border border-border rounded-lg px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-brand"
                  placeholder="2024"
                />
              </div>
              <div className="flex items-center gap-1.5">
                <label className="text-xs text-slate-400">Vendor</label>
                <input
                  type="text"
                  value={filters.vendor}
                  onChange={e => setFilters(f => ({ ...f, vendor: e.target.value }))}
                  className="w-32 bg-surface border border-border rounded-lg px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-brand"
                  placeholder="e.g. apache"
                />
              </div>
            </div>
          </div>
        )}

        {/* Input row */}
        <div className="flex items-end gap-2">
          {/* Filter toggle */}
          <button
            onClick={() => setShowFilters(v => !v)}
            title="Toggle filters"
            className={`flex-shrink-0 p-2.5 rounded-xl border transition-colors ${
              showFilters
                ? 'border-brand bg-brand/20 text-brand'
                : 'border-border bg-card text-slate-400 hover:text-slate-200'
            }`}
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round"
                d="M3 4h18M7 8h10M11 12h2M9 16h6" />
            </svg>
          </button>

          {/* Textarea */}
          <textarea
            ref={textareaRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isStreaming}
            rows={1}
            placeholder="Ask about CVEs… (Enter to send, Shift+Enter for newline)"
            className="flex-1 resize-none bg-card border border-border rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand disabled:opacity-50 leading-relaxed"
            style={{ maxHeight: '120px', overflowY: 'auto' }}
          />

          {/* Send */}
          <button
            onClick={() => sendMessage()}
            disabled={isStreaming || !input.trim()}
            className="flex-shrink-0 p-2.5 rounded-xl bg-brand hover:bg-brand/80 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            aria-label="Send"
          >
            <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 12L3.3 4.7 20.7 12 3.3 19.3 6 12zm0 0h7" />
            </svg>
          </button>
        </div>
      </div>
    </div>
  )
}
