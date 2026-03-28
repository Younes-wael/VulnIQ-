import { useState, useEffect, useRef } from 'react'
import {
  getWatchlists,
  createWatchlist,
  updateWatchlist,
  deleteWatchlist,
  testWatchlist,
} from '../lib/api'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function relativeTime(dateStr) {
  if (!dateStr) return 'Never'
  const iso = dateStr.replace(' ', 'T') + (dateStr.includes('T') ? '' : 'Z')
  const diff = Date.now() - new Date(iso).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60) return 'just now'
  const m = Math.floor(s / 60)
  if (m < 60) return `${m} min ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  const d = Math.floor(h / 24)
  return `${d}d ago`
}

// ─── Constants ───────────────────────────────────────────────────────────────

const EMPTY_FORM = {
  name: '',
  vendors: [],
  products: [],
  keywords: [],
  min_cvss: 0,
  webhook_url: '',
}

const CHIP_COLORS = {
  vendors:  { bg: 'rgba(59,130,246,0.15)',  border: 'rgba(59,130,246,0.3)',  text: '#93c5fd' },
  products: { bg: 'rgba(139,92,246,0.15)',  border: 'rgba(139,92,246,0.3)',  text: '#c4b5fd' },
  keywords: { bg: 'rgba(100,116,139,0.2)',  border: 'rgba(100,116,139,0.3)', text: '#94a3b8' },
}

const SECTION_LABEL_STYLE = {
  fontFamily: "'Consolas','Courier New',monospace",
  fontSize: '0.65rem',
  color: '#475569',
  textTransform: 'uppercase',
  letterSpacing: '0.1em',
  marginBottom: '8px',
  display: 'block',
}

// ─── TagInput ─────────────────────────────────────────────────────────────────

function TagInput({ tags, onChange, placeholder, chipColor }) {
  const [input, setInput] = useState('')
  const inputRef = useRef(null)

  function add(raw) {
    const t = raw.trim().replace(/,+$/, '').trim()
    if (t && !tags.includes(t)) onChange([...tags, t])
    setInput('')
  }

  function handleKeyDown(e) {
    if (e.key === 'Enter' || e.key === 'Tab') {
      e.preventDefault()
      if (input.trim()) add(input)
    } else if (e.key === 'Backspace' && !input && tags.length > 0) {
      onChange(tags.slice(0, -1))
    }
  }

  function handleChange(e) {
    const v = e.target.value
    if (v.endsWith(',')) {
      add(v.slice(0, -1))
    } else {
      setInput(v)
    }
  }

  return (
    <div
      onClick={() => inputRef.current?.focus()}
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '4px',
        alignItems: 'center',
        padding: '6px 10px',
        background: '#0f172a',
        border: '1px solid #334155',
        borderRadius: '10px',
        cursor: 'text',
        minHeight: '40px',
      }}
    >
      {tags.map((tag, i) => (
        <span
          key={i}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '3px',
            fontSize: '0.72rem',
            padding: '2px 7px',
            borderRadius: '9999px',
            background: chipColor.bg,
            border: `1px solid ${chipColor.border}`,
            color: chipColor.text,
            fontWeight: 500,
          }}
        >
          {tag}
          <button
            type="button"
            onClick={e => { e.stopPropagation(); onChange(tags.filter((_, j) => j !== i)) }}
            style={{
              lineHeight: 1,
              color: chipColor.text,
              opacity: 0.7,
              padding: '0 1px',
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              fontSize: '0.85rem',
            }}
          >
            ×
          </button>
        </span>
      ))}
      <input
        ref={inputRef}
        value={input}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        placeholder={tags.length === 0 ? placeholder : ''}
        style={{
          flex: '1 1 80px',
          minWidth: '80px',
          background: 'transparent',
          border: 'none',
          outline: 'none',
          fontSize: '0.875rem',
          color: '#e2e8f0',
        }}
      />
    </div>
  )
}

// ─── Spinner ──────────────────────────────────────────────────────────────────

function Spinner() {
  return (
    <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
    </svg>
  )
}

// ─── WatchlistCard ────────────────────────────────────────────────────────────

function WatchlistCard({ wl, onEdit, onDelete, testResult, onTest }) {
  const hasWebhook = !!wl.webhook_url

  function TestResultBadge() {
    if (!testResult) return null
    if (testResult.loading) return (
      <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '4px' }}>
        <Spinner /> Testing…
      </span>
    )
    if (testResult.fetchError) return (
      <span style={{ fontSize: '0.7rem', color: '#fca5a5' }}>Error: {testResult.fetchError}</span>
    )
    if (testResult.matches === 0) return (
      <span style={{ fontSize: '0.7rem', color: '#475569' }}>No matches in last 24 h</span>
    )
    if (testResult.delivered) return (
      <span style={{ fontSize: '0.7rem', color: '#86efac' }}>
        {testResult.matches} match{testResult.matches !== 1 ? 'es' : ''}, webhook delivered
      </span>
    )
    if (testResult.error) return (
      <span style={{ fontSize: '0.7rem', color: '#fca5a5' }}>
        {testResult.matches} match{testResult.matches !== 1 ? 'es' : ''} · webhook error: {testResult.error}
      </span>
    )
    return (
      <span style={{ fontSize: '0.7rem', color: '#94a3b8' }}>
        {testResult.matches} match{testResult.matches !== 1 ? 'es' : ''}
      </span>
    )
  }

  return (
    <div className="bg-card border border-border rounded-xl p-4 flex flex-col gap-3">
      {/* Name + actions */}
      <div className="flex items-start justify-between gap-2">
        <p className="text-slate-100 font-semibold text-sm">{wl.name}</p>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <button
            onClick={onEdit}
            title="Edit"
            className="p-1.5 rounded-lg hover:bg-white/5 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
              <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
            </svg>
          </button>
          <button
            onClick={onDelete}
            title="Delete"
            className="p-1.5 rounded-lg hover:bg-red-500/10 text-slate-400 hover:text-red-400 transition-colors"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <polyline points="3 6 5 6 21 6"/>
              <path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/>
              <path d="M10 11v6M14 11v6"/>
              <path d="M9 6V4a1 1 0 011-1h4a1 1 0 011 1v2"/>
            </svg>
          </button>
        </div>
      </div>

      {/* Filter chips */}
      <div className="flex flex-wrap gap-1.5">
        {wl.vendors.map(v => (
          <span key={v} style={{ ...CHIP_COLORS.vendors, display: 'inline-block', fontSize: '0.7rem', padding: '1px 8px', borderRadius: '9999px', background: CHIP_COLORS.vendors.bg, border: `1px solid ${CHIP_COLORS.vendors.border}`, color: CHIP_COLORS.vendors.text }}>
            {v}
          </span>
        ))}
        {wl.products.map(p => (
          <span key={p} style={{ display: 'inline-block', fontSize: '0.7rem', padding: '1px 8px', borderRadius: '9999px', background: CHIP_COLORS.products.bg, border: `1px solid ${CHIP_COLORS.products.border}`, color: CHIP_COLORS.products.text }}>
            {p}
          </span>
        ))}
        {wl.keywords.map(k => (
          <span key={k} style={{ display: 'inline-block', fontSize: '0.7rem', padding: '1px 8px', borderRadius: '9999px', background: CHIP_COLORS.keywords.bg, border: `1px solid ${CHIP_COLORS.keywords.border}`, color: CHIP_COLORS.keywords.text }}>
            {k}
          </span>
        ))}
        {wl.min_cvss > 0 && (
          <span style={{ display: 'inline-block', fontSize: '0.7rem', padding: '1px 8px', borderRadius: '9999px', background: 'rgba(249,115,22,0.1)', border: '1px solid rgba(249,115,22,0.3)', color: '#fdba74' }}>
            CVSS ≥ {wl.min_cvss.toFixed(1)}
          </span>
        )}
      </div>

      {/* Metadata row */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-3">
          {/* Webhook */}
          <span style={{ fontSize: '0.7rem', color: hasWebhook ? '#64748b' : '#334155', display: 'flex', alignItems: 'center', gap: '4px' }}>
            {hasWebhook ? (
              <>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="2">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                  <path d="M7 11V7a5 5 0 0110 0v4"/>
                </svg>
                {wl.webhook_url.length > 40 ? wl.webhook_url.slice(0, 40) + '…' : wl.webhook_url}
              </>
            ) : (
              <span style={{ color: '#334155' }}>No webhook</span>
            )}
          </span>

          {/* Last alerted */}
          <span style={{ fontSize: '0.7rem', color: '#475569' }}>
            Last alerted: <span style={{ color: '#64748b' }}>{relativeTime(wl.last_alerted_at)}</span>
          </span>
        </div>

        {/* Test button + result */}
        <div className="flex items-center gap-2">
          <TestResultBadge />
          <button
            onClick={onTest}
            disabled={testResult?.loading}
            style={{
              fontSize: '0.7rem',
              padding: '3px 10px',
              borderRadius: '6px',
              background: 'rgba(16,185,129,0.1)',
              border: '1px solid rgba(16,185,129,0.3)',
              color: '#6ee7b7',
              cursor: testResult?.loading ? 'not-allowed' : 'pointer',
              opacity: testResult?.loading ? 0.5 : 1,
            }}
          >
            Test now
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function Watchlists() {
  const [watchlists, setWatchlists]   = useState([])
  const [fetchLoading, setFetchLoading] = useState(true)
  const [fetchError, setFetchError]   = useState(null)

  const [editingId, setEditingId]     = useState(null)
  const [form, setForm]               = useState(EMPTY_FORM)
  const [saving, setSaving]           = useState(false)
  const [formError, setFormError]     = useState(null)

  const [testResults, setTestResults] = useState({})

  const formRef = useRef(null)
  const listRef = useRef(null)

  useEffect(() => { loadWatchlists() }, [])

  async function loadWatchlists() {
    try {
      const data = await getWatchlists()
      setWatchlists(data)
    } catch (err) {
      setFetchError(err.message)
    } finally {
      setFetchLoading(false)
    }
  }

  function setField(key, value) {
    setForm(prev => ({ ...prev, [key]: value }))
  }

  function handleEdit(wl) {
    setEditingId(wl.id)
    setForm({
      name:        wl.name,
      vendors:     wl.vendors,
      products:    wl.products,
      keywords:    wl.keywords,
      min_cvss:    wl.min_cvss,
      webhook_url: wl.webhook_url,
    })
    setFormError(null)
    setTimeout(() => formRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50)
  }

  function handleCancelEdit() {
    setEditingId(null)
    setForm(EMPTY_FORM)
    setFormError(null)
  }

  async function handleDelete(id) {
    if (!window.confirm('Delete this watchlist?')) return
    try {
      await deleteWatchlist(id)
      setTestResults(prev => { const n = { ...prev }; delete n[id]; return n })
      await loadWatchlists()
    } catch (err) {
      setFetchError(err.message)
    }
  }

  async function handleTest(id) {
    setTestResults(prev => ({ ...prev, [id]: { loading: true } }))
    try {
      const result = await testWatchlist(id)
      setTestResults(prev => ({ ...prev, [id]: { loading: false, ...result } }))
    } catch (err) {
      setTestResults(prev => ({ ...prev, [id]: { loading: false, fetchError: err.message } }))
    }
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (!form.name.trim()) { setFormError('Name is required.'); return }
    if (form.min_cvss < 0 || form.min_cvss > 10) { setFormError('Min CVSS must be 0–10.'); return }

    setSaving(true)
    setFormError(null)
    try {
      if (editingId != null) {
        await updateWatchlist(editingId, form)
      } else {
        await createWatchlist(form)
      }
      setForm(EMPTY_FORM)
      setEditingId(null)
      await loadWatchlists()
      setTimeout(() => listRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50)
    } catch (err) {
      setFormError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="max-w-2xl mx-auto flex flex-col gap-6 pb-8 animate-fadein">

      {/* ── Header ── */}
      <div>
        <div style={{ width: '32px', height: '3px', borderRadius: '2px', background: '#10b981', marginBottom: '8px', display: 'block' }} />
        <h1 className="text-2xl font-bold text-slate-100">Watchlists</h1>
        <p className="text-slate-400 text-sm mt-1">
          Monitor vendors, products, and keywords — get webhook alerts when new CVEs match
        </p>
      </div>

      {/* ── List ── */}
      <div ref={listRef} className="flex flex-col gap-3">
        <p style={SECTION_LABEL_STYLE}>Saved watchlists</p>

        {fetchLoading && (
          <div className="animate-pulse flex flex-col gap-3">
            {[1, 2].map(i => (
              <div key={i} className="bg-card border border-border rounded-xl h-24" />
            ))}
          </div>
        )}

        {fetchError && (
          <p className="text-sm text-red-400 bg-critical/10 border border-critical/30 rounded-xl px-4 py-3">
            {fetchError}
          </p>
        )}

        {!fetchLoading && !fetchError && watchlists.length === 0 && (
          <div className="bg-card border border-border rounded-xl p-6 text-center">
            <p className="text-slate-400 text-sm">
              No watchlists yet. Create one below to start monitoring vendors and products.
            </p>
          </div>
        )}

        {watchlists.map(wl => (
          <WatchlistCard
            key={wl.id}
            wl={wl}
            onEdit={() => handleEdit(wl)}
            onDelete={() => handleDelete(wl.id)}
            testResult={testResults[wl.id] ?? null}
            onTest={() => handleTest(wl.id)}
          />
        ))}
      </div>

      {/* ── Create / Edit Form ── */}
      <div ref={formRef} className="bg-card border border-border rounded-xl p-5 flex flex-col gap-4">
        <p style={SECTION_LABEL_STYLE}>
          {editingId != null ? `Editing watchlist` : 'Create watchlist'}
        </p>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">

          {/* Name */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs text-slate-400 font-medium">Name *</label>
            <input
              value={form.name}
              onChange={e => setField('name', e.target.value)}
              placeholder="e.g. Apache + Log4j watch"
              className="w-full bg-surface border border-border rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-brand"
            />
          </div>

          {/* Vendors */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs text-slate-400 font-medium">
              Vendors
              <span className="ml-1.5 font-normal text-slate-600">— press Enter or comma to add</span>
            </label>
            <TagInput
              tags={form.vendors}
              onChange={v => setField('vendors', v)}
              placeholder="apache, microsoft…"
              chipColor={CHIP_COLORS.vendors}
            />
          </div>

          {/* Products */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs text-slate-400 font-medium">
              Products
              <span className="ml-1.5 font-normal text-slate-600">— press Enter or comma to add</span>
            </label>
            <TagInput
              tags={form.products}
              onChange={v => setField('products', v)}
              placeholder="log4j, openssl, nginx…"
              chipColor={CHIP_COLORS.products}
            />
          </div>

          {/* Keywords */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs text-slate-400 font-medium">
              Keywords
              <span className="ml-1.5 font-normal text-slate-600">— matched against CVE descriptions</span>
            </label>
            <TagInput
              tags={form.keywords}
              onChange={v => setField('keywords', v)}
              placeholder="remote code execution, buffer overflow…"
              chipColor={CHIP_COLORS.keywords}
            />
          </div>

          {/* Min CVSS slider */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs text-slate-400 font-medium">
              Min CVSS score
              <span className="ml-2 text-slate-200 font-semibold">
                {form.min_cvss === 0 ? 'Any' : form.min_cvss.toFixed(1)}
              </span>
            </label>
            <input
              type="range"
              min="0"
              max="10"
              step="0.1"
              value={form.min_cvss}
              onChange={e => setField('min_cvss', parseFloat(e.target.value))}
              className="w-full accent-brand"
            />
            <div className="flex justify-between text-xs text-slate-600">
              <span>0 — any</span>
              <span>7.0 — high</span>
              <span>9.0 — critical</span>
              <span>10</span>
            </div>
          </div>

          {/* Webhook URL */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs text-slate-400 font-medium">Webhook URL</label>
            <input
              value={form.webhook_url}
              onChange={e => setField('webhook_url', e.target.value)}
              placeholder="https://hooks.slack.com/… (optional)"
              className="w-full bg-surface border border-border rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-brand"
            />
            <p className="text-xs text-slate-600">
              Receives a JSON POST when new CVEs match this watchlist. Works with Slack, Teams, or any HTTP endpoint.
            </p>
          </div>

          {formError && (
            <p className="text-xs text-red-400 bg-critical/10 border border-critical/30 px-3 py-2 rounded-lg">
              {formError}
            </p>
          )}

          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={saving}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-brand hover:bg-brand/80 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium transition-colors"
            >
              {saving && <Spinner />}
              {editingId != null ? 'Update watchlist' : 'Save watchlist'}
            </button>

            {editingId != null && (
              <button
                type="button"
                onClick={handleCancelEdit}
                className="px-4 py-2.5 rounded-xl border border-border bg-surface hover:bg-white/5 text-slate-400 text-sm transition-colors"
              >
                Cancel
              </button>
            )}
          </div>
        </form>
      </div>
    </div>
  )
}
