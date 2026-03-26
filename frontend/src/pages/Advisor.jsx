import { useState, useEffect, useRef } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { fetchAdvisory, streamAdvice } from '../lib/api'
import SeverityBadge from '../components/SeverityBadge'

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i

const RISK_COLORS = {
  CRITICAL: { text: 'text-critical', bg: 'bg-critical/10', border: 'border-critical/40' },
  HIGH:     { text: 'text-high',     bg: 'bg-high/10',     border: 'border-high/40' },
  MEDIUM:   { text: 'text-medium',   bg: 'bg-medium/10',   border: 'border-medium/40' },
  LOW:      { text: 'text-low',      bg: 'bg-low/10',      border: 'border-low/40' },
}

const URGENCY = {
  CRITICAL: 'Patch immediately',
  HIGH:     'Patch within 7 days',
  MEDIUM:   'Patch within 30 days',
  LOW:      'Monitor and assess',
}

function SkeletonCard({ rows = 4 }) {
  return (
    <div className="bg-card border border-border rounded-xl p-5 animate-pulse flex flex-col gap-3">
      {Array(rows).fill(0).map((_, i) => (
        <div key={i} className={`h-3 bg-slate-700 rounded ${i === 0 ? 'w-1/3' : i % 2 === 0 ? 'w-full' : 'w-4/5'}`} />
      ))}
    </div>
  )
}

function Chip({ label }) {
  return (
    <span className="text-xs bg-surface border border-border px-2 py-0.5 rounded-full text-slate-300">{label}</span>
  )
}

function RelatedTable({ rows, onSelect }) {
  if (!rows?.length) return <p className="text-xs text-slate-500">No related CVEs found</p>
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-slate-400 border-b border-border">
            <th className="text-left py-1.5 pr-3 font-medium">CVE ID</th>
            <th className="text-left py-1.5 pr-3 font-medium">Severity</th>
            <th className="text-left py-1.5 pr-3 font-medium">CVSS</th>
            <th className="text-left py-1.5 font-medium">Published</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(r => (
            <tr
              key={r.cve_id}
              onClick={() => onSelect(r.cve_id)}
              className="border-b border-border/50 hover:bg-white/5 cursor-pointer transition-colors"
            >
              <td className="py-1.5 pr-3 text-brand font-medium">{r.cve_id}</td>
              <td className="py-1.5 pr-3"><SeverityBadge severity={r.severity} /></td>
              <td className="py-1.5 pr-3 text-slate-300">{r.cvss_score?.toFixed(1) ?? '—'}</td>
              <td className="py-1.5 text-slate-400">{(r.published_date || '').slice(0, 10)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function Advisor() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()

  const [cveInput, setCveInput]     = useState('')
  const [inputError, setInputError] = useState('')
  const [loading, setLoading]       = useState(false)
  const [advisory, setAdvisory]     = useState(null)
  const [fetchError, setFetchError] = useState(null)

  const [advice, setAdvice]           = useState('')
  const [adviceStreaming, setAdviceStreaming] = useState(false)
  const [adviceError, setAdviceError] = useState(null)
  const [adviceDone, setAdviceDone]   = useState(false)

  const adviceRef = useRef(null)

  // Auto-populate and submit from ?cve= URL param
  useEffect(() => {
    const param = searchParams.get('cve')
    if (param) {
      setCveInput(param.toUpperCase())
      runAnalysis(param.toUpperCase())
    }
  }, [])

  // Scroll advice into view when it starts
  useEffect(() => {
    if (advice) adviceRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  }, [advice])

  async function runAnalysis(id) {
    const cveId = (id ?? cveInput).trim().toUpperCase()
    if (!CVE_RE.test(cveId)) {
      setInputError('Invalid format — use CVE-YYYY-NNNNN (e.g. CVE-2021-44228)')
      return
    }
    setInputError('')
    setAdvisory(null)
    setFetchError(null)
    setAdvice('')
    setAdviceDone(false)
    setLoading(true)
    try {
      const data = await fetchAdvisory(cveId)
      setAdvisory(data)
    } catch (err) {
      setFetchError(err.message)
    } finally {
      setLoading(false)
    }
  }

  function startStreamAdvice() {
    if (!advisory) return
    setAdvice('')
    setAdviceError(null)
    setAdviceDone(false)
    setAdviceStreaming(true)
    const cveId = advisory.cve.cve_id
    streamAdvice(
      cveId,
      (token) => setAdvice(prev => prev + token),
      (err) => { setAdviceError(err); setAdviceStreaming(false) },
    )
    // detect done: watch for stream ending via a small trick —
    // readSSEStream calls onDone but our streamAdvice doesn't expose it;
    // we'll rely on the absence of new tokens to show "Regenerate"
    // by setting done after a short delay once streaming stops naturally.
    // Instead we pass onDone via a wrapper:
    // (already handled below via the done detection approach)
  }

  // Detect streaming completion: when adviceStreaming is true and
  // we haven't received a new token for 1.5s, mark done.
  const lastTokenTime = useRef(0)
  useEffect(() => {
    if (!adviceStreaming) return
    lastTokenTime.current = Date.now()
  }, [advice])

  useEffect(() => {
    if (!adviceStreaming) return
    const interval = setInterval(() => {
      if (Date.now() - lastTokenTime.current > 1500 && advice) {
        setAdviceStreaming(false)
        setAdviceDone(true)
        clearInterval(interval)
      }
    }, 500)
    return () => clearInterval(interval)
  }, [adviceStreaming, advice])

  const cve         = advisory?.cve
  const riskSummary = advisory?.risk_summary
  const risk        = RISK_COLORS[riskSummary?.risk_level] ?? RISK_COLORS.LOW

  const vendorList = cve
    ? (Array.isArray(cve.vendors) ? cve.vendors : (cve.vendors || '').split(',').map(v => v.trim()).filter(Boolean))
    : []
  const productList = cve
    ? (Array.isArray(cve.products) ? cve.products : (cve.products || '').split(',').map(p => p.trim()).filter(Boolean))
    : []

  return (
    <div className="max-w-4xl mx-auto flex flex-col gap-6 pb-8 animate-fadein">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">🛡️ Patch Advisor</h1>
        <p className="text-slate-400 text-sm mt-1">
          Enter a CVE ID to get structured risk analysis and AI-powered remediation advice
        </p>
      </div>

      {/* ── Input ── */}
      <div className="bg-card border border-border rounded-xl p-4 flex flex-col gap-3">
        <div className="flex gap-3">
          <div className="flex-1 flex flex-col gap-1">
            <input
              type="text"
              value={cveInput}
              onChange={e => { setCveInput(e.target.value.toUpperCase()); setInputError('') }}
              onKeyDown={e => e.key === 'Enter' && runAnalysis()}
              placeholder="CVE-2021-44228"
              disabled={loading}
              className="w-full bg-surface border border-border rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand disabled:opacity-50"
            />
            {inputError && <p className="text-xs text-red-400 pl-1">{inputError}</p>}
          </div>
          <button
            onClick={() => runAnalysis()}
            disabled={loading || !cveInput.trim()}
            className="px-5 py-2.5 rounded-xl bg-brand hover:bg-brand/80 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium transition-colors"
          >
            {loading ? 'Loading…' : 'Analyze'}
          </button>
        </div>
      </div>

      {/* ── Fetch error ── */}
      {fetchError && (
        <div className="bg-critical/10 border border-critical/40 rounded-xl px-4 py-3 text-sm text-red-300">
          {fetchError}
        </div>
      )}

      {/* ── Loading skeletons ── */}
      {loading && (
        <>
          <SkeletonCard rows={3} />
          <SkeletonCard rows={5} />
          <SkeletonCard rows={4} />
        </>
      )}

      {/* ── Results ── */}
      {advisory && !loading && (
        <>
          {/* Card 1 — Risk Assessment */}
          <div className={`border rounded-xl p-5 ${risk.bg} ${risk.border}`}>
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">Risk Assessment</p>
            <div className="grid grid-cols-3 gap-4">
              <div>
                <p className="text-xs text-slate-400 mb-0.5">Risk Level</p>
                <p className={`text-xl font-bold ${risk.text}`}>{riskSummary.risk_level}</p>
              </div>
              <div>
                <p className="text-xs text-slate-400 mb-0.5">CVSS Score</p>
                <p className="text-xl font-bold text-slate-100">
                  {riskSummary.cvss_score?.toFixed(1) ?? '—'}
                </p>
              </div>
              <div>
                <p className="text-xs text-slate-400 mb-0.5">Age</p>
                <p className="text-xl font-bold text-slate-100">
                  {riskSummary.age_days >= 0 ? `${riskSummary.age_days}d` : '—'}
                </p>
              </div>
            </div>
            <p className={`mt-3 text-sm font-medium ${risk.text}`}>
              {URGENCY[riskSummary.risk_level] ?? 'Assess manually'}
            </p>
          </div>

          {/* Card 2 — Vulnerability Details */}
          <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Vulnerability Details</p>
              <a
                href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-brand hover:underline"
              >
                View on NVD ↗
              </a>
            </div>

            <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
              <span className="font-bold text-brand">{cve.cve_id}</span>
              <SeverityBadge severity={cve.severity} />
            </div>

            <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-400">
              {cve.published_date && (
                <span>Published <span className="text-slate-200">{cve.published_date.slice(0, 10)}</span></span>
              )}
              {cve.last_modified && (
                <span>Modified <span className="text-slate-200">{cve.last_modified.slice(0, 10)}</span></span>
              )}
            </div>

            <p className="text-sm text-slate-200 leading-relaxed">{cve.description || 'No description available.'}</p>

            {vendorList.length > 0 && (
              <div>
                <p className="text-xs font-medium text-slate-400 mb-1.5">Vendors</p>
                <div className="flex flex-wrap gap-1">{vendorList.map(v => <Chip key={v} label={v} />)}</div>
              </div>
            )}

            {productList.length > 0 && (
              <div>
                <p className="text-xs font-medium text-slate-400 mb-1.5">Products</p>
                <div className="flex flex-wrap gap-1">{productList.map(p => <Chip key={p} label={p} />)}</div>
              </div>
            )}
          </div>

          {/* Card 3 — Related CVEs */}
          <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-4">
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Related CVEs</p>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <p className="text-xs text-slate-400 mb-2">By Vendor</p>
                <RelatedTable
                  rows={advisory.related_by_vendor}
                  onSelect={id => { setCveInput(id); runAnalysis(id) }}
                />
              </div>
              <div>
                <p className="text-xs text-slate-400 mb-2">By Product</p>
                <RelatedTable
                  rows={advisory.related_by_product}
                  onSelect={id => { setCveInput(id); runAnalysis(id) }}
                />
              </div>
            </div>
          </div>

          {/* Card 4 — AI Advice */}
          <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-4" ref={adviceRef}>
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-slate-100">🤖 AI Remediation Advice</p>
              {!adviceStreaming && !advice && (
                <button
                  onClick={startStreamAdvice}
                  className="px-4 py-1.5 rounded-lg bg-brand hover:bg-brand/80 text-white text-xs font-medium transition-colors"
                >
                  Generate Advice
                </button>
              )}
              {adviceDone && (
                <button
                  onClick={startStreamAdvice}
                  className="px-4 py-1.5 rounded-lg border border-border hover:bg-white/5 text-slate-400 text-xs transition-colors"
                >
                  Regenerate
                </button>
              )}
            </div>

            {adviceStreaming && !advice && (
              <div className="flex items-center gap-2 text-slate-400 text-sm">
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                </svg>
                Generating…
              </div>
            )}

            {adviceError && (
              <p className="text-xs text-red-400">{adviceError}</p>
            )}

            {advice && (
              <p className="text-sm text-slate-200 leading-relaxed whitespace-pre-wrap">{advice}</p>
            )}
          </div>
        </>
      )}
    </div>
  )
}
