import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { analyzeStack, streamStackReport } from '../lib/api'
import MetricTile from '../components/MetricTile'
import SeverityBadge from '../components/SeverityBadge'

function Spinner() {
  return (
    <svg className="w-4 h-4 animate-spin text-brand" fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
    </svg>
  )
}

function Chip({ label, variant }) {
  const cls = variant === 'red'
    ? 'bg-critical/20 text-red-300 border-critical/30'
    : 'bg-low/20 text-green-300 border-low/30'
  return (
    <span className={`inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded-full border font-medium ${cls}`}>
      {variant === 'red' ? '⚠' : '✓'} {label}
    </span>
  )
}

export default function StackAnalysis() {
  const navigate = useNavigate()

  const [stackInput, setStackInput]   = useState('')
  const [warning, setWarning]         = useState('')
  const [loading, setLoading]         = useState(false)
  const [error, setError]             = useState(null)
  const [analysis, setAnalysis]       = useState(null)
  const [techList, setTechList]       = useState([])

  const [report, setReport]           = useState('')
  const [reportStreaming, setReportStreaming] = useState(false)
  const [reportDone, setReportDone]   = useState(false)
  const [reportError, setReportError] = useState(null)

  const reportRef    = useRef(null)
  const lastTokenRef = useRef(0)

  // Detect stream done via silence
  useEffect(() => {
    if (!reportStreaming) return
    lastTokenRef.current = Date.now()
  }, [report])

  useEffect(() => {
    if (!reportStreaming) return
    const id = setInterval(() => {
      if (Date.now() - lastTokenRef.current > 1500 && report) {
        setReportStreaming(false)
        setReportDone(true)
        clearInterval(id)
      }
    }, 400)
    return () => clearInterval(id)
  }, [reportStreaming, report])

  useEffect(() => {
    if (report) reportRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  }, [report])

  async function handleAnalyze() {
    const terms = stackInput
      .split('\n')
      .map(t => t.trim())
      .filter(Boolean)

    if (terms.length === 0) {
      setWarning('Please enter at least one technology.')
      return
    }
    setWarning('')
    setError(null)
    setAnalysis(null)
    setReport('')
    setReportDone(false)
    setLoading(true)
    setTechList(terms)

    try {
      const data = await analyzeStack(terms)
      setAnalysis(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  function handleReset() {
    setStackInput('')
    setAnalysis(null)
    setTechList([])
    setReport('')
    setReportDone(false)
    setReportError(null)
    setError(null)
    setWarning('')
  }

  function startReport() {
    setReport('')
    setReportError(null)
    setReportDone(false)
    setReportStreaming(true)
    lastTokenRef.current = Date.now()
    streamStackReport(
      techList,
      analysis,
      (token) => setReport(prev => prev + token),
      (err)   => { setReportError(err); setReportStreaming(false) },
    )
  }

  const matched = analysis?.technologies_matched ?? []
  const clean   = analysis?.technologies_clean   ?? []
  const topCVEs = analysis?.top_cves             ?? []
  const warnings = analysis?.warnings            ?? []

  return (
    <div className="max-w-3xl mx-auto flex flex-col gap-6 pb-8 animate-fadein">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">🧱 Tech Stack Analysis</h1>
        <p className="text-slate-400 text-sm mt-1">
          Enter your technology stack to get a personalised CVE exposure report
        </p>
      </div>

      {/* ── Input card ── */}
      <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-3">
        <textarea
          value={stackInput}
          onChange={e => { setStackInput(e.target.value); setWarning('') }}
          rows={6}
          placeholder={'django\nopenssl\nnginx\npostgresql\nredis'}
          disabled={loading}
          className="w-full bg-surface border border-border rounded-xl px-4 py-3 text-sm text-slate-100 placeholder-slate-600 font-mono focus:outline-none focus:border-brand disabled:opacity-50 resize-none leading-relaxed"
        />
        <p className="text-xs text-slate-500 leading-relaxed">
          💡 Use general names — <code className="text-slate-400">openssl</code> not <code className="text-slate-400">OpenSSL 3.0.1</code>.
          Avoid single letters and very broad names like <code className="text-slate-400">microsoft</code>.
        </p>

        {warning && (
          <p className="text-xs text-medium bg-medium/10 border border-medium/30 px-3 py-2 rounded-lg">{warning}</p>
        )}

        <div className="flex items-center gap-3">
          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-brand hover:bg-brand/80 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium transition-colors"
          >
            {loading && <Spinner />}
            {loading ? 'Matching against NVD database…' : 'Analyze My Stack'}
          </button>

          {analysis && (
            <button
              onClick={handleReset}
              className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl border border-border bg-surface hover:bg-white/5 text-slate-400 text-sm transition-colors"
            >
              🔄 Analyze New Stack
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="bg-critical/10 border border-critical/40 rounded-xl px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* ── Results ── */}
      {analysis && (
        <>
          {/* Card 1 — Metrics */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <MetricTile
              label="Total CVEs Found"
              value={analysis.total}
            />
            <MetricTile
              label="Critical"
              value={analysis.critical}
              color={analysis.critical > 0 ? '#ef4444' : undefined}
            />
            <MetricTile
              label="High"
              value={analysis.high}
              color={analysis.high > 0 ? '#f97316' : undefined}
            />
            <MetricTile
              label="Technologies Matched"
              value={`${matched.length} / ${techList.length}`}
              subtitle={`${clean.length} clear`}
            />
          </div>

          {/* Card 2 — Tech status */}
          <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-4">
            <p className="text-sm font-semibold text-slate-100">Technology Status</p>

            {warnings.map((w, i) => (
              <div key={i} className="text-xs text-medium bg-medium/10 border border-medium/30 px-3 py-2 rounded-lg">
                ⚠ {w}
              </div>
            ))}

            {matched.length > 0 && (
              <div>
                <p className="text-xs text-slate-400 mb-2 font-medium">⚠️ Affected — CVEs found</p>
                <div className="flex flex-wrap gap-2">
                  {matched.map(t => <Chip key={t} label={t} variant="red" />)}
                </div>
              </div>
            )}

            {clean.length > 0 && (
              <div>
                <p className="text-xs text-slate-400 mb-2 font-medium">✅ Clear — No matches in this dataset</p>
                <div className="flex flex-wrap gap-2">
                  {clean.map(t => <Chip key={t} label={t} variant="green" />)}
                </div>
              </div>
            )}

            {matched.length === 0 && clean.length === 0 && (
              <p className="text-sm text-slate-400">No technologies were processed.</p>
            )}
          </div>

          {/* Card 3 — CVE table */}
          <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-4">
            <p className="text-sm font-semibold text-slate-100">Top CVEs by Risk Score</p>

            {topCVEs.length === 0 ? (
              <p className="text-sm text-slate-400">
                No CVEs found for your stack in this dataset. Try different technology names.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-slate-400 border-b border-border">
                      {['CVE ID', 'Severity', 'CVSS', 'EPSS', 'Risk', 'Matched Tech', 'Published'].map(h => (
                        <th key={h} className="text-left py-2 pr-4 font-medium whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {topCVEs.map(cve => (
                      <tr key={cve.cve_id} className="border-b border-border/50 hover:bg-white/5 transition-colors">
                        <td className="py-2 pr-4 whitespace-nowrap">
                          <button
                            onClick={() => navigate(`/advisor?cve=${cve.cve_id}`)}
                            className="text-brand hover:underline font-medium"
                          >
                            {cve.cve_id}
                          </button>
                        </td>
                        <td className="py-2 pr-4">
                          <SeverityBadge severity={cve.severity} />
                        </td>
                        <td className="py-2 pr-4 text-slate-300">
                          {cve.cvss_score != null ? Number(cve.cvss_score).toFixed(1) : '—'}
                        </td>
                        <td className="py-2 pr-4 text-slate-300">
                          {cve.epss_score != null ? Number(cve.epss_score).toFixed(4) : '—'}
                        </td>
                        <td className="py-2 pr-4 font-semibold text-slate-200">
                          {cve.risk_score != null ? Number(cve.risk_score).toFixed(2) : '—'}
                        </td>
                        <td className="py-2 pr-4 text-slate-400">{cve.matched_tech}</td>
                        <td className="py-2 text-slate-400 whitespace-nowrap">
                          {(cve.published_date || '').slice(0, 10)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Card 4 — AI report */}
          <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-4" ref={reportRef}>
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-slate-100">🤖 AI Risk Report</p>
              {!reportStreaming && !report && (
                <button
                  onClick={startReport}
                  className="px-4 py-1.5 rounded-lg bg-brand hover:bg-brand/80 text-white text-xs font-medium transition-colors"
                >
                  Generate Report
                </button>
              )}
              {reportDone && (
                <button
                  onClick={startReport}
                  className="px-4 py-1.5 rounded-lg border border-border hover:bg-white/5 text-slate-400 text-xs transition-colors"
                >
                  Regenerate Report
                </button>
              )}
            </div>

            {reportStreaming && !report && (
              <div className="flex items-center gap-2 text-slate-400 text-sm">
                <Spinner />
                Generating report…
              </div>
            )}

            {reportError && (
              <p className="text-xs text-red-400">{reportError}</p>
            )}

            {report && (
              <p className="text-sm text-slate-200 leading-relaxed whitespace-pre-wrap font-mono bg-surface rounded-xl p-4 border border-border">
                {report}
              </p>
            )}
          </div>
        </>
      )}
    </div>
  )
}
