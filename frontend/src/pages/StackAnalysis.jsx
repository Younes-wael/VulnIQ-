import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { analyzeStack, streamStackReport, exportStackPDF } from '../lib/api'
import MetricTile from '../components/MetricTile'
import SeverityBadge from '../components/SeverityBadge'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

function Spinner() {
  return (
    <svg className="w-4 h-4 animate-spin text-brand" fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
    </svg>
  )
}

function Chip({ label, count, variant }) {
  if (variant === 'red') {
    return (
      <span style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        fontSize: '0.75rem',
        padding: '4px 10px',
        borderRadius: '9999px',
        border: '1px solid rgba(239,68,68,0.3)',
        background: 'rgba(239,68,68,0.1)',
        color: '#fca5a5',
        fontWeight: 500,
      }}>
        ⚠ {label}{count != null ? ` (${count})` : ''}
      </span>
    )
  }
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '4px',
      fontSize: '0.75rem',
      padding: '4px 10px',
      borderRadius: '9999px',
      border: '1px solid rgba(34,197,94,0.3)',
      background: 'rgba(34,197,94,0.1)',
      color: '#86efac',
      fontWeight: 500,
    }}>
      ✓ {label} · clear
    </span>
  )
}

const SECTION_LABEL_STYLE = {
  fontFamily: "'Consolas','Courier New',monospace",
  fontSize: '0.65rem',
  color: '#475569',
  textTransform: 'uppercase',
  letterSpacing: '0.1em',
  marginBottom: '10px',
  display: 'block',
}

export default function StackAnalysis() {
  const navigate = useNavigate()

  const [stackInput, setStackInput]   = useState('')
  const [warning, setWarning]         = useState('')
  const [loading, setLoading]         = useState(false)
  const [error, setError]             = useState(null)
  const [analysis, setAnalysis]       = useState(null)
  const [techList, setTechList]       = useState([])
  const [techFilter, setTechFilter]   = useState(null)

  const [report, setReport]           = useState('')
  const [reportStreaming, setReportStreaming] = useState(false)
  const [reportDone, setReportDone]   = useState(false)
  const [reportError, setReportError] = useState(null)

  const [exporting, setExporting]     = useState(false)
  const [exportError, setExportError] = useState('')

  const reportRef   = useRef(null)
  const cveTableRef = useRef(null)

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
    setTechFilter(null)

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
    setTechFilter(null)
  }

  function startReport() {
    setReport('')
    setReportError(null)
    setReportDone(false)
    setReportStreaming(true)
    streamStackReport(
      techList,
      analysis,
      (token) => setReport(prev => prev + token),
      (err)   => { setReportError(err); setReportStreaming(false) },
      ()      => { setReportStreaming(false); setReportDone(true) },
    )
  }

  const matched  = analysis?.technologies_matched ?? []
  const clean    = analysis?.technologies_clean   ?? []
  const topCVEs  = analysis?.top_cves             ?? []
  const warnings = analysis?.warnings             ?? []

  // Group topCVEs by matched_tech for TOP RISK TECHNOLOGIES
  const techGroups = topCVEs.reduce((acc, cve) => {
    const t = cve.matched_tech
    if (!acc[t]) acc[t] = { name: t, total: 0, critical: 0, high: 0, maxRisk: 0 }
    acc[t].total++
    if ((cve.severity || '').toUpperCase() === 'CRITICAL') acc[t].critical++
    if ((cve.severity || '').toUpperCase() === 'HIGH') acc[t].high++
    if (cve.risk_score != null && cve.risk_score > acc[t].maxRisk) acc[t].maxRisk = cve.risk_score
    return acc
  }, {})

  const topRiskTechs = Object.values(techGroups)
    .sort((a, b) => b.critical - a.critical || b.total - a.total)
    .slice(0, 5)

  // CVE count per tech for chips
  const cveCountByTech = topCVEs.reduce((acc, cve) => {
    acc[cve.matched_tech] = (acc[cve.matched_tech] || 0) + 1
    return acc
  }, {})

  // Filtered CVEs for the table
  const displayCVEs = techFilter
    ? topCVEs.filter(c => c.matched_tech === techFilter)
    : topCVEs

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
    <div className="max-w-3xl mx-auto flex flex-col gap-6 pb-8 animate-fadein">
      <div>
        <div style={{ width: '32px', height: '3px', borderRadius: '2px', background: '#ef4444', marginBottom: '8px', display: 'block' }} />
        <h1 className="text-2xl font-bold text-slate-100">Tech Stack Analysis</h1>
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
        <div>
          <p style={SECTION_LABEL_STYLE}>Tips</p>
          {[
            'Use general package names: openssl, django, redis',
            'Avoid version strings like OpenSSL 3.0.1',
            'Avoid vague names like microsoft or linux',
          ].map(tip => (
            <div key={tip} className="flex items-start gap-1.5" style={{ lineHeight: 1.6 }}>
              <span style={{ color: '#3b82f6', fontSize: '0.78rem', flexShrink: 0 }}>›</span>
              <span style={{ fontSize: '0.78rem', color: '#64748b' }}>{tip}</span>
            </div>
          ))}
        </div>

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
              Analyze New Stack
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

          {/* TOP RISK TECHNOLOGIES */}
          {topRiskTechs.length > 0 && (
            <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-3">
              <p style={SECTION_LABEL_STYLE}>Top Risk Technologies</p>
              {topRiskTechs.map((tech, i) => {
                const isActive = techFilter === tech.name
                return (
                  <div
                    key={tech.name}
                    onClick={() => {
                      if (isActive) {
                        setTechFilter(null)
                      } else {
                        setTechFilter(tech.name)
                        cveTableRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
                      }
                    }}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      padding: '10px 0',
                      borderBottom: i < topRiskTechs.length - 1 ? '1px solid #1e293b' : 'none',
                      cursor: 'pointer',
                      borderRadius: isActive ? '6px' : undefined,
                      background: isActive ? 'rgba(59,130,246,0.05)' : 'transparent',
                      paddingLeft: isActive ? '8px' : '0',
                      paddingRight: isActive ? '8px' : '0',
                      transition: 'background 0.15s, padding 0.15s',
                    }}
                    onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = '#0f172a' }}
                    onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = 'transparent' }}
                  >
                    <span style={{
                      fontFamily: "'Consolas','Courier New',monospace",
                      fontSize: '0.9rem',
                      fontWeight: 700,
                      color: isActive ? '#93c5fd' : '#e2e8f0',
                      minWidth: '100px',
                    }}>
                      {tech.name}
                    </span>
                    <div className="flex items-center gap-2 flex-wrap">
                      {tech.critical > 0 && (
                        <span style={{
                          fontSize: '0.7rem',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          background: 'rgba(239,68,68,0.15)',
                          border: '1px solid rgba(239,68,68,0.3)',
                          color: '#fca5a5',
                          fontWeight: 600,
                        }}>
                          {tech.critical} critical
                        </span>
                      )}
                      {tech.high > 0 && (
                        <span style={{
                          fontSize: '0.7rem',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          background: 'rgba(249,115,22,0.15)',
                          border: '1px solid rgba(249,115,22,0.3)',
                          color: '#fdba74',
                          fontWeight: 600,
                        }}>
                          {tech.high} high
                        </span>
                      )}
                    </div>
                    <span style={{ marginLeft: 'auto', fontSize: '0.8rem', color: '#475569', flexShrink: 0 }}>
                      risk {tech.maxRisk.toFixed(2)}
                    </span>
                    <span style={{ fontSize: '0.75rem', color: isActive ? '#3b82f6' : '#334155' }}>
                      {isActive ? '× clear' : '→'}
                    </span>
                  </div>
                )
              })}
              {techFilter && (
                <p style={{ fontSize: '0.72rem', color: '#3b82f6', marginTop: '2px' }}>
                  Filtering CVE table by <strong>{techFilter}</strong> — click row again to clear
                </p>
              )}
            </div>
          )}

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
                <p className="text-xs text-slate-400 mb-2 font-medium">Affected — CVEs found</p>
                <div className="flex flex-wrap gap-2">
                  {matched.map(t => (
                    <Chip
                      key={t}
                      label={t}
                      count={cveCountByTech[t] ?? null}
                      variant="red"
                    />
                  ))}
                </div>
              </div>
            )}

            {clean.length > 0 && (
              <div>
                <p className="text-xs text-slate-400 mb-2 font-medium">Clear — No matches in this dataset</p>
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
          <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-4" ref={cveTableRef}>
            <div className="flex items-center justify-between gap-2">
              <p className="text-sm font-semibold text-slate-100">Top CVEs by Risk Score</p>
              {techFilter && (
                <span style={{
                  fontSize: '0.7rem',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  background: 'rgba(59,130,246,0.1)',
                  border: '1px solid rgba(59,130,246,0.3)',
                  color: '#93c5fd',
                }}>
                  Filtered: {techFilter}
                </span>
              )}
            </div>

            {displayCVEs.length === 0 ? (
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
                    {displayCVEs.map(cve => (
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
              <p className="text-sm font-semibold text-slate-100">AI Risk Report</p>
              <div className="flex items-center gap-2">
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
                <button
                  disabled={exporting}
                  onClick={async () => {
                    setExporting(true)
                    setExportError('')
                    try {
                      await exportStackPDF(techList.join(', '), analysis, report)
                    } catch {
                      setExportError('Export failed')
                      setTimeout(() => setExportError(''), 3000)
                    } finally {
                      setExporting(false)
                    }
                  }}
                  style={{
                    fontSize: '0.75rem',
                    padding: '3px 10px',
                    borderRadius: '6px',
                    background: 'transparent',
                    border: '1px solid #334155',
                    color: exporting ? '#475569' : '#94a3b8',
                    cursor: exporting ? 'not-allowed' : 'pointer',
                    opacity: exporting ? 0.6 : 1,
                    transition: 'border-color 0.15s, color 0.15s',
                  }}
                  onMouseEnter={e => { if (!exporting) { e.currentTarget.style.borderColor = '#ef4444'; e.currentTarget.style.color = '#ef4444' } }}
                  onMouseLeave={e => { if (!exporting) { e.currentTarget.style.borderColor = '#334155'; e.currentTarget.style.color = '#94a3b8' } }}
                >
                  {exporting ? 'Exporting…' : '↓ Export PDF'}
                </button>
                {exportError && (
                  <span style={{ fontSize: '0.7rem', color: '#ef4444' }}>{exportError}</span>
                )}
              </div>
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
              <div className="bg-slate-900 rounded-xl p-6 border border-slate-700 text-sm leading-relaxed">
                <ReactMarkdown remarkPlugins={[remarkGfm]} components={markdownComponents}>
                  {report}
                </ReactMarkdown>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
