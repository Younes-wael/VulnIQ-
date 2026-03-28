import { useState, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { scanSBOM, exportSBOMPDF } from '../lib/api'
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

const SECTION_LABEL_STYLE = {
  fontFamily: "'Consolas','Courier New',monospace",
  fontSize: '0.65rem',
  color: '#475569',
  textTransform: 'uppercase',
  letterSpacing: '0.1em',
  marginBottom: '10px',
  display: 'block',
}

const SUPPORTED_FORMATS = ['requirements.txt', 'package.json', 'pom.xml', '.csproj', 'cyclonedx.json']

export default function SBOMScanner() {
  const navigate = useNavigate()
  const fileInputRef = useRef(null)

  const [dragging, setDragging] = useState(false)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState(null)
  const [result, setResult]     = useState(null)
  const [fileName, setFileName] = useState('')

  const [exporting, setExporting]     = useState(false)
  const [exportError, setExportError] = useState('')

  const processFile = useCallback(async (file) => {
    setLoading(true)
    setError(null)
    setResult(null)
    setFileName(file.name)
    try {
      const data = await scanSBOM(file)
      setResult(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  function handleFileInput(e) {
    const file = e.target.files?.[0]
    if (file) processFile(file)
    e.target.value = ''
  }

  function handleDrop(e) {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files?.[0]
    if (file) processFile(file)
  }

  function handleReset() {
    setResult(null)
    setError(null)
    setFileName('')
  }

  const {
    packages = [],
    vulnerabilities = [],
    total_packages = 0,
    vulnerable_packages = 0,
    total_vulnerabilities = 0,
    elapsed_ms = 0,
  } = result || {}

  const criticalCount = vulnerabilities.filter(v => (v.severity || '').toUpperCase() === 'CRITICAL').length

  return (
    <div className="max-w-3xl mx-auto flex flex-col gap-6 pb-8 animate-fadein">

      {/* ── Header ── */}
      <div>
        <div style={{ width: '32px', height: '3px', borderRadius: '2px', background: '#8b5cf6', marginBottom: '8px', display: 'block' }} />
        <h1 className="text-2xl font-bold text-slate-100">SBOM Scanner</h1>
        <p className="text-slate-400 text-sm mt-1">
          Upload a dependency file to scan for known CVEs in your software supply chain
        </p>
      </div>

      {/* ── Upload card ── */}
      {!result && !loading && (
        <div
          onDragOver={e => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className="bg-card border-2 border-dashed rounded-xl p-10 flex flex-col items-center gap-4 cursor-pointer transition-colors"
          style={{
            borderColor: dragging ? '#8b5cf6' : '#334155',
            background: dragging ? 'rgba(139,92,246,0.05)' : undefined,
          }}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".txt,.json,.xml,.csproj"
            onChange={handleFileInput}
            className="hidden"
          />

          <div style={{
            width: '48px',
            height: '48px',
            borderRadius: '12px',
            background: 'rgba(139,92,246,0.1)',
            border: '1px solid rgba(139,92,246,0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#8b5cf6" strokeWidth="1.5">
              <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
              <polyline points="17 8 12 3 7 8"/>
              <line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
          </div>

          <div className="text-center">
            <p className="text-slate-200 font-medium text-sm">
              {dragging ? 'Drop to scan' : 'Drop your dependency file here'}
            </p>
            <p className="text-slate-500 text-xs mt-1">or click to browse</p>
          </div>

          <div className="flex flex-wrap gap-2 justify-center">
            {SUPPORTED_FORMATS.map(f => (
              <span key={f} style={{
                fontSize: '0.7rem',
                padding: '2px 8px',
                borderRadius: '4px',
                background: 'rgba(139,92,246,0.1)',
                border: '1px solid rgba(139,92,246,0.2)',
                color: '#a78bfa',
                fontFamily: "'Consolas','Courier New',monospace",
              }}>
                {f}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── Loading ── */}
      {loading && (
        <div className="bg-card border border-border rounded-xl p-8 flex flex-col items-center gap-3">
          <Spinner />
          <p className="text-slate-400 text-sm">
            Scanning{' '}
            <span style={{ color: '#a78bfa', fontFamily: "'Consolas','Courier New',monospace" }}>
              {fileName}
            </span>
            …
          </p>
        </div>
      )}

      {/* ── Error ── */}
      {error && (
        <div className="bg-critical/10 border border-critical/40 rounded-xl px-4 py-3 flex items-start justify-between gap-3">
          <p className="text-sm text-red-300">{error}</p>
          <button
            onClick={handleReset}
            className="text-xs text-slate-400 hover:text-slate-100 whitespace-nowrap transition-colors"
          >
            Try again
          </button>
        </div>
      )}

      {/* ── Results ── */}
      {result && (
        <>
          {/* File info + reset */}
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <span style={{ fontFamily: "'Consolas','Courier New',monospace", fontSize: '0.8rem', color: '#a78bfa' }}>
                {fileName}
              </span>
              <span style={{ fontSize: '0.7rem', color: '#475569' }}>
                · scanned in {elapsed_ms}ms
              </span>
            </div>
            <div className="flex items-center gap-2">
              {result && result.total_vulnerabilities > 0 && (
                <>
                  <button
                    disabled={exporting}
                    onClick={async () => {
                      setExporting(true)
                      setExportError('')
                      try {
                        await exportSBOMPDF({ ...result, filename: fileName })
                      } catch {
                        setExportError('Export failed')
                        setTimeout(() => setExportError(''), 3000)
                      } finally {
                        setExporting(false)
                      }
                    }}
                    style={{
                      fontSize: '0.75rem',
                      padding: '4px 10px',
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
                </>
              )}
              <button
                onClick={handleReset}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border bg-surface hover:bg-white/5 text-slate-400 text-xs transition-colors"
              >
                Scan New File
              </button>
            </div>
          </div>

          {/* Metrics */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <MetricTile label="Packages Scanned" value={total_packages} />
            <MetricTile
              label="Vulnerable"
              value={vulnerable_packages}
              color={vulnerable_packages > 0 ? '#ef4444' : undefined}
            />
            <MetricTile
              label="Critical CVEs"
              value={criticalCount}
              color={criticalCount > 0 ? '#ef4444' : undefined}
            />
            <MetricTile label="Total CVEs Found" value={total_vulnerabilities} />
          </div>

          {/* All clear */}
          {total_vulnerabilities === 0 && (
            <div className="bg-card border border-border rounded-xl p-6 text-center">
              <p className="text-slate-300 text-sm font-medium">
                No known CVEs found for this dependency set.
              </p>
              <p className="text-slate-500 text-xs mt-1">
                This dataset covers NVD data. Results may not reflect all vulnerabilities.
              </p>
            </div>
          )}

          {/* Affected packages table */}
          {packages.some(p => p.matched) && (
            <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-3">
              <p style={SECTION_LABEL_STYLE}>Affected Packages</p>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-slate-400 border-b border-border">
                      {['Package', 'Version', 'CVEs', 'Max CVSS', 'Max Severity'].map(h => (
                        <th key={h} className="text-left py-2 pr-4 font-medium whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {packages
                      .filter(p => p.matched)
                      .sort((a, b) => (b.max_cvss || 0) - (a.max_cvss || 0))
                      .map(pkg => (
                        <tr key={pkg.name} className="border-b border-border/50 hover:bg-white/5 transition-colors">
                          <td className="py-2 pr-4 whitespace-nowrap" style={{ fontFamily: "'Consolas','Courier New',monospace", color: '#e2e8f0' }}>
                            {pkg.name}
                          </td>
                          <td className="py-2 pr-4 text-slate-400">{pkg.version || '—'}</td>
                          <td className="py-2 pr-4 text-slate-300">{pkg.cve_count}</td>
                          <td className="py-2 pr-4 text-slate-300">
                            {pkg.max_cvss != null ? Number(pkg.max_cvss).toFixed(1) : '—'}
                          </td>
                          <td className="py-2 pr-4">
                            <SeverityBadge severity={pkg.max_severity} />
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* CVE details */}
          {vulnerabilities.length > 0 && (
            <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-3">
              <p style={SECTION_LABEL_STYLE}>CVE Details ({vulnerabilities.length})</p>
              <div className="flex flex-col gap-2">
                {vulnerabilities.map(vuln => (
                  <div
                    key={vuln.cve_id}
                    className="bg-surface border border-border rounded-lg p-4 flex flex-col gap-2"
                  >
                    <div className="flex items-start justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2 flex-wrap">
                        <button
                          onClick={() => navigate(`/advisor?cve=${vuln.cve_id}`)}
                          className="text-brand hover:underline font-medium text-sm"
                          style={{ fontFamily: "'Consolas','Courier New',monospace" }}
                        >
                          {vuln.cve_id}
                        </button>
                        <SeverityBadge severity={vuln.severity} />
                        {vuln.cvss_score != null && (
                          <span style={{
                            fontSize: '0.7rem',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            background: 'rgba(100,116,139,0.2)',
                            color: '#94a3b8',
                          }}>
                            CVSS {Number(vuln.cvss_score).toFixed(1)}
                          </span>
                        )}
                      </div>
                      <span style={{ fontSize: '0.7rem', color: '#475569', flexShrink: 0 }}>
                        via{' '}
                        <span style={{ color: '#a78bfa', fontFamily: "'Consolas','Courier New',monospace" }}>
                          {vuln.matched_package}
                        </span>
                      </span>
                    </div>

                    <p className="text-slate-400 text-xs leading-relaxed" style={{
                      display: '-webkit-box',
                      WebkitLineClamp: 3,
                      WebkitBoxOrient: 'vertical',
                      overflow: 'hidden',
                    }}>
                      {vuln.description}
                    </p>

                    <div className="flex items-center justify-between">
                      <span style={{ fontSize: '0.65rem', color: '#475569' }}>
                        Published {(vuln.published_date || '').slice(0, 10) || '—'}
                      </span>
                      <button
                        onClick={() => navigate(`/advisor?cve=${vuln.cve_id}`)}
                        className="text-xs text-brand hover:text-brand/80 transition-colors"
                      >
                        Patch Advisor →
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Clear packages */}
          {packages.some(p => !p.matched) && (
            <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-3">
              <p style={SECTION_LABEL_STYLE}>
                Clear Packages ({packages.filter(p => !p.matched).length})
              </p>
              <div className="flex flex-wrap gap-2">
                {packages.filter(p => !p.matched).map(pkg => (
                  <span key={pkg.name} style={{
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
                    fontFamily: "'Consolas','Courier New',monospace",
                  }}>
                    ✓ {pkg.name}
                  </span>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
