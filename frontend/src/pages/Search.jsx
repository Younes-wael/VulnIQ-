import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { searchCVEs } from '../lib/api'
import SeverityBadge from '../components/SeverityBadge'

const SEV_OPTIONS = [
  { label: 'CRITICAL', color: 'bg-critical' },
  { label: 'HIGH',     color: 'bg-high' },
  { label: 'MEDIUM',   color: 'bg-medium' },
  { label: 'LOW',      color: 'bg-low' },
]

const SEV_ACCENT = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
}

const EMPTY_FILTERS = {
  severities: [],
  year_from: '',
  year_to: '',
  vendor: '',
  cvss_min: '',
  cvss_max: '',
  keyword: '',
}

function SkeletonCard() {
  return (
    <div className="bg-card border border-border rounded-xl p-4 flex flex-col gap-3 animate-pulse">
      <div className="flex justify-between">
        <div className="h-4 w-32 bg-slate-700 rounded" />
        <div className="h-4 w-16 bg-slate-700 rounded-full" />
      </div>
      <div className="h-3 w-48 bg-slate-700 rounded" />
      <div className="h-3 w-full bg-slate-700 rounded" />
      <div className="h-3 w-4/5 bg-slate-700 rounded" />
    </div>
  )
}

function ResultRow({ cve, onClick }) {
  const upper = (cve.severity || '').toUpperCase()
  const accentColor = SEV_ACCENT[upper] ?? '#334155'

  const vendorList = Array.isArray(cve.vendors)
    ? cve.vendors
    : (cve.vendors || '').split(',').map(v => v.trim()).filter(Boolean)

  const productList = Array.isArray(cve.products)
    ? cve.products
    : (cve.products || '').split(',').map(p => p.trim()).filter(Boolean)

  const hasBottom = vendorList.length > 0 || productList.length > 0
  const displayVendors = vendorList.slice(0, 3)
  const extraVendors = vendorList.length - 3

  return (
    <div
      onClick={onClick}
      style={{
        background: '#1e293b',
        borderLeft: `3px solid ${accentColor}`,
        borderRadius: '8px',
        padding: '14px 16px',
        cursor: 'pointer',
        transition: 'background 0.15s',
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
      }}
      onMouseEnter={e => e.currentTarget.style.background = '#263548'}
      onMouseLeave={e => e.currentTarget.style.background = '#1e293b'}
    >
      {/* Top line */}
      <div className="flex items-center gap-3 flex-wrap">
        <span style={{
          fontFamily: "'Consolas','Courier New',monospace",
          fontSize: '0.9rem',
          fontWeight: 600,
          color: '#3b82f6',
          flexShrink: 0,
        }}>
          {cve.cve_id}
        </span>
        <SeverityBadge severity={cve.severity} />
        <div className="flex items-center gap-3 ml-auto text-xs text-slate-500 flex-wrap">
          {cve.cvss_score != null && (
            <span>CVSS <span style={{ color: '#cbd5e1', fontWeight: 500 }}>{Number(cve.cvss_score).toFixed(1)}</span></span>
          )}
          {cve.published_date && (
            <span>{cve.published_date.slice(0, 10)}</span>
          )}
          {vendorList[0] && (
            <span style={{
              background: 'rgba(6,182,212,0.1)',
              color: '#22d3ee',
              border: '1px solid rgba(6,182,212,0.2)',
              borderRadius: '4px',
              padding: '1px 8px',
              fontFamily: "'Consolas','Courier New',monospace",
              fontSize: '0.7rem',
            }}>
              {vendorList[0]}
            </span>
          )}
        </div>
      </div>

      {/* Description */}
      {cve.description && (
        <p style={{
          fontSize: '0.82rem',
          color: '#94a3b8',
          lineHeight: 1.5,
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
        }}>
          {cve.description}
        </p>
      )}

      {/* Bottom line */}
      {hasBottom && (
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex flex-wrap gap-1">
            {displayVendors.map(v => (
              <span key={v} style={{
                fontSize: '0.7rem',
                color: '#64748b',
                background: '#0f172a',
                border: '1px solid #1e293b',
                borderRadius: '4px',
                padding: '1px 7px',
              }}>{v}</span>
            ))}
            {extraVendors > 0 && (
              <span style={{ fontSize: '0.7rem', color: '#475569' }}>+{extraVendors} more</span>
            )}
          </div>
          <span style={{ fontSize: '0.75rem', color: '#3b82f6', flexShrink: 0 }}>
            → Patch Advisor
          </span>
        </div>
      )}
    </div>
  )
}

function DetailDrawer({ cve, onClose }) {
  const navigate = useNavigate()
  if (!cve) return null

  const vendorList = Array.isArray(cve.vendors)
    ? cve.vendors
    : (cve.vendors || '').split(',').map(v => v.trim()).filter(Boolean)
  const productList = Array.isArray(cve.products)
    ? cve.products
    : (cve.products || '').split(',').map(p => p.trim()).filter(Boolean)

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-30 bg-black/50"
        onClick={onClose}
      />
      {/* Drawer */}
      <aside className="fixed inset-y-0 right-0 z-40 w-full max-w-lg bg-card border-l border-border flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-start justify-between gap-3 px-5 py-4 border-b border-border">
          <div className="flex flex-col gap-1.5">
            <span className="font-bold text-brand text-base">{cve.cve_id}</span>
            <SeverityBadge severity={cve.severity} />
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-100 mt-0.5 flex-shrink-0"
            aria-label="Close"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 flex flex-col gap-4 text-sm">
          {/* Meta */}
          <div className="flex flex-wrap gap-x-6 gap-y-1 text-slate-400">
            {cve.cvss_score != null && (
              <span>CVSS <span className="text-slate-200 font-semibold">{Number(cve.cvss_score).toFixed(1)}</span></span>
            )}
            {cve.published_date && (
              <span>Published <span className="text-slate-200">{cve.published_date.slice(0, 10)}</span></span>
            )}
            {cve.last_modified && (
              <span>Modified <span className="text-slate-200">{cve.last_modified.slice(0, 10)}</span></span>
            )}
          </div>

          {/* Description */}
          <div>
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Description</p>
            <p className="text-slate-200 leading-relaxed">{cve.description || 'No description available.'}</p>
          </div>

          {/* Vendors */}
          {vendorList.length > 0 && (
            <div>
              <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Vendors</p>
              <div className="flex flex-wrap gap-1">
                {vendorList.map(v => (
                  <span key={v} className="text-xs bg-surface border border-border px-2 py-0.5 rounded-full text-slate-300">{v}</span>
                ))}
              </div>
            </div>
          )}

          {/* Products */}
          {productList.length > 0 && (
            <div>
              <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Products</p>
              <div className="flex flex-wrap gap-1">
                {productList.map(p => (
                  <span key={p} className="text-xs bg-surface border border-border px-2 py-0.5 rounded-full text-slate-300">{p}</span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-4 border-t border-border flex flex-col gap-2">
          <button
            onClick={() => { onClose(); navigate(`/advisor?cve=${cve.cve_id}`) }}
            className="w-full py-2 rounded-xl bg-brand hover:bg-brand/80 text-white text-sm font-medium transition-colors"
          >
            View in Patch Advisor
          </button>
          <a
            href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
            target="_blank"
            rel="noopener noreferrer"
            className="w-full py-2 rounded-xl border border-border bg-surface hover:bg-white/5 text-slate-300 text-sm font-medium text-center transition-colors"
          >
            View on NVD ↗
          </a>
        </div>
      </aside>
    </>
  )
}

export default function Search() {
  const [filters, setFilters]         = useState(EMPTY_FILTERS)
  const [results, setResults]         = useState(null)   // null = not searched yet
  const [loading, setLoading]         = useState(false)
  const [elapsed, setElapsed]         = useState(null)
  const [selectedCVE, setSelectedCVE] = useState(null)
  const [error, setError]             = useState(null)

  // Debounce refs for vendor + keyword
  const vendorTimer  = useRef(null)
  const keywordTimer = useRef(null)

  const runSearch = useCallback(async (overrideFilters) => {
    const f = overrideFilters ?? filters
    const params = {}
    if (f.severities.length)   params.severities = f.severities
    if (f.year_from !== '')    params.year_from   = Number(f.year_from)
    if (f.year_to !== '')      params.year_to     = Number(f.year_to)
    if (f.vendor.trim())       params.vendor      = f.vendor.trim()
    if (f.cvss_min !== '')     params.cvss_min    = Number(f.cvss_min)
    if (f.cvss_max !== '')     params.cvss_max    = Number(f.cvss_max)
    if (f.keyword.trim())      params.keyword     = f.keyword.trim()
    params.limit = 100

    setLoading(true)
    setError(null)
    try {
      const data = await searchCVEs(params)
      setResults(data.results)
      setElapsed(data.elapsed_ms)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [filters])

  const clearFilters = () => {
    setFilters(EMPTY_FILTERS)
    setResults(null)
    setElapsed(null)
    setError(null)
  }

  const toggleSeverity = (sev) => {
    setFilters(f => ({
      ...f,
      severities: f.severities.includes(sev)
        ? f.severities.filter(s => s !== sev)
        : [...f.severities, sev],
    }))
  }

  const removeFilter = (updater) => {
    const newF = { ...filters, ...updater }
    setFilters(newF)
    runSearch(newF)
  }

  // Build active filter pills for display
  const activePills = []
  if (filters.severities.length > 0) {
    filters.severities.forEach(s => {
      activePills.push({
        key: `sev-${s}`,
        label: s,
        color: SEV_ACCENT[s] ?? '#475569',
        onRemove: () => removeFilter({ severities: filters.severities.filter(x => x !== s) }),
      })
    })
  }
  if (filters.year_from || filters.year_to) {
    const label = filters.year_from && filters.year_to
      ? `${filters.year_from}–${filters.year_to}`
      : filters.year_from ? `from ${filters.year_from}` : `to ${filters.year_to}`
    activePills.push({
      key: 'year',
      label: `Year: ${label}`,
      color: '#475569',
      onRemove: () => removeFilter({ year_from: '', year_to: '' }),
    })
  }
  if (filters.vendor.trim()) {
    activePills.push({
      key: 'vendor',
      label: `Vendor: ${filters.vendor.trim()}`,
      color: '#475569',
      onRemove: () => removeFilter({ vendor: '' }),
    })
  }
  if (filters.cvss_min || filters.cvss_max) {
    const label = filters.cvss_min && filters.cvss_max
      ? `CVSS ${filters.cvss_min}–${filters.cvss_max}`
      : filters.cvss_min ? `CVSS ≥${filters.cvss_min}` : `CVSS ≤${filters.cvss_max}`
    activePills.push({
      key: 'cvss',
      label,
      color: '#475569',
      onRemove: () => removeFilter({ cvss_min: '', cvss_max: '' }),
    })
  }
  if (filters.keyword.trim()) {
    activePills.push({
      key: 'keyword',
      label: `"${filters.keyword.trim()}"`,
      color: '#475569',
      onRemove: () => removeFilter({ keyword: '' }),
    })
  }

  return (
    <div className="flex gap-0 lg:gap-6 h-full relative animate-fadein">

      {/* ── Filters panel ── */}
      <aside className="hidden lg:flex flex-col w-72 flex-shrink-0 gap-4">
        <div style={{ width: '32px', height: '3px', borderRadius: '2px', background: '#06b6d4', marginBottom: '8px', display: 'block' }} />
        <h2 className="text-base font-semibold text-slate-100">Search & Filter</h2>

        <div className="bg-card border border-border rounded-xl p-4 flex flex-col gap-4">

          {/* Severity */}
          <div>
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">Severity</p>
            <div className="flex flex-col gap-1.5">
              {SEV_OPTIONS.map(({ label, color }) => (
                <label key={label} className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={filters.severities.includes(label)}
                    onChange={() => toggleSeverity(label)}
                    className="accent-brand"
                  />
                  <span className={`w-2 h-2 rounded-full flex-shrink-0 ${color}`} />
                  <span className="text-sm text-slate-300">{label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Year range */}
          <div>
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">Year Range</p>
            <div className="flex items-center gap-2">
              <input
                type="number" min="2000" max="2026"
                value={filters.year_from}
                onChange={e => setFilters(f => ({ ...f, year_from: e.target.value }))}
                placeholder="From"
                className="w-full bg-surface border border-border rounded-lg px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-brand"
              />
              <span className="text-slate-500 flex-shrink-0">–</span>
              <input
                type="number" min="2000" max="2026"
                value={filters.year_to}
                onChange={e => setFilters(f => ({ ...f, year_to: e.target.value }))}
                placeholder="To"
                className="w-full bg-surface border border-border rounded-lg px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-brand"
              />
            </div>
          </div>

          {/* Vendor */}
          <div>
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">Vendor</p>
            <input
              type="text"
              value={filters.vendor}
              onChange={e => setFilters(f => ({ ...f, vendor: e.target.value }))}
              placeholder="e.g. apache"
              className="w-full bg-surface border border-border rounded-lg px-3 py-1.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-brand"
            />
          </div>

          {/* CVSS range */}
          <div>
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">CVSS Score</p>
            <div className="flex items-center gap-2">
              <input
                type="number" min="0" max="10" step="0.1"
                value={filters.cvss_min}
                onChange={e => setFilters(f => ({ ...f, cvss_min: e.target.value }))}
                placeholder="Min"
                className="w-full bg-surface border border-border rounded-lg px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-brand"
              />
              <span className="text-slate-500 flex-shrink-0">–</span>
              <input
                type="number" min="0" max="10" step="0.1"
                value={filters.cvss_max}
                onChange={e => setFilters(f => ({ ...f, cvss_max: e.target.value }))}
                placeholder="Max"
                className="w-full bg-surface border border-border rounded-lg px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-brand"
              />
            </div>
          </div>

          {/* Keyword */}
          <div>
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">Keyword</p>
            <input
              type="text"
              value={filters.keyword}
              onChange={e => setFilters(f => ({ ...f, keyword: e.target.value }))}
              placeholder="Search in description"
              className="w-full bg-surface border border-border rounded-lg px-3 py-1.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-brand"
            />
          </div>

          {/* Buttons */}
          <button
            onClick={() => runSearch()}
            disabled={loading}
            className="w-full py-2 rounded-xl bg-brand hover:bg-brand/80 disabled:opacity-50 text-white text-sm font-medium transition-colors"
          >
            {loading ? 'Searching…' : 'Search'}
          </button>
          <button
            onClick={clearFilters}
            className="w-full py-2 rounded-xl border border-border bg-surface hover:bg-white/5 text-slate-400 text-sm transition-colors"
          >
            Clear Filters
          </button>

          {/* Result summary */}
          {results !== null && !loading && (
            <p className="text-xs text-slate-500 text-center">
              {results.length} result{results.length !== 1 ? 's' : ''} in {elapsed?.toFixed(1)}ms
            </p>
          )}
        </div>
      </aside>

      {/* ── Results area ── */}
      <div className="flex-1 flex flex-col gap-3 min-w-0">

        {/* Mobile search button */}
        <div className="flex lg:hidden gap-2">
          <input
            type="text"
            value={filters.keyword}
            onChange={e => setFilters(f => ({ ...f, keyword: e.target.value }))}
            onKeyDown={e => e.key === 'Enter' && runSearch()}
            placeholder="Keyword search…"
            className="flex-1 bg-card border border-border rounded-xl px-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-brand"
          />
          <button
            onClick={() => runSearch()}
            disabled={loading}
            className="px-4 py-2.5 rounded-xl bg-brand hover:bg-brand/80 disabled:opacity-50 text-white text-sm font-medium transition-colors"
          >
            {loading ? '…' : 'Search'}
          </button>
        </div>

        {error && (
          <div className="bg-critical/10 border border-critical/40 rounded-xl px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        {/* Loading skeletons */}
        {loading && (
          <div className="flex flex-col gap-3">
            <SkeletonCard /><SkeletonCard /><SkeletonCard />
          </div>
        )}

        {/* No results */}
        {!loading && results !== null && results.length === 0 && (
          <div className="flex flex-col items-center justify-center py-20 text-slate-500 gap-2">
            <p className="text-sm">No results. Try adjusting your filters.</p>
          </div>
        )}

        {/* Results with filter summary bar */}
        {!loading && results !== null && results.length > 0 && (
          <>
            {/* Filter summary bar */}
            <div className="flex items-center justify-between flex-wrap gap-2">
              <p className="text-sm text-slate-400">
                Showing <span className="font-semibold text-slate-200">{results.length}</span> result{results.length !== 1 ? 's' : ''}
                {elapsed != null && <span className="ml-1 text-slate-500">· {elapsed.toFixed(1)}ms</span>}
              </p>
              {activePills.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {activePills.map(pill => (
                    <span
                      key={pill.key}
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '5px',
                        fontSize: '0.7rem',
                        fontFamily: "'Consolas','Courier New',monospace",
                        padding: '3px 8px',
                        borderRadius: '4px',
                        background: pill.color + '1a',
                        border: `1px solid ${pill.color}44`,
                        color: '#94a3b8',
                      }}
                    >
                      {pill.label}
                      <button
                        onClick={pill.onRemove}
                        style={{ color: '#64748b', lineHeight: 1, cursor: 'pointer', background: 'none', border: 'none', padding: 0, fontSize: '0.75rem' }}
                        onMouseEnter={e => e.currentTarget.style.color = '#cbd5e1'}
                        onMouseLeave={e => e.currentTarget.style.color = '#64748b'}
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>
            {results.length === 100 && (
              <p className="text-xs text-medium bg-medium/10 border border-medium/30 px-3 py-1.5 rounded-lg">
                Showing first 100 results — refine your filters to see more
              </p>
            )}

            {/* Result rows */}
            <div className="flex flex-col overflow-y-auto" style={{ gap: '8px' }}>
              {results.map(cve => (
                <ResultRow
                  key={cve.cve_id}
                  cve={cve}
                  onClick={() => setSelectedCVE(cve)}
                />
              ))}
            </div>
          </>
        )}

        {/* Not yet searched */}
        {!loading && results === null && !error && (
          <div className="flex flex-col gap-5 py-10 max-w-sm">
            {/* Helper text */}
            <div>
              <p style={{ fontSize: '0.95rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
                Search the NVD database
              </p>
              <p style={{ fontSize: '0.8rem', color: '#64748b', maxWidth: '340px', lineHeight: 1.5 }}>
                Filter by severity, vendor, year, CVSS score, or keyword to find relevant vulnerabilities
              </p>
            </div>

            <div style={{ height: '1px', background: '#1e293b' }} />

            {/* Suggestion chips */}
            <div>
              <p style={{
                fontFamily: "'Consolas','Courier New',monospace",
                fontSize: '0.65rem',
                color: '#475569',
                textTransform: 'uppercase',
                letterSpacing: '0.1em',
                marginBottom: '10px',
              }}>Try searching for</p>
              <div className="flex flex-wrap gap-2">
                {['openssl', 'apache', 'nginx', 'log4j'].map(term => (
                  <button
                    key={term}
                    onClick={() => {
                      const newF = { ...filters, keyword: term }
                      setFilters(newF)
                      runSearch(newF)
                    }}
                    style={{
                      background: '#0f172a',
                      border: '1px solid #334155',
                      borderRadius: '6px',
                      padding: '4px 12px',
                      fontSize: '0.8rem',
                      fontFamily: "'Consolas','Courier New',monospace",
                      color: '#94a3b8',
                      cursor: 'pointer',
                      transition: 'border-color 0.15s, color 0.15s',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = '#3b82f6'; e.currentTarget.style.color = '#e2e8f0' }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = '#334155'; e.currentTarget.style.color = '#94a3b8' }}
                  >
                    {term}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ height: '1px', background: '#1e293b' }} />

            {/* Quick filters */}
            <div>
              <p style={{
                fontFamily: "'Consolas','Courier New',monospace",
                fontSize: '0.65rem',
                color: '#475569',
                textTransform: 'uppercase',
                letterSpacing: '0.1em',
                marginBottom: '10px',
              }}>Quick filters</p>
              <div className="flex flex-col gap-2">
                {[
                  {
                    label: 'Critical CVEs (2023–2024)',
                    apply: { ...EMPTY_FILTERS, severities: ['CRITICAL'], year_from: '2023', year_to: '2024' },
                  },
                  {
                    label: 'High severity Apache vulnerabilities',
                    apply: { ...EMPTY_FILTERS, severities: ['HIGH'], vendor: 'apache' },
                  },
                  {
                    label: 'Recent CVSS 9.0+ CVEs',
                    apply: { ...EMPTY_FILTERS, cvss_min: '9.0', year_from: '2022' },
                  },
                ].map(({ label, apply }) => (
                  <button
                    key={label}
                    onClick={() => { setFilters(apply); runSearch(apply) }}
                    className="flex items-center gap-2 text-left group"
                    style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: '2px 0' }}
                    onMouseEnter={e => { e.currentTarget.querySelector('.arrow').style.color = '#3b82f6'; e.currentTarget.querySelector('.lbl').style.color = '#e2e8f0' }}
                    onMouseLeave={e => { e.currentTarget.querySelector('.arrow').style.color = '#475569'; e.currentTarget.querySelector('.lbl').style.color = '#94a3b8' }}
                  >
                    <span className="arrow" style={{ color: '#475569', fontSize: '0.82rem', transition: 'color 0.15s' }}>→</span>
                    <span className="lbl" style={{ fontSize: '0.82rem', color: '#94a3b8', transition: 'color 0.15s' }}>{label}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Detail drawer */}
      <DetailDrawer cve={selectedCVE} onClose={() => setSelectedCVE(null)} />
    </div>
  )
}
