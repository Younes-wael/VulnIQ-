import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { searchCVEs } from '../lib/api'
import CVECard from '../components/CVECard'
import SeverityBadge from '../components/SeverityBadge'

const SEV_OPTIONS = [
  { label: 'CRITICAL', color: 'bg-critical' },
  { label: 'HIGH',     color: 'bg-high' },
  { label: 'MEDIUM',   color: 'bg-medium' },
  { label: 'LOW',      color: 'bg-low' },
]

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
            🛡️ View in Patch Advisor
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

  return (
    <div className="flex gap-0 lg:gap-6 h-full relative animate-fadein">

      {/* ── Filters panel ── */}
      <aside className="hidden lg:flex flex-col w-72 flex-shrink-0 gap-4">
        <h2 className="text-base font-semibold text-slate-100">🔎 Search & Filter</h2>

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

        {/* Header / status */}
        {results !== null && !loading && (
          <div className="flex items-center justify-between flex-wrap gap-2">
            <p className="text-sm text-slate-400">
              <span className="font-semibold text-slate-200">{results.length}</span> result{results.length !== 1 ? 's' : ''}
              {elapsed != null && <span className="ml-1">in {elapsed.toFixed(1)}ms</span>}
            </p>
            {results.length === 100 && (
              <p className="text-xs text-medium bg-medium/10 border border-medium/30 px-3 py-1 rounded-full">
                Showing first 100 results — refine your filters to see more
              </p>
            )}
          </div>
        )}

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

        {/* Results */}
        {!loading && results !== null && results.length === 0 && (
          <div className="flex flex-col items-center justify-center py-20 text-slate-500 gap-2">
            <span className="text-3xl">🔍</span>
            <p className="text-sm">No results. Try adjusting your filters.</p>
          </div>
        )}

        {!loading && results !== null && results.length > 0 && (
          <div className="flex flex-col gap-3 overflow-y-auto">
            {results.map(cve => (
              <CVECard
                key={cve.cve_id}
                cve={cve}
                onClick={() => setSelectedCVE(cve)}
              />
            ))}
          </div>
        )}

        {/* Not yet searched */}
        {!loading && results === null && !error && (
          <div className="flex flex-col items-center justify-center py-20 text-slate-500 gap-2">
            <span className="text-3xl">🔎</span>
            <p className="text-sm">Set your filters and press Search.</p>
          </div>
        )}
      </div>

      {/* Detail drawer */}
      <DetailDrawer cve={selectedCVE} onClose={() => setSelectedCVE(null)} />
    </div>
  )
}
