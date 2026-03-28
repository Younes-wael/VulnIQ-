import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchStats, searchCVEs } from '../lib/api'
import MetricTile from '../components/MetricTile'
import SeverityBadge from '../components/SeverityBadge'

const FEATURES = [
  {
    to: '/chat',
    color: '#8b5cf6',
    title: 'Chat',
    desc: 'Ask natural language questions about CVEs and get cited answers grounded in NVD data.',
  },
  {
    to: '/search',
    color: '#06b6d4',
    title: 'Search',
    desc: 'Filter and browse 200k+ vulnerabilities by severity, vendor, year, and keyword.',
  },
  {
    to: '/dashboard',
    color: '#f97316',
    title: 'Dashboard',
    desc: 'Visualize CVE trends, severity distributions, and top affected vendors over time.',
  },
  {
    to: '/advisor',
    color: '#3b82f6',
    title: 'Patch Advisor',
    desc: 'Enter any CVE ID and get AI-powered remediation advice and related vulnerability context.',
  },
  {
    to: '/stack',
    color: '#ef4444',
    title: 'Stack Analysis',
    desc: 'Input your tech stack and find which CVEs may affect you — with risk scoring and AI report.',
  },
  {
    to: '/sbom',
    color: '#10b981',
    title: 'SBOM Scanner',
    desc: 'Upload a dependency file and instantly surface all known CVEs affecting your packages.',
  },
  {
    to: '/watchlists',
    color: '#10b981',
    title: 'Watchlists',
    desc: 'Monitor vendors, products, and keywords. Get webhook alerts the moment new CVEs match.',
  },
]

const QUICK_ACTIONS = [
  {
    to: '/search',
    borderColor: '#ef4444',
    title: 'Search Critical CVEs',
    desc: 'Filter by severity, vendor, and CVSS score',
  },
  {
    to: '/sbom',
    borderColor: '#10b981',
    title: 'Scan a Dependency File',
    desc: 'Upload requirements.txt, package.json, or pom.xml',
  },
  {
    to: '/watchlists',
    borderColor: '#10b981',
    title: 'Set Up a Watchlist',
    desc: 'Get alerted when new CVEs match your stack',
  },
  {
    to: '/advisor',
    borderColor: '#6366f1',
    title: 'Look Up a CVE',
    desc: 'Get AI-generated patch advice for any CVE ID',
  },
]

const SECTION_LABEL = {
  fontFamily: "'Consolas','Courier New',monospace",
  fontSize: '0.65rem',
  letterSpacing: '0.12em',
  textTransform: 'uppercase',
  color: '#475569',
  marginBottom: '16px',
  display: 'block',
}

export default function Home() {
  const navigate = useNavigate()
  const [stats, setStats]               = useState(null)
  const [statsLoading, setStatsLoading] = useState(true)
  const [recentCVEs, setRecentCVEs]     = useState([])
  const [recentLoading, setRecentLoading] = useState(true)

  useEffect(() => {
    fetchStats()
      .then(setStats)
      .catch(() => {})
      .finally(() => setStatsLoading(false))
  }, [])

  useEffect(() => {
    searchCVEs({ severities: ['CRITICAL'], limit: 5 })
      .then(data => setRecentCVEs(data.results || []))
      .catch(() => {})
      .finally(() => setRecentLoading(false))
  }, [])

  return (
    <div className="max-w-4xl mx-auto flex flex-col gap-10 pb-10 animate-fadein">

      {/* ── Hero ── */}
      <div className="flex flex-col gap-4 pt-4">
        <div>
          <p style={{
            fontSize: '0.65rem',
            letterSpacing: '0.15em',
            textTransform: 'uppercase',
            color: '#3b82f6',
            fontFamily: "'Consolas','Courier New',monospace",
            marginBottom: '10px',
          }}>
            Vulnerability Intelligence Platform
          </p>
          <h1 style={{
            fontSize: '2.5rem',
            fontWeight: 800,
            lineHeight: 1.1,
            background: 'linear-gradient(135deg, #3b82f6, #ef4444)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
            marginBottom: '12px',
          }}>
            VulnLens
          </h1>
          <p className="text-lg text-slate-400 max-w-2xl leading-relaxed">
            AI-powered vulnerability intelligence grounded in real NVD data.
            No hallucinated CVE IDs — every answer is backed by the database.
          </p>
        </div>
        <div className="flex flex-wrap gap-3 mt-1">
          <button
            onClick={() => navigate('/sbom')}
            style={{
              padding: '10px 20px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, #3b82f6, #2563eb)',
              color: '#fff',
              fontWeight: 600,
              fontSize: '0.875rem',
              border: 'none',
              cursor: 'pointer',
              transition: 'opacity 0.2s',
            }}
            onMouseEnter={e => e.currentTarget.style.opacity = '0.85'}
            onMouseLeave={e => e.currentTarget.style.opacity = '1'}
          >
            Start scanning →
          </button>
          <button
            onClick={() => navigate('/search')}
            style={{
              padding: '10px 20px',
              borderRadius: '10px',
              background: 'transparent',
              color: '#cbd5e1',
              fontWeight: 600,
              fontSize: '0.875rem',
              border: '1px solid #334155',
              cursor: 'pointer',
              transition: 'border-color 0.2s, color 0.2s',
            }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = '#3b82f6'; e.currentTarget.style.color = '#fff' }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = '#334155'; e.currentTarget.style.color = '#cbd5e1' }}
          >
            Explore CVEs
          </button>
        </div>
      </div>

      {/* ── Gradient divider ── */}
      <div style={{ height: '1px', background: 'linear-gradient(90deg, #3b82f6 0%, #ef4444 100%)', opacity: 0.3 }} />

      {/* ── Stats row ── */}
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
        {statsLoading ? (
          Array(3).fill(0).map((_, i) => (
            <div key={i} className="animate-pulse bg-card border border-border rounded-xl p-5 h-20" />
          ))
        ) : stats ? (
          <>
            <MetricTile label="CVEs Indexed"  value={stats.total_cves?.toLocaleString()} color="#3b82f6" />
            <MetricTile label="Critical CVEs" value={stats.critical_count?.toLocaleString()} color="#ef4444" />
            <MetricTile label="Avg CVSS Score" value={stats.avg_cvss?.toFixed(2)} color="#f97316" />
          </>
        ) : (
          <p className="col-span-3 text-xs text-slate-500">Stats unavailable — make sure the backend is running.</p>
        )}
      </div>

      {/* ── Feature cards ── */}
      <div>
        <p style={SECTION_LABEL}>Features</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {FEATURES.map(({ to, color, title, desc }) => (
            <button
              key={to}
              onClick={() => navigate(to)}
              className="text-left bg-card border border-border rounded-xl overflow-hidden flex flex-col transition-all group"
              style={{ padding: 0 }}
              onMouseEnter={e => {
                e.currentTarget.style.borderColor = color + '66'
                e.currentTarget.style.transform = 'translateY(-2px)'
                e.currentTarget.style.boxShadow = `0 4px 20px ${color}1a`
              }}
              onMouseLeave={e => {
                e.currentTarget.style.borderColor = ''
                e.currentTarget.style.transform = ''
                e.currentTarget.style.boxShadow = ''
              }}
            >
              <div style={{ height: '3px', background: color, width: '100%' }} />
              <div className="p-5 flex flex-col gap-2">
                <span className="font-semibold text-slate-100" style={{ fontSize: '0.925rem' }}>{title}</span>
                <p className="text-xs text-slate-400 leading-relaxed">{desc}</p>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* ── Recent Critical CVEs ── */}
      <div>
        <p style={SECTION_LABEL}>Recent Critical CVEs</p>
        <div style={{ border: '1px solid #1e293b', borderRadius: '12px', overflow: 'hidden', background: '#1e293b' }}>
          {recentLoading ? (
            [0, 1, 2].map(i => (
              <div key={i} className="animate-pulse flex items-center gap-3 px-4 py-3" style={{ borderBottom: i < 2 ? '1px solid #0f172a' : 'none' }}>
                <div className="h-4 w-36 bg-slate-700 rounded" />
                <div className="h-4 w-16 bg-slate-700 rounded" />
                <div className="h-3 w-20 bg-slate-700 rounded ml-auto" />
              </div>
            ))
          ) : recentCVEs.length === 0 ? (
            <p className="text-sm text-slate-500 px-4 py-5">No data available</p>
          ) : (
            recentCVEs.map((cve, i) => (
              <div
                key={cve.cve_id}
                onClick={() => navigate(`/advisor?cve=${cve.cve_id}`)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  padding: '12px 16px',
                  borderBottom: i < recentCVEs.length - 1 ? '1px solid #0f172a' : 'none',
                  cursor: 'pointer',
                  transition: 'background 0.15s',
                }}
                onMouseEnter={e => e.currentTarget.style.background = '#263548'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                <span style={{
                  fontFamily: "'Consolas','Courier New',monospace",
                  fontSize: '0.85rem',
                  fontWeight: 600,
                  color: '#3b82f6',
                  flexShrink: 0,
                  minWidth: '140px',
                }}>
                  {cve.cve_id}
                </span>
                <SeverityBadge severity={cve.severity} />
                <div className="flex items-center gap-3 ml-auto text-xs text-slate-500 flex-shrink-0">
                  {cve.cvss_score != null && (
                    <span>CVSS <span className="text-slate-300 font-medium">{Number(cve.cvss_score).toFixed(1)}</span></span>
                  )}
                  {cve.published_date && (
                    <span>{cve.published_date.slice(0, 10)}</span>
                  )}
                </div>
                <span style={{ color: '#475569', fontSize: '0.85rem', flexShrink: 0 }}>→</span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* ── Quick Actions ── */}
      <div>
        <p style={SECTION_LABEL}>Quick Actions</p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {QUICK_ACTIONS.map(({ to, borderColor, title, desc }) => (
            <button
              key={to}
              onClick={() => navigate(to)}
              style={{
                textAlign: 'left',
                background: '#1e293b',
                border: '1px solid #334155',
                borderLeft: `3px solid ${borderColor}`,
                borderRadius: '8px',
                padding: '14px 16px',
                cursor: 'pointer',
                transition: 'background 0.15s, transform 0.15s, box-shadow 0.15s',
                display: 'flex',
                flexDirection: 'column',
                gap: '4px',
              }}
              onMouseEnter={e => {
                e.currentTarget.style.background = '#263548'
                e.currentTarget.style.transform = 'translateY(-1px)'
                e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.2)'
              }}
              onMouseLeave={e => {
                e.currentTarget.style.background = '#1e293b'
                e.currentTarget.style.transform = ''
                e.currentTarget.style.boxShadow = ''
              }}
            >
              <span style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0' }}>{title}</span>
              <span style={{ fontSize: '0.75rem', color: '#64748b', lineHeight: 1.4 }}>{desc}</span>
            </button>
          ))}
        </div>
      </div>

      {/* ── Footer note ── */}
      <p className="text-xs text-slate-600 border-t border-border pt-4">
        Data sourced from the National Vulnerability Database (NVD) · nvd.nist.gov · Not affiliated with NIST
      </p>
    </div>
  )
}
