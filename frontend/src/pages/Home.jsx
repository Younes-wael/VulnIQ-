import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchStats } from '../lib/api'
import MetricTile from '../components/MetricTile'

const FEATURES = [
  {
    to: '/chat',
    icon: '💬',
    title: 'Chat',
    desc: 'Ask natural language questions about CVEs and get cited answers grounded in NVD data.',
  },
  {
    to: '/search',
    icon: '🔎',
    title: 'Search',
    desc: 'Filter and browse 200k+ vulnerabilities by severity, vendor, year, and keyword.',
  },
  {
    to: '/dashboard',
    icon: '📊',
    title: 'Dashboard',
    desc: 'Visualize CVE trends, severity distributions, and top affected vendors over time.',
  },
  {
    to: '/advisor',
    icon: '🛡️',
    title: 'Patch Advisor',
    desc: 'Enter any CVE ID and get AI-powered remediation advice and related vulnerability context.',
  },
  {
    to: '/stack',
    icon: '🧱',
    title: 'Stack Analysis',
    desc: 'Input your tech stack and find which CVEs may affect you — with risk scoring and AI report.',
  },
]

export default function Home() {
  const navigate = useNavigate()
  const [stats, setStats]     = useState(null)
  const [statsLoading, setStatsLoading] = useState(true)

  useEffect(() => {
    fetchStats()
      .then(setStats)
      .catch(() => {})
      .finally(() => setStatsLoading(false))
  }, [])

  return (
    <div className="max-w-4xl mx-auto flex flex-col gap-10 pb-10 animate-fadein">

      {/* ── Hero ── */}
      <div className="flex flex-col gap-4 pt-4">
        <div>
          <h1 className="text-4xl font-bold text-slate-100 tracking-tight">
            🔐 CVE Security Assistant
          </h1>
          <p className="mt-3 text-lg text-slate-400 max-w-2xl leading-relaxed">
            AI-powered vulnerability intelligence grounded in real NVD data.
            No hallucinated CVE IDs, no made-up scores — every answer is backed by the database.
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => navigate('/chat')}
            className="px-5 py-2.5 rounded-xl bg-brand hover:bg-brand/80 text-white text-sm font-semibold transition-colors"
          >
            Start Chatting →
          </button>
          <button
            onClick={() => navigate('/stack')}
            className="px-5 py-2.5 rounded-xl border border-border bg-card hover:border-brand/60 hover:bg-white/5 text-slate-300 text-sm font-semibold transition-colors"
          >
            Analyze My Stack →
          </button>
        </div>
      </div>

      {/* ── Stats row ── */}
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
        {statsLoading ? (
          Array(3).fill(0).map((_, i) => (
            <div key={i} className="animate-pulse bg-card border border-border rounded-xl p-5 h-20" />
          ))
        ) : stats ? (
          <>
            <MetricTile label="CVEs Indexed"  value={stats.total_cves?.toLocaleString()} />
            <MetricTile label="Critical CVEs" value={stats.critical_count?.toLocaleString()} color="#ef4444" />
            <MetricTile label="Avg CVSS Score" value={stats.avg_cvss?.toFixed(2)} color="#f97316" />
          </>
        ) : (
          <p className="col-span-3 text-xs text-slate-500">Stats unavailable — start the backend to see live data.</p>
        )}
      </div>

      {/* ── Feature cards ── */}
      <div>
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">Pages</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {FEATURES.map(({ to, icon, title, desc }) => (
            <button
              key={to}
              onClick={() => navigate(to)}
              className="text-left bg-card border border-border rounded-xl p-5 flex flex-col gap-2 hover:border-brand/60 hover:bg-white/5 transition-colors group"
            >
              <div className="flex items-center gap-2">
                <span className="text-xl">{icon}</span>
                <span className="font-semibold text-slate-100 group-hover:text-brand transition-colors">{title}</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{desc}</p>
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
