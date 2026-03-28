import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  ResponsiveContainer,
  LineChart, Line,
  BarChart, Bar,
  PieChart, Pie, Cell,
  XAxis, YAxis,
  CartesianGrid, Tooltip, Legend,
} from 'recharts'
import MetricTile from '../components/MetricTile'
import {
  fetchStats,
  fetchYearlyTrends,
  fetchSeverityTrends,
  fetchVendorTrends,
  fetchCVSSTrends,
  fetchSeverityByYear,
  getWatchlists,
} from '../lib/api'

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

const SEV_COLORS = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
}

const CHART_STYLE = {
  background: '#1e293b',
  borderRadius: 12,
  border: '1px solid #334155',
  padding: '16px',
}

const AXIS_STYLE = { fill: '#94a3b8', fontSize: 11 }
const GRID_COLOR = '#334155'
const TOOLTIP_STYLE = {
  backgroundColor: '#0f172a',
  border: '1px solid #334155',
  borderRadius: 8,
  color: '#e2e8f0',
  fontSize: 12,
}

function ChartCard({ title, children, loading, error }) {
  return (
    <div style={CHART_STYLE}>
      <p className="text-sm font-semibold text-slate-200 mb-4">{title}</p>
      {loading && (
        <div className="animate-pulse flex flex-col gap-2">
          <div className="h-4 bg-slate-700 rounded w-1/3" />
          <div className="h-48 bg-slate-700 rounded" />
        </div>
      )}
      {error && <p className="text-xs text-red-400">{error}</p>}
      {!loading && !error && children}
    </div>
  )
}

function useData(fetcher) {
  const [data, setData]   = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  useEffect(() => {
    fetcher()
      .then(setData)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])
  return { data, loading, error }
}

// Custom label for pie chart
function PieLabel({ cx, cy, midAngle, innerRadius, outerRadius, percent }) {
  if (percent < 0.04) return null
  const rad = Math.PI / 180
  const r = innerRadius + (outerRadius - innerRadius) * 0.55
  const x = cx + r * Math.cos(-midAngle * rad)
  const y = cy + r * Math.sin(-midAngle * rad)
  return (
    <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central" fontSize={11} fontWeight={600}>
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  )
}

export default function Dashboard() {
  const watchlistsData = useData(getWatchlists)
  const stats      = useData(fetchStats)
  const yearly     = useData(fetchYearlyTrends)
  const severity   = useData(fetchSeverityTrends)
  const vendors    = useData(fetchVendorTrends)
  const cvss       = useData(fetchCVSSTrends)
  const sevByYear  = useData(fetchSeverityByYear)

  // Derive years covered from yearly data
  const yearsCovered = yearly.data
    ? yearly.data[yearly.data.length - 1]?.year - yearly.data[0]?.year + 1
    : null

  // Pivot severity-by-year into recharts stacked format
  const sevByYearPivoted = (() => {
    if (!sevByYear.data) return []
    const map = {}
    for (const row of sevByYear.data) {
      if (!map[row.year]) map[row.year] = { year: row.year }
      map[row.year][row.severity] = row.count
    }
    return Object.values(map).sort((a, b) => a.year - b.year)
  })()

  const recentlyAlerted = (watchlistsData.data || [])
    .filter(w => w.last_alerted_at)
    .sort((a, b) => new Date(b.last_alerted_at) - new Date(a.last_alerted_at))
    .slice(0, 3)

  return (
    <div className="flex flex-col gap-6 pb-8 animate-fadein">
      <div>
        <div style={{ width: '32px', height: '3px', borderRadius: '2px', background: '#f97316', marginBottom: '8px', display: 'block' }} />
        <h1 className="text-2xl font-bold text-slate-100">CVE Dashboard</h1>
        <p className="text-slate-400 text-sm mt-1">Trends and statistics from the NVD database</p>
      </div>

      {/* ── Section 0: Watchlist Alerts ── */}
      <div style={CHART_STYLE}>
        <div className="flex items-center justify-between mb-3">
          <p className="text-sm font-semibold text-slate-200">
            Watchlist Alerts
            {watchlistsData.data && (
              <span className="ml-2 text-xs font-normal text-slate-500">
                {watchlistsData.data.length} watchlist{watchlistsData.data.length !== 1 ? 's' : ''}
              </span>
            )}
          </p>
          <Link to="/watchlists" style={{ fontSize: '0.75rem', color: '#6366f1', textDecoration: 'none' }}
            onMouseEnter={e => e.target.style.textDecoration = 'underline'}
            onMouseLeave={e => e.target.style.textDecoration = 'none'}
          >
            Manage →
          </Link>
        </div>

        {watchlistsData.loading && (
          <div className="animate-pulse h-8 bg-slate-700 rounded w-1/2" />
        )}

        {watchlistsData.error && (
          <p className="text-xs text-red-400">{watchlistsData.error}</p>
        )}

        {!watchlistsData.loading && !watchlistsData.error && watchlistsData.data?.length === 0 && (
          <p className="text-xs text-slate-500">
            No watchlists configured.{' '}
            <Link to="/watchlists" style={{ color: '#6366f1' }}>Create one →</Link>
          </p>
        )}

        {!watchlistsData.loading && recentlyAlerted.length === 0 && watchlistsData.data?.length > 0 && (
          <p className="text-xs text-slate-500">No alerts delivered yet.</p>
        )}

        {recentlyAlerted.length > 0 && (
          <div className="flex flex-col gap-2">
            {recentlyAlerted.map(w => (
              <div key={w.id} className="flex items-center justify-between text-xs py-1 border-b border-slate-700/50 last:border-0">
                <span className="text-slate-200 font-medium">{w.name}</span>
                <span className="text-slate-500">{relativeTime(w.last_alerted_at)}</span>
              </div>
            ))}
            <Link
              to="/watchlists"
              style={{ fontSize: '0.7rem', color: '#6366f1', marginTop: '4px', display: 'inline-block' }}
            >
              View all watchlists →
            </Link>
          </div>
        )}
      </div>

      {/* ── Section 1: Metrics ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.loading ? (
          Array(4).fill(0).map((_, i) => (
            <div key={i} className="animate-pulse bg-card border border-border rounded-xl p-5 h-24" />
          ))
        ) : stats.error ? (
          <p className="col-span-4 text-sm text-red-400">{stats.error}</p>
        ) : (
          <>
            <MetricTile
              label="Total CVEs"
              value={stats.data?.total_cves?.toLocaleString()}
            />
            <MetricTile
              label="Critical CVEs"
              value={stats.data?.critical_count?.toLocaleString()}
              color="#ef4444"
            />
            <MetricTile
              label="Avg CVSS Score"
              value={stats.data?.avg_cvss?.toFixed(2)}
              color="#f97316"
            />
            <MetricTile
              label="Years of Data"
              value={yearsCovered ?? '—'}
              subtitle={
                yearly.data
                  ? `${yearly.data[0]?.year} – ${yearly.data[yearly.data.length - 1]?.year}`
                  : undefined
              }
            />
          </>
        )}
      </div>

      {/* ── Section 2: Yearly + Severity pie ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ChartCard title="CVEs Reported Per Year" loading={yearly.loading} error={yearly.error}>
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={yearly.data} margin={{ top: 4, right: 12, left: 0, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={GRID_COLOR} />
              <XAxis dataKey="year" tick={AXIS_STYLE} />
              <YAxis tick={AXIS_STYLE} width={48} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Line
                type="monotone"
                dataKey="count"
                stroke="#6366f1"
                strokeWidth={2}
                dot={{ r: 3, fill: '#6366f1' }}
                activeDot={{ r: 5 }}
                name="CVEs"
              />
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Severity Distribution" loading={severity.loading} error={severity.error}>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie
                data={severity.data}
                dataKey="count"
                nameKey="severity"
                cx="50%"
                cy="45%"
                outerRadius={90}
                labelLine={false}
                label={PieLabel}
              >
                {severity.data?.map(entry => (
                  <Cell key={entry.severity} fill={SEV_COLORS[entry.severity] ?? '#64748b'} />
                ))}
              </Pie>
              <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(v, name) => [v.toLocaleString(), name]} />
              <Legend
                formatter={v => <span style={{ color: '#94a3b8', fontSize: 12 }}>{v}</span>}
              />
            </PieChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {/* ── Section 3: Vendors + CVSS histogram ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ChartCard title="Top 15 Most Affected Vendors" loading={vendors.loading} error={vendors.error}>
          <ResponsiveContainer width="100%" height={320}>
            <BarChart
              data={vendors.data}
              layout="vertical"
              margin={{ top: 4, right: 12, left: 80, bottom: 4 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke={GRID_COLOR} horizontal={false} />
              <XAxis type="number" tick={AXIS_STYLE} />
              <YAxis
                type="category"
                dataKey="vendor"
                tick={{ ...AXIS_STYLE, fontSize: 10 }}
                width={80}
              />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Bar dataKey="count" name="CVEs" radius={[0, 4, 4, 0]}>
                {vendors.data?.map((_, i) => (
                  <Cell
                    key={i}
                    fill={`hsl(${239 + i * 4}, ${70 - i * 2}%, ${55 - i}%)`}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="CVSS Score Distribution" loading={cvss.loading} error={cvss.error}>
          <ResponsiveContainer width="100%" height={320}>
            <BarChart
              data={cvss.data}
              margin={{ top: 4, right: 12, left: 0, bottom: 40 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke={GRID_COLOR} />
              <XAxis
                dataKey="bucket"
                tick={{ ...AXIS_STYLE, fontSize: 9 }}
                angle={-45}
                textAnchor="end"
                interval={0}
              />
              <YAxis tick={AXIS_STYLE} width={48} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Bar dataKey="count" fill="#f97316" name="CVEs" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {/* ── Section 4: Severity trend full width ── */}
      <ChartCard title="Severity Trend Over Years" loading={sevByYear.loading} error={sevByYear.error}>
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={sevByYearPivoted} margin={{ top: 4, right: 12, left: 0, bottom: 4 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={GRID_COLOR} />
            <XAxis dataKey="year" tick={AXIS_STYLE} />
            <YAxis tick={AXIS_STYLE} width={48} />
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Legend formatter={v => <span style={{ color: '#94a3b8', fontSize: 12 }}>{v}</span>} />
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
              <Bar key={sev} dataKey={sev} stackId="a" fill={SEV_COLORS[sev]} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>
    </div>
  )
}
