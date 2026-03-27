import SeverityBadge from './SeverityBadge'

const ACCENT = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
}

export default function CVECard({ cve, onClick }) {
  const { cve_id, severity, cvss_score, description, vendors, published_date } = cve

  const upper = (severity || '').toUpperCase()
  const accentColor = ACCENT[upper] ?? '#334155'

  const vendorText = Array.isArray(vendors)
    ? vendors.slice(0, 3).join(', ')
    : (vendors || '').split(',').slice(0, 3).join(', ')

  const dateShort = (published_date || '').slice(0, 10)

  return (
    <div
      onClick={onClick}
      className="bg-card border border-border rounded-xl p-4 flex flex-col gap-2 transition-all"
      style={{
        borderLeft: `3px solid ${accentColor}`,
        cursor: onClick ? 'pointer' : 'default',
      }}
      onMouseEnter={e => {
        if (!onClick) return
        e.currentTarget.style.transform = 'translateY(-2px)'
        e.currentTarget.style.boxShadow = `0 4px 20px ${accentColor}1a`
      }}
      onMouseLeave={e => {
        e.currentTarget.style.transform = ''
        e.currentTarget.style.boxShadow = ''
      }}
    >
      {/* Top row */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <span
          className="font-bold text-sm"
          style={{ fontFamily: "'Consolas','Courier New',monospace", color: '#3b82f6' }}
        >
          {cve_id}
        </span>
        <SeverityBadge severity={severity} />
      </div>

      {/* Meta row */}
      <div className="flex items-center gap-3 text-xs text-slate-400 flex-wrap">
        {cvss_score != null && (
          <span>CVSS <span className="text-slate-200 font-semibold">{Number(cvss_score).toFixed(1)}</span></span>
        )}
        {dateShort && <span>{dateShort}</span>}
        {vendorText && (
          <span className="truncate max-w-[160px]" title={vendorText}>{vendorText}</span>
        )}
      </div>

      {/* Description */}
      {description && (
        <p className="text-sm text-slate-300 line-clamp-2 leading-relaxed">{description}</p>
      )}
    </div>
  )
}
