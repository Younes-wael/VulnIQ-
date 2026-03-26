import SeverityBadge from './SeverityBadge'

export default function CVECard({ cve, onClick }) {
  const {
    cve_id,
    severity,
    cvss_score,
    description,
    vendors,
    published_date,
  } = cve

  const vendorText = Array.isArray(vendors)
    ? vendors.slice(0, 3).join(', ')
    : (vendors || '').split(',').slice(0, 3).join(', ')

  const dateShort = (published_date || '').slice(0, 10)

  return (
    <div
      onClick={onClick}
      className={`bg-card border border-border rounded-xl p-4 flex flex-col gap-2 transition-colors ${
        onClick ? 'cursor-pointer hover:border-brand/60 hover:bg-white/5' : ''
      }`}
    >
      {/* Top row */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <span className="font-bold text-brand text-sm">{cve_id}</span>
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
