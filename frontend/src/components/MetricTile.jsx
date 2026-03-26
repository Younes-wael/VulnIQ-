export default function MetricTile({ label, value, subtitle, color }) {
  return (
    <div
      className={`bg-card rounded-xl p-5 flex flex-col gap-1 border border-border ${
        color ? 'border-l-4' : ''
      }`}
      style={color ? { borderLeftColor: color } : undefined}
    >
      <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">{label}</p>
      <p className="text-3xl font-bold text-slate-100">{value ?? '—'}</p>
      {subtitle && <p className="text-xs text-slate-500">{subtitle}</p>}
    </div>
  )
}
