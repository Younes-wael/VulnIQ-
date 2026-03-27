export default function MetricTile({ label, value, subtitle, color }) {
  return (
    <div className="bg-card rounded-xl overflow-hidden border border-border flex flex-col">
      {color && (
        <div style={{ height: '3px', background: color, borderRadius: '8px 8px 0 0', width: '100%' }} />
      )}
      <div className="p-5 flex flex-col gap-1">
        <p style={{ fontSize: '0.65rem', letterSpacing: '0.1em' }} className="font-medium text-slate-500 uppercase">{label}</p>
        <p style={{ fontSize: '1.75rem' }} className="font-bold text-white leading-none">{value ?? '—'}</p>
        {subtitle && <p className="text-xs text-slate-500">{subtitle}</p>}
      </div>
    </div>
  )
}
