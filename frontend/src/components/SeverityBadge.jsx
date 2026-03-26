const STYLES = {
  CRITICAL: 'bg-critical text-white',
  HIGH:     'bg-high text-white',
  MEDIUM:   'bg-medium text-slate-900',
  LOW:      'bg-low text-white',
}

export default function SeverityBadge({ severity }) {
  const upper = (severity || '').toUpperCase()
  const cls = STYLES[upper] ?? 'bg-slate-600 text-white'
  return (
    <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide ${cls}`}>
      {upper || 'N/A'}
    </span>
  )
}
