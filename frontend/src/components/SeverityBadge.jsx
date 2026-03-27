const STYLES = {
  CRITICAL: { bg: '#ef4444', text: '#fff',      border: '#f87171' },
  HIGH:     { bg: '#f97316', text: '#fff',      border: '#fb923c' },
  MEDIUM:   { bg: '#eab308', text: '#0f172a',   border: '#facc15' },
  LOW:      { bg: '#22c55e', text: '#fff',      border: '#4ade80' },
}

export default function SeverityBadge({ severity }) {
  const upper = (severity || '').toUpperCase()
  const s = STYLES[upper]
  return (
    <span
      style={{
        fontFamily: "'Consolas','Courier New',monospace",
        fontSize: '0.7rem',
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        padding: '2px 10px',
        borderRadius: '4px',
        background: s?.bg ?? '#334155',
        color: s?.text ?? '#fff',
        border: `1px solid ${s?.border ?? '#475569'}`,
        display: 'inline-block',
      }}
    >
      {upper || 'N/A'}
    </span>
  )
}
