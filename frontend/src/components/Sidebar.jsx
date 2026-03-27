import { useState } from 'react'
import { NavLink } from 'react-router-dom'

const NAV = [
  {
    to: '/', label: 'Home', color: '#3b82f6',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>
        <polyline points="9 22 9 12 15 12 15 22"/>
      </svg>
    ),
  },
  {
    to: '/chat', label: 'Chat', color: '#8b5cf6',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/>
      </svg>
    ),
  },
  {
    to: '/search', label: 'Search', color: '#06b6d4',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="11" cy="11" r="8"/>
        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
      </svg>
    ),
  },
  {
    to: '/dashboard', label: 'Dashboard', color: '#f97316',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <rect x="18" y="3" width="4" height="18"/>
        <rect x="10" y="8" width="4" height="13"/>
        <rect x="2" y="13" width="4" height="8"/>
      </svg>
    ),
  },
  {
    to: '/advisor', label: 'Advisor', color: '#3b82f6',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    ),
  },
  {
    to: '/stack', label: 'Stack Analysis', color: '#ef4444',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <polygon points="12 2 2 7 12 12 22 7 12 2"/>
        <polyline points="2 17 12 22 22 17"/>
        <polyline points="2 12 12 17 22 12"/>
      </svg>
    ),
  },
]

function NavItem({ to, label, color, icon, onClose }) {
  const [hovered, setHovered] = useState(false)

  return (
    <NavLink
      to={to}
      end={to === '/'}
      onClick={onClose}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={({ isActive }) => ({
        padding: '8px 16px',
        background: isActive ? '#0f172a' : 'transparent',
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        borderRadius: '8px',
        textDecoration: 'none',
        color: isActive ? '#fff' : hovered ? '#cbd5e1' : '#64748b',
        fontSize: '0.875rem',
        fontWeight: 500,
        transition: 'color 0.15s, background 0.15s',
        flexShrink: 0,
      })}
    >
      {({ isActive }) => (
        <>
          <div style={{
            width: '2px',
            height: '16px',
            borderRadius: '2px',
            background: color,
            flexShrink: 0,
            opacity: isActive ? 1 : hovered ? 0.6 : 0.2,
            transition: 'opacity 0.15s',
          }} />
          {icon}
          {label}
        </>
      )}
    </NavLink>
  )
}

export default function Sidebar({ onClose }) {
  return (
    <div
      className="flex flex-col h-full"
      style={{ background: '#1e293b', borderRight: '1px solid #334155' }}
    >
      {/* ── Brand header ── */}
      <div className="flex items-center justify-between px-4 py-4" style={{ borderBottom: '1px solid #334155' }}>
        <div className="flex items-center gap-2.5">
          {/* VL badge */}
          <div style={{
            background: 'linear-gradient(135deg, #3b82f6, #ef4444)',
            color: '#fff',
            fontWeight: 700,
            borderRadius: '6px',
            fontSize: '0.75rem',
            padding: '4px 6px',
            lineHeight: 1,
            flexShrink: 0,
          }}>
            VL
          </div>
          <div>
            {/* Gradient wordmark */}
            <div style={{
              fontWeight: 700,
              fontSize: '0.95rem',
              background: 'linear-gradient(135deg, #3b82f6, #ef4444)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
              lineHeight: 1.2,
            }}>
              VulnLens
            </div>
            <div style={{ fontSize: '0.65rem', color: '#64748b', lineHeight: 1 }}>
              Vulnerability Intelligence
            </div>
          </div>
        </div>
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-slate-100 lg:hidden transition-colors"
          aria-label="Close menu"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* ── Navigation ── */}
      <nav className="flex-1 px-3 py-3 flex flex-col" style={{ gap: '2px' }}>
        {NAV.map(({ to, label, color, icon }) => (
          <NavItem
            key={to}
            to={to}
            label={label}
            color={color}
            icon={icon}
            onClose={onClose}
          />
        ))}
      </nav>

      {/* ── Footer ── */}
      <div className="px-5 py-4" style={{ borderTop: '1px solid #334155' }}>
        <p style={{ fontSize: '0.65rem', color: '#64748b', marginBottom: '2px' }}>Powered by NVD + Groq</p>
        <p style={{ fontSize: '0.6rem', color: '#475569' }}>© 2025 VulnLens</p>
      </div>
    </div>
  )
}
