import { NavLink } from 'react-router-dom'

const NAV = [
  { to: '/',          icon: '🏠', label: 'Home' },
  { to: '/chat',      icon: '💬', label: 'Chat' },
  { to: '/search',    icon: '🔎', label: 'Search' },
  { to: '/dashboard', icon: '📊', label: 'Dashboard' },
  { to: '/advisor',   icon: '🛡️', label: 'Advisor' },
  { to: '/stack',     icon: '🧱', label: 'Stack Analysis' },
]

export default function Sidebar({ onClose }) {
  return (
    <div className="flex flex-col h-full bg-card border-r border-border" style={{ borderTop: '2px solid #6366f1' }}>

      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-border">
        <div className="flex items-center gap-2">
          <span className="text-xl">🔐</span>
          <span className="font-bold text-slate-100 tracking-tight">CVE Assistant</span>
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

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {NAV.map(({ to, icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            onClick={onClose}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors relative ${
                isActive
                  ? 'bg-brand/20 text-brand border-l-2 border-brand pl-[10px]'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-white/5 border-l-2 border-transparent pl-[10px]'
              }`
            }
          >
            <span className="text-base leading-none">{icon}</span>
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-border">
        <p className="text-xs text-slate-500">Powered by NVD + Groq</p>
      </div>
    </div>
  )
}
