import { useState, useEffect, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { useLocation } from 'react-router-dom'
import emailjs from '@emailjs/browser'

// ── EmailJS config ──────────────────────────────────────────────────────────
const EMAILJS_SERVICE_ID  = 'service_8hbhlpr'
const EMAILJS_TEMPLATE_ID = 'template_bp43ug4'
const EMAILJS_PUBLIC_KEY  = '_3jXuIdc96ALMLLXo'

// ────────────────────────────────────────────────────────────────────────────

const FEEDBACK_TYPES = [
  { id: 'bug',     label: 'Bug Report',      placeholder: 'What happened? What did you expect?' },
  { id: 'feature', label: 'Feature Request', placeholder: 'What feature would you like and why?' },
  { id: 'ui',      label: 'UI Feedback',     placeholder: 'What would you improve?' },
  { id: 'general', label: 'General Feedback', placeholder: "What's on your mind?" },
]

const PAGE_OPTIONS = [
  { label: 'Home',           path: '/' },
  { label: 'Chat',           path: '/chat' },
  { label: 'Search',         path: '/search' },
  { label: 'Dashboard',      path: '/dashboard' },
  { label: 'Advisor',        path: '/advisor' },
  { label: 'Stack Analysis', path: '/stack' },
  { label: 'SBOM Scanner',   path: '/sbom' },
  { label: 'Watchlists',     path: '/watchlists' },
  { label: 'Other',          path: null },
]

function getPageLabel(pathname) {
  const match = PAGE_OPTIONS.find(p => p.path && pathname === p.path)
  return match ? match.label : 'Other'
}

const ACCENT = '#3b82f6'

const INPUT_STYLE = {
  width: '100%',
  background: '#1e293b',
  border: '1px solid #334155',
  borderRadius: '8px',
  padding: '8px 12px',
  color: '#f1f5f9',
  fontSize: '0.875rem',
  fontFamily: 'inherit',
  outline: 'none',
  boxSizing: 'border-box',
}

function resetForm(setters) {
  setters.setTypeId('bug')
  setters.setMessage('')
  setters.setEmail('')
  setters.setStatus('idle')
  setters.setErrorDetail('')
}

export default function FeedbackDrawer({ isOpen, onClose }) {
  const location = useLocation()

  const [typeId,  setTypeId]  = useState('bug')
  const [page,    setPage]    = useState(() => getPageLabel(location.pathname))
  const [message, setMessage] = useState('')
  const [email,   setEmail]   = useState('')
  const [status,      setStatus]      = useState('idle') // idle | sending | success | error
  const [errorDetail, setErrorDetail] = useState('')

  // Sync page label when route changes
  useEffect(() => {
    setPage(getPageLabel(location.pathname))
  }, [location.pathname])

  // Escape key closes drawer
  useEffect(() => {
    if (!isOpen) return
    const handler = e => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [isOpen, onClose])

  // Lock body scroll while open; reset form when closed
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
      resetForm({ setTypeId, setMessage, setEmail, setStatus, setErrorDetail })
    }
    return () => { document.body.style.overflow = '' }
  }, [isOpen])

  const currentType = FEEDBACK_TYPES.find(t => t.id === typeId) || FEEDBACK_TYPES[0]

  const handleClose = useCallback(() => {
    onClose()
  }, [onClose])

  async function handleSubmit(e) {
    e.preventDefault()
    if (!message.trim() || status === 'sending') return

    setStatus('sending')

    const params = {
      feedback_type: currentType.label,
      page:          page,
      message:       message.trim(),
      user_email:    email.trim() || '',
      context_url:   window.location.href,
      timestamp:     new Date().toISOString(),
    }

    try {
      emailjs.init({ publicKey: EMAILJS_PUBLIC_KEY })
      const response = await emailjs.send(EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, params)
      console.log('[FeedbackDrawer] Sent OK — status:', response.status, response.text)
      setStatus('success')
      setTimeout(handleClose, 2000)
    } catch (err) {
      console.error('[FeedbackDrawer] Full error object:', err)
      console.error('[FeedbackDrawer] Status:', err?.status)
      console.error('[FeedbackDrawer] Text:', err?.text)
      const detail = err?.text ?? err?.message ?? JSON.stringify(err)
      setStatus('error')
      setErrorDetail(detail)
      setTimeout(() => setStatus('idle'), 5000)
    }
  }

  function focusBorder(e)  { e.target.style.borderColor = ACCENT }
  function blurBorder(e)   { e.target.style.borderColor = '#334155' }

  return createPortal(
    <>
      {/* Backdrop — clicking outside closes drawer */}
      <div
        onClick={handleClose}
        style={{
          position: 'fixed', inset: 0,
          background: 'rgba(0,0,0,0.55)',
          zIndex: 9998,
          opacity: isOpen ? 1 : 0,
          pointerEvents: isOpen ? 'auto' : 'none',
          transition: 'opacity 0.3s ease',
        }}
      />

      {/* Drawer panel */}
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Send Feedback"
        style={{
          position: 'fixed', top: 0, right: 0, bottom: 0,
          width: 'min(420px, 100vw)',
          background: '#0f1629',
          borderLeft: '1px solid #1e2d4a',
          zIndex: 9999,
          display: 'flex',
          flexDirection: 'column',
          overflowY: 'auto',
          transform: isOpen ? 'translateX(0)' : 'translateX(100%)',
          transition: 'transform 0.3s ease',
        }}
      >
        {/* Header */}
        <div style={{
          padding: '20px 24px 16px',
          borderBottom: '1px solid #1e2d4a',
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          flexShrink: 0,
        }}>
          <div>
            <h2 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700, color: '#f1f5f9' }}>
              Send Feedback
            </h2>
            <p style={{ margin: '5px 0 0', fontSize: '0.78rem', color: '#64748b', lineHeight: 1.55 }}>
              Found a bug, have an idea, or want to share your experience?
            </p>
          </div>
          <button
            type="button"
            onClick={handleClose}
            aria-label="Close feedback drawer"
            style={{
              flexShrink: 0, marginLeft: '12px',
              background: 'none', border: 'none', cursor: 'pointer',
              color: '#64748b', padding: '4px', lineHeight: 1,
              transition: 'color 0.15s', zIndex: 1,
            }}
            onMouseEnter={e => { e.currentTarget.style.color = '#f1f5f9' }}
            onMouseLeave={e => { e.currentTarget.style.color = '#64748b' }}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>

        {/* Form */}
        <form
          onSubmit={handleSubmit}
          style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: '18px', flex: 1 }}
        >
          {/* Feedback type chips — no emojis */}
          <div>
            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', marginBottom: '10px' }}>
              Feedback Type
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
              {FEEDBACK_TYPES.map(t => {
                const active = typeId === t.id
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setTypeId(t.id)}
                    style={{
                      padding: '5px 13px',
                      borderRadius: '100px',
                      fontSize: '0.78rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      transition: 'all 0.15s',
                      background: active ? ACCENT : 'transparent',
                      border:     `1px solid ${active ? ACCENT : '#334155'}`,
                      color:      active ? '#fff' : '#94a3b8',
                    }}
                  >
                    {t.label}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Page / Section */}
          <div>
            <label
              htmlFor="fb-page"
              style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', display: 'block', marginBottom: '6px' }}
            >
              Page / Section
            </label>
            <select
              id="fb-page"
              value={page}
              onChange={e => setPage(e.target.value)}
              style={{
                ...INPUT_STYLE,
                appearance: 'none',
                backgroundImage: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='2'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E\")",
                backgroundRepeat: 'no-repeat',
                backgroundPosition: 'right 10px center',
                backgroundSize: '14px',
                paddingRight: '32px',
                cursor: 'pointer',
              }}
            >
              {PAGE_OPTIONS.map(opt => (
                <option key={opt.label} value={opt.label} style={{ background: '#1e293b' }}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          {/* Message */}
          <div>
            <label
              htmlFor="fb-message"
              style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', display: 'block', marginBottom: '6px' }}
            >
              Message
            </label>
            <textarea
              id="fb-message"
              value={message}
              onChange={e => setMessage(e.target.value)}
              placeholder={currentType.placeholder}
              rows={4}
              required
              style={{ ...INPUT_STYLE, resize: 'vertical', minHeight: '100px' }}
              onFocus={focusBorder}
              onBlur={blurBorder}
            />
          </div>

          {/* Email (optional) */}
          <div>
            <label
              htmlFor="fb-email"
              style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', display: 'block', marginBottom: '6px' }}
            >
              Your Email{' '}
              <span style={{ fontWeight: 400, color: '#475569' }}>(optional)</span>
            </label>
            <input
              type="email"
              id="fb-email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="In case we need to follow up"
              style={INPUT_STYLE}
              onFocus={focusBorder}
              onBlur={blurBorder}
            />
          </div>

          {/* Status */}
          {status === 'success' && (
            <div style={{ padding: '10px 14px', background: 'rgba(34,197,94,0.1)', border: '1px solid #22c55e', borderRadius: '8px', color: '#22c55e', fontSize: '0.84rem' }}>
              ✓ Feedback sent! Thank you.
            </div>
          )}
          {status === 'error' && (
            <div style={{ padding: '10px 14px', background: 'rgba(239,68,68,0.1)', border: '1px solid #ef4444', borderRadius: '8px', color: '#ef4444', fontSize: '0.84rem' }}>
              Failed to send. Please try again.
              {errorDetail ? <div style={{ marginTop: '4px', fontSize: '0.75rem', opacity: 0.8 }}>{errorDetail}</div> : null}
            </div>
          )}

          {/* Submit */}
          <button
            type="submit"
            disabled={!message.trim() || status === 'sending' || status === 'success'}
            style={{
              alignSelf: 'flex-start',
              padding: '9px 22px',
              background: ACCENT,
              color: '#fff',
              border: 'none',
              borderRadius: '10px',
              fontSize: '0.9rem',
              fontWeight: 700,
              cursor: status === 'sending' ? 'wait' : 'pointer',
              opacity: (!message.trim() || status === 'sending' || status === 'success') ? 0.55 : 1,
              transition: 'opacity 0.2s, transform 0.15s',
            }}
            onMouseEnter={e => { if (!e.currentTarget.disabled) e.currentTarget.style.transform = 'translateY(-1px)' }}
            onMouseLeave={e => { e.currentTarget.style.transform = 'none' }}
          >
            {status === 'sending' ? 'Sending...' : 'Send Feedback \u2192'}
          </button>
        </form>
      </div>
    </>,
    document.body
  )
}
