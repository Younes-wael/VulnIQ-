const BASE = 'http://localhost:8000'

// ─── REST helpers ────────────────────────────────────────────────────────────

async function get(path) {
  const res = await fetch(`${BASE}${path}`)
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`)
  return res.json()
}

async function post(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`POST ${path} failed: ${res.status}`)
  return res.json()
}

// ─── REST endpoints ──────────────────────────────────────────────────────────

export const fetchHealth       = ()      => get('/api/health')
export const fetchStats        = ()      => get('/api/stats')
export const fetchYearlyTrends = ()      => get('/api/trends/yearly')
export const fetchSeverityTrends   = () => get('/api/trends/severity')
export const fetchVendorTrends     = () => get('/api/trends/vendors')
export const fetchCVSSTrends       = () => get('/api/trends/cvss')
export const fetchSeverityByYear   = () => get('/api/trends/severity-by-year')
export const fetchAdvisory         = (cveId) => get(`/api/advisor/${cveId}`)
export const analyzeStack          = (technologies) =>
  post('/api/stack/analyze', { technologies })

export function searchCVEs(filters = {}) {
  const params = new URLSearchParams()
  if (filters.severities?.length) params.set('severities', filters.severities.join(','))
  if (filters.year_from != null)  params.set('year_from',  filters.year_from)
  if (filters.year_to   != null)  params.set('year_to',    filters.year_to)
  if (filters.vendor)             params.set('vendor',     filters.vendor)
  if (filters.cvss_min  != null)  params.set('cvss_min',   filters.cvss_min)
  if (filters.cvss_max  != null)  params.set('cvss_max',   filters.cvss_max)
  if (filters.keyword)            params.set('keyword',    filters.keyword)
  if (filters.limit     != null)  params.set('limit',      filters.limit)
  return get(`/api/search?${params.toString()}`)
}

// ─── SSE streaming helpers ───────────────────────────────────────────────────

function readSSEStream(response, onToken, onError, onDone) {
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  function pump() {
    reader.read().then(({ done, value }) => {
      if (done) {
        onDone && onDone()
        return
      }
      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split('\n')
      buffer = lines.pop() // keep incomplete last line

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue
        const payload = line.slice(6)
        if (payload.startsWith('[ERROR] ')) {
          onError && onError(payload.slice(8))
        } else {
          onToken(payload)
        }
      }
      pump()
    }).catch((err) => {
      onError && onError(err.message)
    })
  }

  pump()
}

export async function streamChat(message, history = [], filters = {}, onToken, onSources, onError) {
  let response
  try {
    response = await fetch(`${BASE}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, history, filters }),
    })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
  } catch (err) {
    onError && onError(err.message)
    return
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  function pump() {
    reader.read().then(({ done, value }) => {
      if (done) return
      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split('\n')
      buffer = lines.pop()

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue
        const payload = line.slice(6)
        if (payload.startsWith('[ERROR] ')) {
          onError && onError(payload.slice(8))
        } else if (payload.startsWith('[SOURCES] ')) {
          const ids = payload.slice(10).split(',').map((s) => s.trim())
          onSources && onSources(ids)
        } else {
          onToken(payload)
        }
      }
      pump()
    }).catch((err) => {
      onError && onError(err.message)
    })
  }

  pump()
}

export async function streamAdvice(cveId, onToken, onError) {
  let response
  try {
    response = await fetch(`${BASE}/api/advisor/${cveId}/advice`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
  } catch (err) {
    onError && onError(err.message)
    return
  }
  readSSEStream(response, onToken, onError)
}

export async function streamStackReport(technologies, analysis, onToken, onError) {
  let response
  try {
    response = await fetch(`${BASE}/api/stack/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ technologies, analysis }),
    })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
  } catch (err) {
    onError && onError(err.message)
    return
  }
  readSSEStream(response, onToken, onError)
}
