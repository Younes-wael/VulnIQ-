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

async function put(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`PUT ${path} failed: ${res.status}`)
  return res.json()
}

async function del(path) {
  const res = await fetch(`${BASE}${path}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(`DELETE ${path} failed: ${res.status}`)
  return res.json()
}

// ─── REST endpoints ──────────────────────────────────────────────────────────

// ─── Watchlists ──────────────────────────────────────────────────────────────

export const getWatchlists    = ()        => get('/api/watchlists')
export const createWatchlist  = (data)    => post('/api/watchlists', data)
export const updateWatchlist  = (id, data) => put(`/api/watchlists/${id}`, data)
export const deleteWatchlist  = (id)      => del(`/api/watchlists/${id}`)
export const testWatchlist    = (id)      => post(`/api/watchlists/${id}/test`, {})

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

export function exportSearchCSV(filters = {}) {
  const params = new URLSearchParams()
  if (filters.severities?.length) params.set('severities', filters.severities.join(','))
  if (filters.year_from != null && filters.year_from !== '') params.set('year_from', filters.year_from)
  if (filters.year_to   != null && filters.year_to   !== '') params.set('year_to',   filters.year_to)
  if (filters.vendor)             params.set('vendor',   filters.vendor)
  if (filters.cvss_min  != null && filters.cvss_min  !== '') params.set('cvss_min',  filters.cvss_min)
  if (filters.cvss_max  != null && filters.cvss_max  !== '') params.set('cvss_max',  filters.cvss_max)
  if (filters.keyword)            params.set('keyword', filters.keyword)
  const a = document.createElement('a')
  a.href = `${BASE}/api/search/export?${params.toString()}`
  a.download = 'vulnlens-export.csv'
  a.click()
}

export async function exportAdvisorPDF(cveId, adviceText = '') {
  const res = await fetch(`${BASE}/api/advisor/${encodeURIComponent(cveId)}/export`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ advice_text: adviceText }),
  })
  if (!res.ok) throw new Error('PDF export failed')
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${cveId}-advisory.pdf`
  a.click()
  URL.revokeObjectURL(url)
}

export async function exportStackPDF(techInput, results, reportText = '') {
  const res = await fetch(`${BASE}/api/stack/export`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tech_input: techInput, results, report_text: reportText }),
  })
  if (!res.ok) throw new Error('PDF export failed')
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'vulnlens-stack-report.pdf'
  a.click()
  URL.revokeObjectURL(url)
}

export async function exportSBOMPDF(scanResult) {
  const res = await fetch(`${BASE}/api/sbom/export`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(scanResult),
  })
  if (!res.ok) throw new Error('PDF export failed')
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'vulnlens-sbom-report.pdf'
  a.click()
  URL.revokeObjectURL(url)
}

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
          onToken(payload.replace(/\\n/g, '\n'))
        }
      }
      pump()
    }).catch((err) => {
      onError && onError(err.message)
    })
  }

  pump()
}

export async function streamChat(message, history = [], filters = {}, onToken, onSources, onError, onDone) {
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
      if (done) { onDone && onDone(); return }
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
          onToken(payload.replace(/\\n/g, '\n'))
        }
      }
      pump()
    }).catch((err) => {
      onError && onError(err.message)
    })
  }

  pump()
}

export async function scanSBOM(file) {
  const formData = new FormData()
  formData.append('file', file)
  const res = await fetch(`${BASE}/api/sbom/scan`, {
    method: 'POST',
    body: formData,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function streamAdvice(cveId, onToken, onError, onDone) {
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
  readSSEStream(response, onToken, onError, onDone)
}

export async function streamStackReport(technologies, analysis, onToken, onError, onDone) {
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
  readSSEStream(response, onToken, onError, onDone)
}
