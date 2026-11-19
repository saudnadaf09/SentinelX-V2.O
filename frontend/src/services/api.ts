// Thin fetch wrapper: bearer auth, one-shot refresh-token rotation, uniform errors.
const BASE = '/api/v1'
const KEY = 'sentinelx.tokens'

type Tokens = { access: string; refresh: string }
let tokens: Tokens | null = (() => {
  try { return JSON.parse(sessionStorage.getItem(KEY) || 'null') } catch { return null }
})()
let refreshing: Promise<boolean> | null = null
const listeners: Array<() => void> = []

export class ApiError extends Error {
  status: number
  code: string
  details: any
  requestId: string
  constructor(status: number, code: string, message: string, details?: any, requestId = '') {
    super(message)
    this.status = status; this.code = code; this.details = details; this.requestId = requestId
  }
}

export const hasSession = () => !!tokens
export const onSessionEnd = (fn: () => void) => { listeners.push(fn) }
function setTokens(t: Tokens | null) {
  tokens = t
  if (t) sessionStorage.setItem(KEY, JSON.stringify(t)); else sessionStorage.removeItem(KEY)
  if (!t) listeners.forEach((l) => l())
}

async function parseError(res: Response): Promise<ApiError> {
  let body: any = null
  try { body = await res.json() } catch { /* not JSON */ }
  const e = body?.error
  return new ApiError(res.status, e?.code || 'error', e?.message || res.statusText || 'Request failed', e?.details, e?.request_id)
}

async function refresh(): Promise<boolean> {
  if (!tokens) return false
  if (!refreshing) {
    refreshing = fetch(`${BASE}/auth/refresh`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: tokens.refresh }),
    }).then(async (r) => {
      if (!r.ok) { setTokens(null); return false }
      const d = await r.json()
      setTokens({ access: d.access_token, refresh: d.refresh_token })
      return true
    }).catch(() => false).finally(() => { refreshing = null })
  }
  return refreshing
}

async function request(method: string, path: string, body?: any, retry = true): Promise<Response> {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (tokens) headers['Authorization'] = `Bearer ${tokens.access}`
  const res = await fetch(`${BASE}${path}`, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined })
  if (res.status === 401 && retry && tokens && !path.startsWith('/auth/')) {
    if (await refresh()) return request(method, path, body, false)
    throw await parseError(res)
  }
  if (!res.ok) throw await parseError(res)
  return res
}

function qs(params?: Record<string, any>) {
  if (!params) return ''
  const p = new URLSearchParams()
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') p.set(k, String(v)) })
  const s = p.toString()
  return s ? `?${s}` : ''
}

export const api = {
  get: async <T = any>(path: string, params?: Record<string, any>): Promise<T> => (await request('GET', path + qs(params))).json(),
  post: async <T = any>(path: string, body: any = {}): Promise<T> => (await request('POST', path, body)).json(),
  put: async <T = any>(path: string, body: any): Promise<T> => (await request('PUT', path, body)).json(),
  patch: async <T = any>(path: string, body: any): Promise<T> => (await request('PATCH', path, body)).json(),
  del: async (path: string): Promise<void> => { await request('DELETE', path) },
  download: async (path: string, params?: Record<string, any>) => {
    const res = await request('GET', path + qs(params))
    const cd = res.headers.get('Content-Disposition') || ''
    const name = /filename="?([^";]+)"?/.exec(cd)?.[1] || 'download'
    const url = URL.createObjectURL(await res.blob())
    const a = document.createElement('a')
    a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove()
    URL.revokeObjectURL(url)
  },
}

export async function login(email: string, password: string) {
  const res = await fetch(`${BASE}/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }),
  })
  if (!res.ok) throw await parseError(res)
  const d = await res.json()
  setTokens({ access: d.access_token, refresh: d.refresh_token })
  return d.user
}

export async function logout() {
  try { if (tokens) await api.post('/auth/logout', { refresh_token: tokens.refresh }) } catch { /* ignore */ }
  setTokens(null)
}
