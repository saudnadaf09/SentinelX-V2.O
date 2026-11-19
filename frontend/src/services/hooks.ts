import { useCallback, useEffect, useRef, useState } from 'react'

/** Fetch on mount/deps change, optional polling. Keeps previous data visible while reloading. */
export function useApi<T = any>(fn: () => Promise<T>, deps: any[] = [], pollMs = 0) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const seq = useRef(0)
  const run = useCallback(() => {
    const id = ++seq.current
    setLoading(true)
    fn().then((d) => { if (id === seq.current) { setData(d); setError(null) } })
      .catch((e) => { if (id === seq.current) setError(e) })
      .finally(() => { if (id === seq.current) setLoading(false) })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  useEffect(() => {
    run()
    if (!pollMs) return
    const t = setInterval(run, pollMs)
    return () => clearInterval(t)
  }, [run, pollMs])
  return { data, error, loading, reload: run }
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational']
export const ALERT_STATUSES = ['new', 'in_review', 'escalated', 'resolved', 'false_positive']
export const INCIDENT_STATUSES = ['open', 'investigating', 'contained', 'closed']

export function fmtTime(v?: string | null) {
  if (!v) return '-'
  const d = new Date(v)
  return isNaN(d.getTime()) ? String(v) : d.toLocaleString()
}
export function relTime(v?: string | null) {
  if (!v) return '-'
  const s = Math.round((Date.now() - new Date(v).getTime()) / 1000)
  if (s < 0) return 'just now'
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}
export const label = (s?: string | null) => (s || '').replace(/_/g, ' ')
export function errText(e: any) {
  if (!e) return ''
  const d = e.details?.length ? ' (' + e.details.map((x: any) => `${x.field}: ${x.message}`).join('; ') + ')' : ''
  return `${e.message || 'Request failed'}${d}`
}
