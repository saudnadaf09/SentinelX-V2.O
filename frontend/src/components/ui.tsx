import { ReactNode, useEffect } from 'react'
import { errText, label } from '../services/hooks'

export const sevColor: Record<string, string> = {
  critical: '#ff5c7a', high: '#ff9248', medium: '#f2c94c', low: '#5ab0f0', informational: '#8793a6',
}

export function SeverityBadge({ value }: { value?: string }) {
  const c = sevColor[value || 'informational'] || '#8793a6'
  return (
    <span className="inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs font-medium" style={{ background: c + '22', color: c }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />{value}
    </span>
  )
}

const statusTone: Record<string, string> = {
  new: '#6aa6ff', in_review: '#f2c94c', escalated: '#ff9248', resolved: '#4cc38a', false_positive: '#8793a6',
  open: '#6aa6ff', investigating: '#f2c94c', contained: '#4cc38a', closed: '#8793a6',
  pending_approval: '#f2c94c', executed: '#4cc38a', failed: '#ff5c7a', rejected: '#8793a6', expired: '#8793a6', rolled_back: '#8793a6',
  online: '#4cc38a', stale: '#f2c94c', offline: '#ff5c7a', never_seen: '#8793a6', active: '#4cc38a', revoked: '#ff5c7a',
  deregistered: '#8793a6', untested: '#f2c94c', connected: '#4cc38a', error: '#ff5c7a', unavailable: '#8793a6', suspended: '#ff5c7a',
}
export function StatusBadge({ value }: { value?: string }) {
  const c = statusTone[value || ''] || '#8793a6'
  return <span className="rounded px-2 py-0.5 text-xs font-medium" style={{ background: c + '22', color: c }}>{label(value)}</span>
}

const classTone: Record<string, [string, string]> = {
  live: ['LIVE', '#4cc38a'], simulated: ['SIMULATED', '#b48cff'], test: ['TEST', '#f2c94c'],
  offline: ['OFFLINE', '#ff5c7a'], unclassified: ['UNCLASSIFIED', '#8793a6'],
}
/** LIVE = real telemetry from an authorized source, SIMULATED = demo data, TEST = controlled test data, OFFLINE = source unavailable. */
export function ClassBadge({ value }: { value?: string }) {
  const [text, c] = classTone[value || 'unclassified'] || classTone.unclassified
  return <span title={`Data classification: ${text}`} className="inline-block rounded border px-1.5 py-0.5 text-[10px] font-semibold tracking-wider" style={{ borderColor: c + '66', color: c }}>{text}</span>
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold">{title}</h1>
        {subtitle && <p className="mt-1 max-w-3xl text-muted">{subtitle}</p>}
      </div>
      <div className="flex flex-wrap items-center gap-2">{actions}</div>
    </div>
  )
}

export function Card({ title, actions, children, className = '' }: { title?: string; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-lg border border-line bg-panel ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between border-b border-line px-4 py-3">
          <h2 className="font-medium">{title}</h2><div className="flex gap-2">{actions}</div>
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  )
}

export function Button({ variant = 'default', className = '', ...props }: any) {
  const v = {
    default: 'border border-line bg-raised hover:border-accent',
    primary: 'bg-accent text-ink font-medium hover:brightness-110',
    danger: 'border border-bad/50 text-bad hover:bg-bad/10',
    ghost: 'hover:bg-raised',
  }[variant as string]
  return <button {...props} className={`rounded-md px-3 py-1.5 text-sm disabled:cursor-not-allowed disabled:opacity-50 ${v} ${className}`} />
}

export const Loading = ({ text = 'Loading...' }: { text?: string }) => <div className="p-6 text-muted" role="status">{text}</div>

export function ErrorBox({ error, onRetry }: { error: any; onRetry?: () => void }) {
  if (!error) return null
  return (
    <div role="alert" className="mb-4 flex items-center justify-between gap-3 rounded-md border border-bad/40 bg-bad/10 px-3 py-2 text-bad">
      <span>{errText(error)}{error.requestId ? <span className="ml-2 font-mono text-xs opacity-70">ref {error.requestId.slice(0, 8)}</span> : null}</span>
      {onRetry && <Button onClick={onRetry}>Retry</Button>}
    </div>
  )
}

export function Empty({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="px-4 py-10 text-center">
      <p className="font-medium">{title}</p>
      {hint && <p className="mx-auto mt-1 max-w-md text-muted">{hint}</p>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  )
}

export function Pager({ page, size, total, onPage }: { page: number; size: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / size))
  return (
    <div className="flex items-center justify-between px-3 py-2 text-xs text-muted">
      <span>{total.toLocaleString()} result{total === 1 ? '' : 's'}</span>
      <div className="flex items-center gap-2">
        <Button disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</Button>
        <span>Page {page} of {pages}</span>
        <Button disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</Button>
      </div>
    </div>
  )
}

export function Modal({ title, onClose, children, wide = false }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-16" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div role="dialog" aria-modal="true" aria-label={title} className={`w-full ${wide ? 'max-w-4xl' : 'max-w-lg'} rounded-lg border border-line bg-panel shadow-xl`}>
        <header className="flex items-center justify-between border-b border-line px-4 py-3">
          <h2 className="font-medium">{title}</h2>
          <button aria-label="Close" onClick={onClose} className="rounded px-2 text-muted hover:bg-raised">x</button>
        </header>
        <div className="p-4">{children}</div>
      </div>
    </div>
  )
}

export function Field({ label: l, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="mb-3 block">
      <span className="mb-1 block text-xs text-muted">{l}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  )
}

export const Mono = ({ children }: { children: ReactNode }) => <span className="break-all font-mono text-xs">{children}</span>

export function Stat({ label: l, value, tone, onClick }: { label: string; value: ReactNode; tone?: string; onClick?: () => void }) {
  return (
    <button onClick={onClick} disabled={!onClick} className="rounded-lg border border-line bg-panel p-4 text-left enabled:hover:border-accent disabled:cursor-default">
      <div className="text-xs text-muted">{l}</div>
      <div className="mt-1 text-2xl font-semibold" style={tone ? { color: tone } : undefined}>{value}</div>
    </button>
  )
}

export const Json = ({ data }: { data: any }) => (
  <pre className="max-h-96 overflow-auto rounded-md border border-line bg-ink p-3 font-mono text-xs">{JSON.stringify(data, null, 2)}</pre>
)

export function Select({ value, onChange, options, placeholder, className = '' }: { value: string; onChange: (v: string) => void; options: (string | { value: string; label: string })[]; placeholder?: string; className?: string }) {
  return (
    <select className={`field ${className}`} value={value} onChange={(e) => onChange(e.target.value)}>
      {placeholder !== undefined && <option value="">{placeholder}</option>}
      {options.map((o) => typeof o === 'string' ? <option key={o} value={o}>{label(o)}</option> : <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  )
}
