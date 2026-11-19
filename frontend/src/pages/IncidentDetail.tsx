import { FormEvent, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../services/api'
import { INCIDENT_STATUSES, SEVERITIES, errText, fmtTime, useApi } from '../services/hooks'
import { useAuth } from '../auth/AuthContext'
import { Button, Card, Empty, ErrorBox, Loading, PageHeader, Select, SeverityBadge, StatusBadge, sevColor } from '../components/ui'

const kindTone: Record<string, string> = { alert: '#ff9248', note: '#6aa6ff', response: '#4cc38a', status: '#8793a6' }

export default function IncidentDetail() {
  const { id } = useParams()
  const { can } = useAuth()
  const { data: inc, error, reload } = useApi(() => api.get(`/incidents/${id}`), [id])
  const { data: tl, reload: reloadTl } = useApi(() => api.get(`/incidents/${id}/timeline`), [id])
  const { data: dir } = useApi(() => api.get('/users/directory'), [])
  const { data: acts } = useApi(() => (can('response:read') ? api.get('/response/actions', { incident_id: id }) : Promise.resolve({ items: [] })), [id])
  const [note, setNote] = useState(''), [msg, setMsg] = useState('')

  async function act(fn: () => Promise<any>) {
    setMsg('')
    try { await fn(); reload(); reloadTl() } catch (e: any) { setMsg(errText(e)) }
  }
  if (!inc) return error ? <ErrorBox error={error} onRetry={reload} /> : <Loading />
  const write = can('incidents:write')

  return (
    <>
      <PageHeader title={inc.title} subtitle={inc.summary || 'No summary recorded.'}
        actions={can('reports:read') && <>
          <Button onClick={() => api.download(`/reports/incidents/${inc.id}`, { format: 'md' })}>Report (MD)</Button>
          <Button onClick={() => api.download(`/reports/incidents/${inc.id}`, { format: 'html' })}>Report (HTML)</Button>
          <Button onClick={() => api.download(`/reports/incidents/${inc.id}`, { format: 'json' })}>Report (JSON)</Button></>} />
      {msg && <div role="alert" className="mb-3 rounded-md border border-bad/40 bg-bad/10 px-3 py-2 text-bad">{msg}</div>}
      <div className="mb-4 grid gap-4 lg:grid-cols-3">
        <Card title="Status">
          <div className="mb-3 flex gap-2"><SeverityBadge value={inc.severity} /><StatusBadge value={inc.status} />{inc.auto_created && <span className="text-xs text-muted">auto-created</span>}</div>
          {write ? (
            <div className="space-y-2">
              <Select value={inc.status} onChange={(v) => act(() => api.patch(`/incidents/${inc.id}`, { status: v }))} options={INCIDENT_STATUSES} />
              <Select value={inc.severity} onChange={(v) => act(() => api.patch(`/incidents/${inc.id}`, { severity: v }))} options={SEVERITIES} />
              <Select value={inc.assignee_id || ''} placeholder="Unassigned" options={(dir?.items || []).map((u: any) => ({ value: u.id, label: u.email }))}
                onChange={(v) => act(() => api.patch(`/incidents/${inc.id}`, v ? { assignee_id: v } : { unassign: true }))} />
            </div>) : <p className="text-muted">Read-only access.</p>}
        </Card>
        <Card title={`Linked alerts (${inc.alerts.length})`} className="lg:col-span-2">
          {inc.alerts.length === 0 ? <Empty title="No alerts linked" /> : (
            <ul className="divide-y divide-line/60">{inc.alerts.map((a: any) => (
              <li key={a.id} className="flex items-center justify-between gap-3 py-2" style={{ boxShadow: `inset 3px 0 0 ${sevColor[a.severity]}`, paddingLeft: 10 }}>
                <div className="min-w-0"><Link to={`/alerts/${a.id}`} className="block truncate">{a.title}</Link>
                  <span className="text-xs text-muted">{a.correlation_reason || a.explanation}</span></div>
                <SeverityBadge value={a.severity} /></li>))}</ul>
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Timeline" className="lg:col-span-2">
          {!tl ? <Loading /> : tl.items.length === 0 ? <Empty title="Nothing yet" /> : (
            <ol className="relative ml-2 border-l border-line">
              {tl.items.map((t: any) => (
                <li key={t.kind + t.ref} className="mb-4 ml-4">
                  <span className="absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full" style={{ background: kindTone[t.kind] }} />
                  <div className="text-xs text-muted">{fmtTime(t.time)} · {t.kind}</div>
                  <div className="font-medium">{t.title} {t.severity && <SeverityBadge value={t.severity} />}</div>
                  {t.detail && <div className="mt-0.5 text-muted">{t.detail}</div>}
                </li>))}
            </ol>
          )}
        </Card>
        <div className="space-y-4">
          <Card title="Analyst notes">
            {inc.notes.length === 0 ? <p className="mb-3 text-muted">No notes yet.</p> : <ul className="mb-3 space-y-2">{inc.notes.map((n: any) => (
              <li key={n.id} className="rounded-md bg-raised p-2"><div className="text-xs text-muted">{n.author} · {fmtTime(n.created_at)}</div>{n.note}</li>))}</ul>}
            {write && <form onSubmit={(e: FormEvent) => { e.preventDefault(); act(async () => { await api.post(`/incidents/${inc.id}/notes`, { note }); setNote('') }) }}>
              <textarea className="field mb-2" rows={3} required placeholder="Add an investigation note" value={note} onChange={(e) => setNote(e.target.value)} />
              <Button variant="primary">Add note</Button></form>}
          </Card>
          <Card title="Response actions" actions={can('response:propose') && <Link to={`/response?incident=${inc.id}`}>Propose</Link>}>
            {!acts || acts.items.length === 0 ? <p className="text-muted">None proposed.</p> : <ul className="space-y-2">{acts.items.map((a: any) => (
              <li key={a.id} className="flex items-center justify-between"><span>{a.action_type.replace(/_/g, ' ')} on {a.asset}</span><StatusBadge value={a.status} /></li>))}</ul>}
          </Card>
        </div>
      </div>
    </>
  )
}
