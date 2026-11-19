import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../services/api'
import { ALERT_STATUSES, SEVERITIES, errText, fmtTime, useApi } from '../services/hooks'
import { useAuth } from '../auth/AuthContext'
import { Button, Card, ClassBadge, ErrorBox, Loading, Mono, PageHeader, Select, SeverityBadge, StatusBadge } from '../components/ui'

export default function AlertDetail() {
  const { id } = useParams()
  const nav = useNavigate()
  const { can } = useAuth()
  const { data: a, error, reload } = useApi(() => api.get(`/alerts/${id}`), [id])
  const { data: dir } = useApi(() => (can('alerts:read') ? api.get('/users/directory') : Promise.resolve({ items: [] })), [])
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  async function act(fn: () => Promise<any>) {
    setBusy(true); setMsg('')
    try { await fn(); await reload() } catch (e: any) { setMsg(errText(e)) } finally { setBusy(false) }
  }
  if (!a) return error ? <ErrorBox error={error} onRetry={reload} /> : <Loading />
  const write = can('alerts:write')
  const ctx = a.rule_context || {}

  return (
    <>
      <PageHeader title={a.title} subtitle={a.explanation}
        actions={<>
          {<Button onClick={() => nav(`/ai?alert=${a.id}`)}>Investigate</Button>}
          {can('incidents:write') && !a.incident_id && <Button variant="primary" disabled={busy} onClick={() => act(async () => { const i = await api.post(`/alerts/${a.id}/incident`); nav(`/incidents/${i.id}`) })}>Create incident</Button>}
        </>} />
      {msg && <div role="alert" className="mb-3 rounded-md border border-bad/40 bg-bad/10 px-3 py-2 text-bad">{msg}</div>}
      <div className="mb-4 grid gap-4 lg:grid-cols-3">
        <Card title="Triage" className="lg:col-span-1">
          <dl className="space-y-2">
            <div className="flex justify-between"><dt className="text-muted">Severity</dt><dd><SeverityBadge value={a.severity} /></dd></div>
            <div className="flex justify-between"><dt className="text-muted">Status</dt><dd><StatusBadge value={a.status} /></dd></div>
            <div className="flex justify-between"><dt className="text-muted">Data</dt><dd><ClassBadge value={a.data_class} /></dd></div>
            <div className="flex justify-between"><dt className="text-muted">Rule</dt><dd>{a.rule_key} v{a.rule_version}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Host</dt><dd>{a.host_name || '-'}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">User</dt><dd>{a.user_name || '-'}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Source IP</dt><dd>{a.source_ip || '-'}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">First seen</dt><dd>{fmtTime(a.first_seen)}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Last seen</dt><dd>{fmtTime(a.last_seen)}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Events</dt><dd>{a.event_count}</dd></div>
            {a.incident_id && <div className="flex justify-between"><dt className="text-muted">Incident</dt><dd><Link to={`/incidents/${a.incident_id}`}>Open incident</Link></dd></div>}
          </dl>
          {write && (
            <div className="mt-4 space-y-2 border-t border-line pt-4">
              <Select value={a.status} onChange={(v) => act(() => api.patch(`/alerts/${a.id}`, { status: v }))} options={ALERT_STATUSES} />
              <Select value={a.severity} onChange={(v) => act(() => api.patch(`/alerts/${a.id}`, { severity: v }))} options={SEVERITIES} />
              <Select value={a.assignee_id || ''} placeholder="Unassigned" options={(dir?.items || []).map((u: any) => ({ value: u.id, label: u.email }))}
                onChange={(v) => act(() => api.patch(`/alerts/${a.id}`, v ? { assignee_id: v } : { unassign: true }))} />
            </div>
          )}
        </Card>
        <div className="space-y-4 lg:col-span-2">
          <Card title="ATT&CK mapping (from the rule)">
            {a.mitre.length === 0 ? <span className="text-muted">No techniques mapped.</span> : (
              <ul className="space-y-2">{a.mitre.map((m: any) => (
                <li key={m.technique_id}><a href={m.url} target="_blank" rel="noreferrer noopener">{m.technique_id} {m.name}</a>
                  <span className="ml-2 text-xs text-muted">{m.tactics.join(', ')}</span></li>))}</ul>
            )}
          </Card>
          {a.correlation_reason && <Card title="Why related alerts were grouped"><p>{a.correlation_reason}</p></Card>}
          <Card title="Rule context">
            <p className="mb-3 text-muted">{ctx.description}</p>
            {ctx.false_positives?.length > 0 && <><div className="mb-1 text-xs text-muted">Possible benign explanations</div><ul className="mb-3 list-disc pl-5">{ctx.false_positives.map((x: string) => <li key={x}>{x}</li>)}</ul></>}
            {ctx.next_checks?.length > 0 && <><div className="mb-1 text-xs text-muted">Suggested next checks</div><ul className="list-disc pl-5">{ctx.next_checks.map((x: string) => <li key={x}>{x}</li>)}</ul></>}
          </Card>
        </div>
      </div>
      <Card title={`Evidence (${a.evidence.length} of ${a.event_count} events kept)`} className="!p-0">
        <div className="overflow-x-auto">
          <table className="w-full"><thead><tr><th className="th">Time</th><th className="th">Event ID</th><th className="th">Action</th><th className="th">User</th><th className="th">Source / destination</th><th className="th">Command / message</th></tr></thead>
            <tbody>{a.evidence.map((e: any) => (
              <tr key={e.event_id}><td className="td whitespace-nowrap text-muted">{fmtTime(e.timestamp)}</td><td className="td"><Mono>{e.event_id}</Mono></td>
                <td className="td">{e['event.action']}</td><td className="td">{e['user.name']}</td>
                <td className="td">{[e['source.ip'], e['destination.ip'] && `-> ${e['destination.ip']}:${e['destination.port'] ?? ''}`].filter(Boolean).join(' ')}</td>
                <td className="td font-mono text-xs">{e['process.command_line'] || e.message || ''}</td></tr>))}</tbody></table>
        </div>
      </Card>
    </>
  )
}
