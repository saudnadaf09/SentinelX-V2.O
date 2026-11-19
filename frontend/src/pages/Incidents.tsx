import { FormEvent, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../services/api'
import { INCIDENT_STATUSES, SEVERITIES, errText, relTime, useApi } from '../services/hooks'
import { useAuth } from '../auth/AuthContext'
import { Button, Card, Empty, ErrorBox, Field, Loading, Modal, PageHeader, Pager, Select, SeverityBadge, StatusBadge } from '../components/ui'

export default function Incidents() {
  const { can } = useAuth()
  const nav = useNavigate()
  const [sp, setSp] = useSearchParams()
  const [page, setPage] = useState(1)
  const [creating, setCreating] = useState(false)
  const status = sp.get('status') || '', severity = sp.get('severity') || ''
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); v ? n.set(k, v) : n.delete(k); setSp(n); setPage(1) }
  const { data, error, reload } = useApi(() => api.get('/incidents', { status, severity, page, size: 25 }), [status, severity, page], 20000)

  return (
    <>
      <PageHeader title="Incidents" subtitle="Grouped alerts under investigation. Auto-created incidents explain why their alerts were correlated."
        actions={can('incidents:write') && <Button variant="primary" onClick={() => setCreating(true)}>New incident</Button>} />
      <div className="mb-4 grid gap-2 md:grid-cols-4">
        <Select value={status} onChange={(v) => set('status', v)} placeholder="All statuses" options={INCIDENT_STATUSES} />
        <Select value={severity} onChange={(v) => set('severity', v)} placeholder="All severities" options={SEVERITIES} />
      </div>
      <ErrorBox error={error} onRetry={reload} />
      <Card className="!p-0">
        {!data ? <Loading /> : data.items.length === 0 ? <Empty title="No incidents" hint="Incidents are created automatically when alerts correlate, or manually from an alert." /> : (
          <div className="overflow-x-auto"><table className="w-full"><thead><tr><th className="th">Incident</th><th className="th">Severity</th><th className="th">Status</th><th className="th">Alerts</th><th className="th">Origin</th><th className="th">Updated</th></tr></thead>
            <tbody>{data.items.map((i: any) => (
              <tr key={i.id} className="hover:bg-raised"><td className="td"><Link to={`/incidents/${i.id}`}>{i.title}</Link></td><td className="td"><SeverityBadge value={i.severity} /></td>
                <td className="td"><StatusBadge value={i.status} /></td><td className="td">{i.alert_count}</td><td className="td text-muted">{i.auto_created ? 'correlation' : 'analyst'}</td><td className="td text-muted">{relTime(i.updated_at)}</td></tr>))}</tbody></table>
            <Pager page={page} size={25} total={data.total} onPage={setPage} /></div>
        )}
      </Card>
      {creating && <CreateIncident onClose={() => setCreating(false)} onCreated={(id: string) => nav(`/incidents/${id}`)} />}
    </>
  )
}

function CreateIncident({ onClose, onCreated }: any) {
  const [title, setTitle] = useState(''), [severity, setSeverity] = useState('medium'), [summary, setSummary] = useState('')
  const [err, setErr] = useState(''), [busy, setBusy] = useState(false)
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setErr('')
    try { const i = await api.post('/incidents', { title, severity, summary }); onCreated(i.id) } catch (x: any) { setErr(errText(x)) } finally { setBusy(false) }
  }
  return (
    <Modal title="New incident" onClose={onClose}>
      <form onSubmit={submit}>
        {err && <div role="alert" className="mb-3 text-bad">{err}</div>}
        <Field label="Title"><input className="field" required minLength={3} value={title} onChange={(e) => setTitle(e.target.value)} /></Field>
        <Field label="Severity"><Select value={severity} onChange={setSeverity} options={SEVERITIES} /></Field>
        <Field label="Summary"><textarea className="field" rows={4} value={summary} onChange={(e) => setSummary(e.target.value)} /></Field>
        <div className="flex justify-end gap-2"><Button type="button" onClick={onClose}>Cancel</Button><Button variant="primary" disabled={busy}>Create incident</Button></div>
      </form>
    </Modal>
  )
}
