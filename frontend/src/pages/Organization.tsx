import { FormEvent, useEffect, useState } from 'react'
import { api } from '../services/api'
import { errText, useApi } from '../services/hooks'
import { useAuth } from '../auth/AuthContext'
import { Button, Card, ErrorBox, Field, Loading, Modal, PageHeader } from '../components/ui'

export default function Organization() {
  const { can, logout } = useAuth()
  const { data: org, error, reload } = useApi(() => api.get('/org'), [])
  const [f, setF] = useState<any>({ name: '', contact_email: '', details: '', retention_days: '' })
  const [msg, setMsg] = useState<{ ok: boolean; t: string } | null>(null), [del, setDel] = useState(false)
  useEffect(() => { if (org) setF({ name: org.name, contact_email: org.contact_email || '', details: org.details || '', retention_days: org.retention_days ?? '' }) }, [org])
  const manage = can('org:manage')

  async function save(e: FormEvent) {
    e.preventDefault(); setMsg(null)
    try { await api.patch('/org', { name: f.name, contact_email: f.contact_email, details: f.details, retention_days: f.retention_days === '' ? undefined : Number(f.retention_days) }); setMsg({ ok: true, t: 'Saved' }); reload() } catch (x: any) { setMsg({ ok: false, t: errText(x) }) }
  }
  if (!org) return error ? <ErrorBox error={error} onRetry={reload} /> : <Loading />
  return (
    <>
      <PageHeader title="Organization settings" subtitle={`${org.kind === 'organization' ? 'Organization' : 'Personal'} workspace. All data below belongs only to this workspace.`} />
      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[['Members', org.member_count], ['Endpoints', org.endpoint_count], ['Type', org.kind], ['Event retention', `${org.retention_days ?? org.platform_default_retention_days} days`]].map(([k, v]) => (
          <div key={k as string} className="rounded-lg border border-line bg-panel p-4"><div className="text-xs text-muted">{k}</div><div className="mt-1 text-xl font-semibold capitalize">{v}</div></div>))}
      </div>
      <Card title="Details">
        <form onSubmit={save} className="grid max-w-2xl gap-x-4 md:grid-cols-2">
          <Field label="Name"><input className="field" disabled={!manage} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          <Field label="Contact email"><input className="field" type="email" disabled={!manage} value={f.contact_email} onChange={(e) => setF({ ...f, contact_email: e.target.value })} /></Field>
          <div className="md:col-span-2"><Field label="Details"><textarea className="field" rows={3} disabled={!manage} value={f.details} onChange={(e) => setF({ ...f, details: e.target.value })} /></Field></div>
          <Field label="Event retention (days)" hint={`Events older than this are deleted automatically. Platform default: ${org.platform_default_retention_days} days.`}><input className="field" type="number" min={1} max={3650} disabled={!manage} value={f.retention_days} onChange={(e) => setF({ ...f, retention_days: e.target.value })} /></Field>
          <div className="md:col-span-2">{manage ? <Button variant="primary">Save changes</Button> : <span className="text-muted">Only organization admins can change these settings.</span>}{msg && <span role="status" className={`ml-3 ${msg.ok ? 'text-ok' : 'text-bad'}`}>{msg.t}</span>}</div>
        </form>
      </Card>
      {manage && (
        <Card title="Data export and deletion" className="mt-4">
          <p className="mb-3 text-muted">Export a JSON copy of your workspace (members, endpoints, alerts with evidence, incidents, audit trail; no passwords or keys), or permanently delete everything. Raw events can be exported from the Live Events page.</p>
          <div className="flex gap-2"><Button onClick={() => api.download('/org/export')}>Export workspace data</Button><Button variant="danger" onClick={() => setDel(true)}>Delete workspace</Button></div>
        </Card>)}
      {del && <DeleteDialog name={org.name} onClose={() => setDel(false)} onDone={() => logout()} />}
    </>
  )
}

function DeleteDialog({ name, onClose, onDone }: any) {
  const [pw, setPw] = useState(''), [confirm, setConfirm] = useState(''), [err, setErr] = useState('')
  return (
    <Modal title="Delete workspace permanently" onClose={onClose}>
      <p className="mb-3 text-bad">This irreversibly deletes all members, endpoints, events, alerts, incidents and settings of <b>{name}</b>. Audit records are append-only and are retained.</p>
      {err && <div role="alert" className="mb-2 text-bad">{err}</div>}
      <Field label="Your password"><input className="field" type="password" value={pw} onChange={(e) => setPw(e.target.value)} /></Field>
      <Field label={`Type the workspace name (${name}) to confirm`}><input className="field" value={confirm} onChange={(e) => setConfirm(e.target.value)} /></Field>
      <div className="flex justify-end gap-2"><Button onClick={onClose}>Cancel</Button>
        <Button variant="danger" disabled={!pw || confirm !== name} onClick={async () => { try { await api.post('/org/delete', { password: pw, confirm_name: confirm }); onDone() } catch (e: any) { setErr(errText(e)) } }}>Delete everything</Button></div>
    </Modal>
  )
}
