import { FormEvent, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../services/api'
import { errText, fmtTime, useApi } from '../services/hooks'
import { useAuth } from '../auth/AuthContext'
import { Button, Card, ClassBadge, Empty, ErrorBox, Field, Loading, Modal, PageHeader, Select, StatusBadge } from '../components/ui'

const PARAM: Record<string, { key: string; label: string; options?: string[]; placeholder?: string } | null> = {
  disable_test_account: { key: 'account', label: 'Simulated account name', placeholder: 'svc_backup' },
  isolate_lab_host: null,
  collect_evidence: { key: 'script', label: 'Collection script', options: ['process_list', 'network_connections', 'logged_on_users'] },
  block_test_indicator: { key: 'ip', label: 'Reserved test IP', placeholder: '203.0.113.50' },
}

export default function ResponseCenter() {
  const { can, user } = useAuth()
  const [sp] = useSearchParams()
  const [status, setStatus] = useState('')
  const [open, setOpen] = useState(!!sp.get('incident'))
  const [msg, setMsg] = useState('')
  const { data, error, reload } = useApi(() => api.get('/response/actions', { status }), [status], 10000)

  async function decide(id: string, verb: string) {
    setMsg('')
    try { await api.post(`/response/actions/${id}/${verb}`, verb === 'rollback' ? undefined : {}); reload() } catch (e: any) { setMsg(errText(e)) }
  }
  return (
    <>
      <PageHeader title="Response Center" subtitle="XDR-lite actions run through a MOCK adapter against registered lab assets only. Every action needs a dry run, a different person to approve it, and is audited. Nothing outside SentinelX is changed."
        actions={can('response:propose') && <Button variant="primary" onClick={() => setOpen(true)}>Propose action</Button>} />
      <div role="note" className="mb-4 rounded-md border border-[#b48cff]/40 bg-[#b48cff]/10 px-3 py-2 text-sm"><ClassBadge value="simulated" /> <span className="ml-2">Every action here is a simulation. Nothing is isolated, blocked, disabled or collected on any real endpoint, and results never claim otherwise. Real adapters are not implemented.</span></div>
      <div className="mb-4 w-56"><Select value={status} onChange={setStatus} placeholder="All statuses" options={['pending_approval', 'executed', 'rejected', 'expired', 'failed', 'rolled_back']} /></div>
      {msg && <div role="alert" className="mb-3 rounded-md border border-bad/40 bg-bad/10 px-3 py-2 text-bad">{msg}</div>}
      <ErrorBox error={error} onRetry={reload} />
      {!data ? <Loading /> : data.items.length === 0 ? <Card><Empty title="No response actions" hint="Propose a lab-safe action from here or from an incident." /></Card> : (
        <div className="space-y-3">{data.items.map((a: any) => (
          <Card key={a.id}>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div><div className="font-medium">{a.action_type.replace(/_/g, ' ')} on {a.asset} <ClassBadge value="simulated" /></div>
                <div className="text-xs text-muted">requested by {a.requested_by} · {fmtTime(a.created_at)}{a.status === 'pending_approval' && ` · expires ${fmtTime(a.expires_at)}`}</div></div>
              <StatusBadge value={a.status} />
            </div>
            <p className="mt-2">{a.rationale}</p>
            <div className="mt-2 grid gap-2 md:grid-cols-2">
              <div className="rounded-md bg-raised p-2"><div className="text-xs text-muted">Dry run</div>{a.dry_run_result?.would}</div>
              {a.result && <div className="rounded-md bg-raised p-2"><div className="text-xs text-muted">Result</div>{a.result.performed || a.result.error}{a.result.rollback && <div className="text-muted">{a.result.rollback.rolled_back}</div>}</div>}
            </div>
            <div className="mt-3 flex gap-2">
              {a.status === 'pending_approval' && can('response:approve') && (a.requested_by !== user?.email
                ? <><Button variant="primary" onClick={() => decide(a.id, 'approve')}>Approve and execute (mock)</Button><Button variant="danger" onClick={() => decide(a.id, 'reject')}>Reject</Button></>
                : <span className="text-xs text-muted">You proposed this action; another approver must decide it.</span>)}
              {a.status === 'executed' && can('response:approve') && <Button onClick={() => decide(a.id, 'rollback')}>Roll back</Button>}
            </div>
          </Card>))}</div>)}
      {open && <Propose incident={sp.get('incident') || ''} onClose={() => setOpen(false)} onDone={() => { setOpen(false); reload() }} />}
    </>
  )
}

function Propose({ incident, onClose, onDone }: any) {
  const { data: assets } = useApi(() => api.get('/assets'), [])
  const { data: cat } = useApi(() => api.get('/response/catalog'), [])
  const [assetId, setAssetId] = useState(''), [type, setType] = useState('isolate_lab_host'), [val, setVal] = useState(''), [why, setWhy] = useState(''), [err, setErr] = useState('')
  const spec = PARAM[type]
  async function submit(e: FormEvent) {
    e.preventDefault(); setErr('')
    const parameters = spec ? { [spec.key]: spec.options && !val ? spec.options[0] : val } : {}
    try { await api.post('/response/actions', { asset_id: assetId, action_type: type, parameters, rationale: why, incident_id: incident || null, idempotency_key: crypto.randomUUID() }); onDone() } catch (x: any) { setErr(errText(x)) }
  }
  return (
    <Modal title="Propose response action" onClose={onClose}>
      <form onSubmit={submit}>
        {err && <div role="alert" className="mb-3 text-bad">{err}</div>}
        <Field label="Lab asset"><Select value={assetId} onChange={setAssetId} placeholder="Select an asset" options={(assets?.items || []).filter((a: any) => a.is_lab_authorized).map((a: any) => ({ value: a.id, label: a.hostname }))} /></Field>
        <Field label="Action" hint={cat?.items.find((c: any) => c.action_type === type)?.impact}>
          <Select value={type} onChange={(v) => { setType(v); setVal('') }} options={(cat?.items || []).map((c: any) => ({ value: c.action_type, label: c.title }))} /></Field>
        {spec && <Field label={spec.label}>{spec.options ? <Select value={val || spec.options[0]} onChange={setVal} options={spec.options} /> : <input className="field" required placeholder={spec.placeholder} value={val} onChange={(e) => setVal(e.target.value)} />}</Field>}
        <Field label="Rationale"><textarea className="field" rows={3} required minLength={5} value={why} onChange={(e) => setWhy(e.target.value)} /></Field>
        <div className="flex justify-end gap-2"><Button type="button" onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!assetId}>Create dry run</Button></div>
      </form>
    </Modal>
  )
}
