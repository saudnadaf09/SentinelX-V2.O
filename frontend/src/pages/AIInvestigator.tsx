import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../services/api'
import { errText, fmtTime, useApi } from '../services/hooks'
import { useAuth } from '../auth/AuthContext'
import { Button, Card, Empty, ErrorBox, Mono, PageHeader, Select, StatusBadge } from '../components/ui'

function List({ items, empty = 'None' }: { items?: string[]; empty?: string }) {
  return items?.length ? <ul className="list-disc pl-5">{items.map((x, i) => <li key={i}>{x}</li>)}</ul> : <span className="text-muted">{empty}</span>
}

export function Analysis({ inv }: { inv: any }) {
  const o = inv.output, ai = o.ai_generated
  return (
    <div className="space-y-4">
      <div className={`rounded-md border px-3 py-2 text-sm ${ai ? 'border-accent/40 bg-accentdim/20' : 'border-line bg-raised'}`}>
        <b>{ai ? 'AI-GENERATED analysis' : 'RULE-BASED summary (no AI used)'}</b>
        <span className="text-muted"> · {ai ? `${inv.provider} / ${inv.model}` : 'built from rule metadata and stored evidence'} · {fmtTime(inv.created_at)}</span>
        <div className="mt-1 text-xs text-muted">{o.disclaimer}</div>{inv.note && <div className="mt-1 text-xs text-warn">{inv.note}</div>}
      </div>
      <Card title="Summary"><p>{o.summary}</p></Card>
      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Verified evidence (cited events)">{o.evidence?.length ? <ul className="space-y-2">{o.evidence.map((e: any) => <li key={e.event_id}><Mono>{e.event_id}</Mono><div>{e.observation}</div></li>)}</ul> : <span className="text-muted">No events were cited.</span>}</Card>
        <Card title={ai ? 'AI hypotheses (unverified)' : 'Assessment'}>{ai ? <List items={o.hypotheses} empty="None offered" /> : <p>{o.assessment}</p>}{ai && o.assessment && <p className="mt-2 text-muted">{o.assessment}</p>}</Card>
        <Card title="Possible benign explanations"><List items={o.benign_explanations} /></Card>
        <Card title="Unknown or unavailable information"><List items={o.unknowns} empty="None stated" /></Card>
        <Card title="Investigation steps"><List items={o.next_checks} /></Card>
        <Card title="Recommendations / remediation"><List items={o.recommendations} empty="None offered" /></Card>
      </div>
      <Card title="ATT&CK context"><p>{o.attack_context}</p></Card>
      <Card title="Limitations"><List items={o.limitations} /></Card>
    </div>
  )
}

export default function AIInvestigator() {
  const { can } = useAuth()
  const [sp, setSp] = useSearchParams()
  const alertId = sp.get('alert') || ''
  const { data: alerts } = useApi(() => api.get('/alerts', { size: 100 }), [])
  const { data: status, reload: reloadStatus } = useApi(() => api.get('/ai/status'), [])
  const { data: hist, reload } = useApi(() => api.get('/ai/investigations'), [])
  const [inv, setInv] = useState<any>(null), [busy, setBusy] = useState(''), [err, setErr] = useState<any>(null)
  const available = status?.configured

  async function run(kind: 'investigate' | 'rule-summary') {
    setBusy(kind); setErr(null)
    try { setInv(await api.post(`/ai/${kind}/${alertId}`)); reload() } catch (e) { setErr(e); reloadStatus() } finally { setBusy('') }
  }
  return (
    <>
      <PageHeader title="AI Investigator" subtitle="Analyzes the stored evidence, related alerts, incident notes and nearby host events of a selected alert. Output separates verified evidence, hypotheses, recommendations and unknowns." />
      {status && (
        <div className={`mb-4 flex flex-wrap items-center gap-3 rounded-md border px-3 py-2 ${available ? 'border-line bg-panel' : 'border-warn/40 bg-warn/10'}`}>
          <StatusBadge value={status.state} />
          <span>{available ? `${status.provider} / ${status.model}. ${status.message}` : 'AI is unavailable: no provider is configured for this workspace.'}</span>
          {can('ai:configure') && <Link to="/ai-settings">AI provider settings</Link>}
        </div>)}
      <Card className="mb-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[18rem] flex-1"><span className="mb-1 block text-xs text-muted">Alert</span>
            <Select value={alertId} onChange={(v) => { const n = new URLSearchParams(); if (v) n.set('alert', v); setSp(n); setInv(null) }} placeholder="Select an alert"
              options={(alerts?.items || []).map((a: any) => ({ value: a.id, label: `[${a.severity}] ${a.title} - ${a.host_name || ''}` }))} /></div>
          <Button variant="primary" disabled={!alertId || !!busy || !available || !can('ai:use')} onClick={() => run('investigate')}>{busy === 'investigate' ? 'Asking the AI provider...' : 'Investigate with AI'}</Button>
          <Button disabled={!alertId || !!busy} onClick={() => run('rule-summary')}>Rule-based summary (no AI)</Button>
          {alertId && <Link to={`/alerts/${alertId}`}>Open alert</Link>}
        </div>
        {!can('ai:use') && <p className="mt-2 text-xs text-muted">Your role cannot start AI investigations.</p>}
      </Card>
      {err && <ErrorBox error={err} />}
      {inv && <div className="mb-6"><Analysis inv={inv} /></div>}
      <Card title="Investigation history" className="!p-0">
        {!hist || hist.items.length === 0 ? <Empty title="No investigations yet" /> : (
          <table className="w-full"><thead><tr><th className="th">When</th><th className="th">Alert</th><th className="th">Type</th><th className="th" /></tr></thead>
            <tbody>{hist.items.map((h: any) => (<tr key={h.id}><td className="td text-muted">{fmtTime(h.created_at)}</td><td className="td"><Link to={`/alerts/${h.alert_id}`}>{h.alert_title}</Link></td><td className="td">{h.mode === 'llm' ? `AI (${h.provider})` : 'rule-based'}</td>
              <td className="td text-right"><Button onClick={() => setInv(h)}>View</Button></td></tr>))}</tbody></table>)}
      </Card>
    </>
  )
}
