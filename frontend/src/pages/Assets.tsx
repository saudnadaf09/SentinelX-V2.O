import { FormEvent, useState } from 'react'
import { api } from '../services/api'
import { errText, fmtTime, relTime, useApi } from '../services/hooks'
import { useAuth } from '../auth/AuthContext'
import { Button, Card, ClassBadge, Empty, ErrorBox, Field, Loading, Modal, Mono, PageHeader, Select, StatusBadge } from '../components/ui'

export default function Assets() {
  const { can } = useAuth()
  const [showOld, setShowOld] = useState(false)
  const { data, error, reload } = useApi(() => api.get('/assets', { include_deregistered: showOld }), [showOld], 15000)
  const [reg, setReg] = useState(false), [keys, setKeys] = useState<any>(null), [detail, setDetail] = useState<any>(null), [msg, setMsg] = useState('')
  async function deregister(a: any) {
    if (!confirm(`Deregister ${a.hostname}? All its credentials are revoked and it stops being accepted. Existing events are kept.`)) return
    setMsg(''); try { await api.del(`/assets/${a.id}`); reload() } catch (e: any) { setMsg(errText(e)) }
  }
  return (
    <>
      <PageHeader title="Endpoints" subtitle="Registered Windows and Linux hosts (agent) and network devices (syslog). Status comes only from telemetry or heartbeats actually received."
        actions={<><label className="flex items-center gap-2 text-muted"><input type="checkbox" checked={showOld} onChange={(e) => setShowOld(e.target.checked)} />Show deregistered</label>{can('assets:write') && <Button variant="primary" onClick={() => setReg(true)}>Register endpoint</Button>}</>} />
      {msg && <div role="alert" className="mb-3 text-bad">{msg}</div>}
      <ErrorBox error={error} onRetry={reload} />
      <Card className="!p-0">
        {!data ? <Loading /> : data.items.length === 0 ? <Empty title="No endpoints registered" hint="Register an endpoint, create its API key, then install the agent (see docs/AGENT.md) or send syslog." /> : (
          <div className="overflow-x-auto"><table className="w-full"><thead><tr><th className="th">Host</th><th className="th">Platform</th><th className="th">Data</th><th className="th">Connection</th><th className="th">Last seen</th><th className="th">Agent</th><th className="th">Events</th><th className="th" /></tr></thead>
            <tbody>{data.items.map((a: any) => (
              <tr key={a.id}><td className="td"><button className="text-left text-accent hover:underline" onClick={() => setDetail(a)}>{a.hostname}</button><div className="text-xs text-muted">{a.ip_address || a.source_ip || ''}</div></td>
                <td className="td">{a.platform}</td><td className="td"><ClassBadge value={a.status === 'offline' ? 'offline' : a.data_class} /></td><td className="td"><StatusBadge value={a.status} /></td>
                <td className="td text-muted" title={fmtTime(a.last_seen_at || a.last_heartbeat_at)}>{relTime(a.last_seen_at || a.last_heartbeat_at)}</td>
                <td className="td text-xs text-muted">{a.agent_version ? `v${a.agent_version}` : a.platform === 'network' ? 'syslog' : 'not enrolled'}</td><td className="td">{a.events_received}</td>
                <td className="td text-right whitespace-nowrap">{can('keys:manage') && !a.deregistered_at && <Button onClick={() => setKeys(a)}>API keys</Button>} {can('assets:write') && !a.deregistered_at && <Button variant="danger" onClick={() => deregister(a)}>Deregister</Button>}</td></tr>))}</tbody></table></div>)}
      </Card>
      {reg && <Register onClose={() => setReg(false)} onDone={() => { setReg(false); reload() }} />}
      {keys && <Keys asset={keys} onClose={() => setKeys(null)} />}
      {detail && <Detail a={detail} onClose={() => setDetail(null)} />}
    </>
  )
}

function Detail({ a, onClose }: any) {
  const src = a.collection_status?.sources || {}
  return (
    <Modal wide title={a.hostname} onClose={onClose}>
      <dl className="mb-4 grid gap-x-8 gap-y-1 md:grid-cols-2">
        {[['Platform', a.platform], ['OS', a.os_version || '-'], ['IP address', a.ip_address || '-'], ['Syslog source IP', a.source_ip || '-'], ['Enrolled', fmtTime(a.enrolled_at)], ['Last heartbeat', fmtTime(a.last_heartbeat_at)], ['Last event', fmtTime(a.last_seen_at)], ['Agent', a.agent_version ? `v${a.agent_version}` : '-']].map(([k, v]) => (
          <div key={k} className="flex justify-between border-b border-line/50 py-1"><dt className="text-muted">{k}</dt><dd>{v}</dd></div>))}
      </dl>
      <h3 className="mb-2 font-medium">Collection sources (reported by the agent)</h3>
      {Object.keys(src).length === 0 ? <p className="text-muted">No source report yet. A network device is shown as connected only after its first valid syslog message is received.</p> : (
        <table className="w-full"><thead><tr><th className="th">Source</th><th className="th">Status</th><th className="th">Detail</th></tr></thead>
          <tbody>{Object.entries(src).map(([k, v]: any) => (<tr key={k}><td className="td"><Mono>{k}</Mono></td><td className="td"><StatusBadge value={v.status === 'ok' ? 'connected' : v.status === 'permission_denied' || v.status === 'error' ? 'error' : 'unavailable'} /> <span className="text-xs text-muted">{v.status}</span></td><td className="td text-xs text-muted">{v.detail}</td></tr>))}</tbody></table>)}
      {a.collection_status?.last_error && <p className="mt-3 text-sm text-warn">Last agent error: {a.collection_status.last_error}</p>}
      {a.collection_status?.spooled_events > 0 && <p className="mt-1 text-sm text-warn">{a.collection_status.spooled_events} event(s) are queued on the endpoint waiting to be delivered.</p>}
    </Modal>
  )
}

function Register({ onClose, onDone }: any) {
  const [hostname, setHostname] = useState(''), [platform, setPlatform] = useState('windows'), [owner, setOwner] = useState(''), [src, setSrc] = useState('')
  const [dataClass, setDataClass] = useState('live'), [authorized, setAuthorized] = useState(false), [err, setErr] = useState('')
  async function submit(e: FormEvent) {
    e.preventDefault(); setErr('')
    try { await api.post('/assets/register', { hostname, platform, owner: owner || null, authorized, data_class: dataClass, source_ip: platform === 'network' && src ? src : null }); onDone() } catch (x: any) { setErr(errText(x)) }
  }
  return (
    <Modal title="Register endpoint" onClose={onClose}>
      <form onSubmit={submit}>
        {err && <div role="alert" className="mb-3 text-bad">{err}</div>}
        <Field label="Hostname" hint="Letters, digits, dot, dash, underscore. Unique within your workspace."><input className="field" required pattern="[A-Za-z0-9._-]+" value={hostname} onChange={(e) => setHostname(e.target.value)} /></Field>
        <Field label="Type"><Select value={platform} onChange={setPlatform} options={[{ value: 'windows', label: 'Windows (agent)' }, { value: 'linux', label: 'Linux (agent)' }, { value: 'network', label: 'Network device / syslog source' }]} /></Field>
        {platform === 'network' && <Field label="Device source IP" hint="Syslog datagrams are accepted only from this IP. The device shows as connected only after a valid message arrives."><input className="field" required value={src} onChange={(e) => setSrc(e.target.value)} placeholder="192.0.2.10" /></Field>}
        <Field label="Data classification" hint="LIVE = real monitoring. TEST = controlled testing data (kept clearly separate from live)."><Select value={dataClass} onChange={setDataClass} options={[{ value: 'live', label: 'LIVE' }, { value: 'test', label: 'TEST' }]} /></Field>
        <Field label="Owner (optional)"><input className="field" value={owner} onChange={(e) => setOwner(e.target.value)} /></Field>
        <label className="mb-4 flex items-start gap-2"><input type="checkbox" className="mt-1" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} /><span>I am authorized to monitor this system.</span></label>
        <div className="flex justify-end gap-2"><Button type="button" onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!authorized}>Register</Button></div>
      </form>
    </Modal>
  )
}

function Keys({ asset, onClose }: any) {
  const { data, reload } = useApi(() => api.get(`/assets/${asset.id}/keys`), [asset.id])
  const [name, setName] = useState('collector'), [fresh, setFresh] = useState<string | null>(null), [err, setErr] = useState('')
  const cfg = fresh ? JSON.stringify({ server_url: window.location.origin, api_key: fresh, interval_seconds: 30 }, null, 2) : ''
  return (
    <Modal wide title={`Credentials - ${asset.hostname}`} onClose={onClose}>
      {err && <div role="alert" className="mb-3 text-bad">{err}</div>}
      {fresh && <div className="mb-4 rounded-md border border-ok/40 bg-ok/10 p-3"><div className="mb-1 text-ok">Copy this now. The key is shown only once. Save it as <Mono>agent.json</Mono> on the endpoint:</div>
        <pre className="overflow-auto rounded bg-ink p-2 font-mono text-xs">{cfg}</pre><div className="mt-2"><Button onClick={() => navigator.clipboard?.writeText(cfg)}>Copy agent.json</Button></div></div>}
      <div className="mb-4 flex gap-2"><input className="field" value={name} onChange={(e) => setName(e.target.value)} aria-label="Key name" />
        <Button variant="primary" onClick={async () => { setErr(''); try { const k = await api.post(`/assets/${asset.id}/keys`, { name }); setFresh(k.api_key); reload() } catch (e: any) { setErr(errText(e)) } }}>Create key</Button></div>
      {!data ? <Loading /> : data.items.length === 0 ? <p className="text-muted">No keys yet.</p> : (
        <table className="w-full"><thead><tr><th className="th">Name</th><th className="th">Prefix</th><th className="th">State</th><th className="th">Expires</th><th className="th">Last used</th><th className="th" /></tr></thead>
          <tbody>{data.items.map((k: any) => (<tr key={k.id}><td className="td">{k.name}</td><td className="td"><Mono>sxk_{k.prefix}_...</Mono></td><td className="td"><StatusBadge value={k.state} /></td>
            <td className="td text-muted">{fmtTime(k.expires_at)}</td><td className="td text-muted">{relTime(k.last_used_at)}</td>
            <td className="td">{k.state === 'active' && <Button variant="danger" onClick={async () => { await api.post(`/assets/keys/${k.id}/revoke`); reload() }}>Revoke</Button>}</td></tr>))}</tbody></table>)}
      <p className="mt-3 text-xs text-muted">Rotation: run the agent with <Mono>--rotate-key</Mono>, or create a new key here and revoke the old one.</p>
    </Modal>
  )
}
