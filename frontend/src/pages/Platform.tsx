import { useState } from 'react'
import { api } from '../services/api'
import { errText, fmtTime, useApi } from '../services/hooks'
import { Button, Card, ErrorBox, Loading, PageHeader, StatusBadge } from '../components/ui'

export default function Platform() {
  const { data, error, reload } = useApi(() => api.get('/platform/orgs'), [])
  const { data: au } = useApi(() => api.get('/platform/audit', { size: 25 }), [])
  const [msg, setMsg] = useState('')
  async function toggle(o: any) { setMsg(''); try { await api.patch(`/platform/orgs/${o.id}`, { is_active: !o.is_active }); reload() } catch (e: any) { setMsg(errText(e)) } }
  return (
    <>
      <PageHeader title="Platform administration" subtitle="Organizations on this server. You see aggregate counts only: tenant events, alerts and incidents stay private to each workspace." />
      {msg && <div role="alert" className="mb-3 text-bad">{msg}</div>}
      <ErrorBox error={error} onRetry={reload} />
      <Card className="!p-0">
        {!data ? <Loading /> : <div className="overflow-x-auto"><table className="w-full"><thead><tr><th className="th">Workspace</th><th className="th">Type</th><th className="th">Members</th><th className="th">Endpoints</th><th className="th">Alerts</th><th className="th">Created</th><th className="th">Status</th><th className="th" /></tr></thead>
          <tbody>{data.items.map((o: any) => (<tr key={o.id}><td className="td">{o.name}<div className="text-xs text-muted">{o.contact_email}</div></td><td className="td">{o.kind}</td><td className="td">{o.member_count}</td><td className="td">{o.endpoint_count}</td><td className="td">{o.alert_count}</td>
            <td className="td text-muted">{fmtTime(o.created_at)}</td><td className="td"><StatusBadge value={o.is_active ? 'active' : 'suspended'} /></td>
            <td className="td text-right"><Button variant={o.is_active ? 'danger' : 'default'} onClick={() => toggle(o)}>{o.is_active ? 'Suspend' : 'Reactivate'}</Button></td></tr>))}</tbody></table></div>}
      </Card>
      <Card title="Platform audit" className="mt-4 !p-0">
        <table className="w-full"><thead><tr><th className="th">Time</th><th className="th">Actor</th><th className="th">Action</th><th className="th">Outcome</th></tr></thead>
          <tbody>{(au?.items || []).map((e: any) => (<tr key={e.id}><td className="td whitespace-nowrap text-muted">{fmtTime(e.timestamp)}</td><td className="td">{e.actor_email}</td><td className="td">{e.action}</td><td className="td">{e.outcome}</td></tr>))}</tbody></table>
      </Card>
    </>
  )
}
