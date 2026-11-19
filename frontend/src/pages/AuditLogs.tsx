import { useState } from 'react'
import { api } from '../services/api'
import { fmtTime, useApi } from '../services/hooks'
import { Button, Card, Empty, ErrorBox, Loading, Modal, Mono, PageHeader, Pager, Json } from '../components/ui'

export default function AuditLogs() {
  const [action, setAction] = useState(''), [actor, setActor] = useState(''), [page, setPage] = useState(1), [sel, setSel] = useState<any>(null)
  const { data, error, reload } = useApi(() => api.get('/audit-logs', { action, actor, page, size: 50 }), [action, actor, page])
  return (
    <>
      <PageHeader title="Audit Logs" subtitle="Append-only record of security-relevant actions: logins, rule and access changes, investigations, approvals and response results."
        actions={<Button onClick={() => api.download('/audit-logs/export.csv', { action, actor })}>Export CSV</Button>} />
      <div className="mb-4 grid gap-2 md:grid-cols-3">
        <input className="field" placeholder="Action prefix (e.g. response., rule., auth.)" defaultValue={action} onKeyDown={(e) => { if (e.key === 'Enter') { setAction((e.target as HTMLInputElement).value); setPage(1) } }} aria-label="Action prefix" />
        <input className="field" placeholder="Actor email contains" defaultValue={actor} onKeyDown={(e) => { if (e.key === 'Enter') { setActor((e.target as HTMLInputElement).value); setPage(1) } }} aria-label="Actor" />
      </div>
      <ErrorBox error={error} onRetry={reload} />
      <Card className="!p-0">
        {!data ? <Loading /> : data.items.length === 0 ? <Empty title="No audit entries match" /> : (
          <div className="overflow-x-auto"><table className="w-full"><thead><tr><th className="th">Time</th><th className="th">Actor</th><th className="th">Action</th><th className="th">Target</th><th className="th">Outcome</th><th className="th">Request</th></tr></thead>
            <tbody>{data.items.map((e: any) => (
              <tr key={e.id} className="cursor-pointer hover:bg-raised" onClick={() => setSel(e)}><td className="td whitespace-nowrap text-muted">{fmtTime(e.timestamp)}</td><td className="td">{e.actor_email}</td><td className="td">{e.action}</td>
                <td className="td text-xs">{e.target_type} <Mono>{e.target_id.slice(0, 8)}</Mono></td><td className="td"><span className={e.outcome === 'success' ? 'text-ok' : 'text-bad'}>{e.outcome}</span></td><td className="td"><Mono>{e.request_id.slice(0, 8)}</Mono></td></tr>))}</tbody></table>
            <Pager page={page} size={50} total={data.total} onPage={setPage} /></div>)}
      </Card>
      {sel && <Modal wide title={`Audit entry #${sel.id}`} onClose={() => setSel(null)}><Json data={sel} /></Modal>}
    </>
  )
}
