import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../services/api'
import { ALERT_STATUSES, SEVERITIES, fmtTime, useApi } from '../services/hooks'
import { Button, Card, ClassBadge, Empty, ErrorBox, Loading, PageHeader, Pager, Select, SeverityBadge, StatusBadge, sevColor } from '../components/ui'

export default function Alerts() {
  const [sp, setSp] = useSearchParams()
  const [page, setPage] = useState(1)
  const severity = sp.get('severity') || '', status = sp.get('status') || '', q = sp.get('q') || '', host = sp.get('host') || '', technique = sp.get('technique') || ''
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); v ? n.set(k, v) : n.delete(k); setSp(n); setPage(1) }
  const { data, error, reload } = useApi(() => api.get('/alerts', { severity, status, q, host, technique, page, size: 25 }), [severity, status, q, host, technique, page], 20000)

  return (
    <>
      <PageHeader title="Alerts" subtitle="Rule-based detections with the evidence that triggered them."
        actions={<Button onClick={() => api.download('/reports/alerts.csv', { severity, status })}>Export CSV</Button>} />
      <div className="mb-4 grid gap-2 md:grid-cols-4">
        <input className="field" placeholder="Search title, host, user, IP" defaultValue={q} onKeyDown={(e) => e.key === 'Enter' && set('q', (e.target as HTMLInputElement).value)} aria-label="Search alerts" />
        <Select value={severity} onChange={(v) => set('severity', v)} placeholder="All severities" options={SEVERITIES} />
        <Select value={status} onChange={(v) => set('status', v)} placeholder="All statuses" options={ALERT_STATUSES} />
        <div className="flex items-center gap-2 text-muted">{(host || technique) && <>{host && <span>host: {host}</span>}{technique && <span>technique: {technique}</span>}<Button onClick={() => { set('host', ''); set('technique', '') }}>Clear</Button></>}</div>
      </div>
      <ErrorBox error={error} onRetry={reload} />
      <Card className="!p-0">
        {!data ? <Loading /> : data.items.length === 0 ? <Empty title="No alerts match these filters" hint="Alerts appear when telemetry matches a detection rule." /> : (
          <div className="overflow-x-auto">
            <table className="w-full"><thead><tr><th className="th">Severity</th><th className="th">Alert</th><th className="th">Host</th><th className="th">User / source</th><th className="th">Events</th><th className="th">Last seen</th><th className="th">Status</th></tr></thead>
              <tbody>{data.items.map((a: any) => (
                <tr key={a.id} className="hover:bg-raised">
                  <td className="td" style={{ boxShadow: `inset 3px 0 0 ${sevColor[a.severity]}` }}><SeverityBadge value={a.severity} /></td>
                  <td className="td"><Link to={`/alerts/${a.id}`}>{a.title}</Link><div className="text-xs text-muted">{a.rule_key} v{a.rule_version}{a.incident_id ? ' · in incident' : ''} <ClassBadge value={a.data_class} /></div></td>
                  <td className="td">{a.host_name}</td><td className="td text-muted">{[a.user_name, a.source_ip].filter(Boolean).join(' / ')}</td>
                  <td className="td">{a.event_count}</td><td className="td whitespace-nowrap text-muted">{fmtTime(a.last_seen)}</td><td className="td"><StatusBadge value={a.status} /></td></tr>))}</tbody></table>
            <Pager page={page} size={25} total={data.total} onPage={setPage} />
          </div>
        )}
      </Card>
    </>
  )
}
