import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../services/api'
import { useApi } from '../services/hooks'
import { Button, Card, Empty, ErrorBox, Loading, PageHeader, Select, SeverityBadge, StatusBadge } from '../components/ui'
import { useAuth } from '../auth/AuthContext'

export default function Reports() {
  const { can } = useAuth()
  const { data, error, reload } = useApi(() => api.get('/incidents', { size: 100 }), [])
  const [sev, setSev] = useState('')
  return (
    <>
      <PageHeader title="Reports" subtitle="Incident reports include time range, alerts with rule versions, evidence event IDs, notes, response actions, investigations and known limitations." />
      <ErrorBox error={error} onRetry={reload} />
      <div className="mb-4 grid gap-4 lg:grid-cols-3">
        <Card title="Alert export" className="lg:col-span-1">
          <div className="space-y-2"><Select value={sev} onChange={setSev} placeholder="All severities" options={['critical', 'high', 'medium', 'low', 'informational']} />
            <Button variant="primary" onClick={() => api.download('/reports/alerts.csv', { severity: sev })}>Download alerts.csv</Button></div>
        </Card>
        {can('audit:read') && <Card title="Audit export"><p className="mb-2 text-muted">Filtered export lives on the Audit Logs page.</p><Link to="/audit">Go to Audit Logs</Link></Card>}
      </div>
      <Card title="Incident reports" className="!p-0">
        {!data ? <Loading /> : data.items.length === 0 ? <Empty title="No incidents to report on yet" /> : (
          <table className="w-full"><thead><tr><th className="th">Incident</th><th className="th">Severity</th><th className="th">Status</th><th className="th">Download</th></tr></thead>
            <tbody>{data.items.map((i: any) => (<tr key={i.id}><td className="td"><Link to={`/incidents/${i.id}`}>{i.title}</Link></td><td className="td"><SeverityBadge value={i.severity} /></td><td className="td"><StatusBadge value={i.status} /></td>
              <td className="td"><div className="flex gap-2">{['md', 'html', 'json'].map((f) => <Button key={f} onClick={() => api.download(`/reports/incidents/${i.id}`, { format: f })}>{f.toUpperCase()}</Button>)}</div></td></tr>))}</tbody></table>)}
      </Card>
    </>
  )
}
