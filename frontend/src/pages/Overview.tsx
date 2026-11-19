import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../services/api'
import { SEVERITIES, fmtTime, relTime, useApi } from '../services/hooks'
import { Card, ClassBadge, Empty, ErrorBox, Loading, PageHeader, SeverityBadge, Select, Stat, StatusBadge, sevColor } from '../components/ui'

export default function Overview() {
  const nav = useNavigate()
  const [hours, setHours] = useState('24')
  const { data, error, reload } = useApi(() => api.get('/dashboard/overview', { hours }), [hours], 15000)
  if (!data) return <>{error ? <ErrorBox error={error} onRetry={reload} /> : <Loading />}</>

  const sev = SEVERITIES.map((s) => ({ name: s, count: data.alerts.by_severity[s] || 0 }))
  const timeline = data.events.timeline.map((t: any) => ({ ...t, label: new Date(t.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }))
  const online = data.assets.filter((a: any) => a.status === 'online').length
  const live = data.assets.filter((a: any) => a.data_class === 'live')
  const p = data.pipeline, ev = data.events.by_class || {}, al = data.alerts.by_class || {}
  const liveOnline = live.filter((a: any) => a.status === 'online').length

  return (
    <>
      <PageHeader title="Overview" subtitle="Figures come from your workspace's stored records. Each is labelled LIVE (real telemetry), SIMULATED (demo data) or TEST."
        actions={<Select className="w-36" value={hours} onChange={setHours} options={[{ value: '1', label: 'Last hour' }, { value: '6', label: 'Last 6 hours' }, { value: '24', label: 'Last 24 hours' }, { value: '168', label: 'Last 7 days' }]} />} />
      <ErrorBox error={error} onRetry={reload} />
      {!data.event_store_available && <div role="alert" className="mb-4 rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-warn">Event store unavailable: event charts are empty. Alerts and incidents still work.</div>}
      {live.length === 0 && <div role="note" className="mb-4 rounded-md border border-line bg-panel px-3 py-2 text-muted">No LIVE endpoints yet. Everything shown may be SIMULATED demo data. Register an endpoint and install the agent to see real telemetry (see Endpoints).</div>}

      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label={`Events (${hours}h)`} value={data.events.total.toLocaleString()} onClick={() => nav('/events')} />
        <Stat label="Open alerts" value={data.alerts.open} tone={data.alerts.open ? '#ff9248' : undefined} onClick={() => nav('/alerts?status=new')} />
        <Stat label="Open incidents" value={data.incidents.open} tone={data.incidents.open ? '#ff5c7a' : undefined} onClick={() => nav('/incidents?status=open')} />
        <Stat label="Endpoints online" value={`${online} / ${data.assets.length}`} onClick={() => nav('/assets')} />
      </div>

      <div className="mb-4 grid gap-3 lg:grid-cols-3">
        <Card title="Data classification">
          <div className="space-y-1.5 text-sm">
            <div className="text-xs text-muted">Events</div>
            <div className="flex flex-wrap gap-3">{Object.keys(ev).length ? Object.entries(ev).map(([k, v]) => <span key={k} className="flex items-center gap-1.5"><ClassBadge value={k} /> {(v as number).toLocaleString()}</span>) : <span className="text-muted">none</span>}</div>
            <div className="pt-1 text-xs text-muted">Alerts</div>
            <div className="flex flex-wrap gap-3">{Object.keys(al).length ? Object.entries(al).map(([k, v]) => <span key={k} className="flex items-center gap-1.5"><ClassBadge value={k} /> {v as number}</span>) : <span className="text-muted">none</span>}</div>
          </div>
        </Card>
        <Card title="Live endpoint health">
          {live.length === 0 ? <span className="text-muted">No live endpoints registered.</span> : <div><div className="text-2xl font-semibold">{liveOnline} / {live.length}</div><div className="text-xs text-muted">LIVE endpoints reporting within 5 minutes</div></div>}
        </Card>
        <Card title="AI provider" actions={<Link to="/ai-settings">Configure</Link>}>
          <div className="flex items-center gap-2"><StatusBadge value={data.ai.state} /></div>
          <p className="mt-1 text-sm text-muted">{data.ai.configured ? `${data.ai.provider} / ${data.ai.model}` : ''} {data.ai.message}</p>
        </Card>
      </div>

      <div className="mb-4 grid gap-4 lg:grid-cols-3">
        <Card title="Events over time" className="lg:col-span-2">
          {timeline.length === 0 ? <Empty title="No events in this window" hint="Events appear once an endpoint or network device sends telemetry." /> : (
            <div className="h-56" role="img" aria-label="Events over time"><ResponsiveContainer><AreaChart data={timeline}>
              <CartesianGrid stroke="#2a3544" strokeDasharray="3 3" /><XAxis dataKey="label" stroke="#8793a6" fontSize={11} /><YAxis stroke="#8793a6" fontSize={11} allowDecimals={false} />
              <Tooltip contentStyle={{ background: '#1b2430', border: '1px solid #2a3544' }} /><Area dataKey="count" stroke="#6aa6ff" fill="#6aa6ff33" name="Events" /></AreaChart></ResponsiveContainer></div>)}
        </Card>
        <Card title="Alerts by severity">
          <div className="h-56" role="img" aria-label="Alerts by severity"><ResponsiveContainer><BarChart data={sev} layout="vertical" margin={{ left: 20 }}>
            <XAxis type="number" stroke="#8793a6" fontSize={11} allowDecimals={false} /><YAxis type="category" dataKey="name" stroke="#8793a6" fontSize={11} width={80} />
            <Tooltip contentStyle={{ background: '#1b2430', border: '1px solid #2a3544' }} cursor={{ fill: '#ffffff0a' }} />
            <Bar dataKey="count" name="Alerts" cursor="pointer" onClick={(d: any) => nav(`/alerts?severity=${d.name}`)}>{sev.map((s) => <Cell key={s.name} fill={sevColor[s.name]} />)}</Bar></BarChart></ResponsiveContainer></div>
        </Card>
      </div>

      <div className="mb-4 grid gap-4 lg:grid-cols-2">
        <Card title="Latest alerts" actions={<Link to="/alerts">All alerts</Link>}>
          {data.alerts.latest.length === 0 ? <Empty title="No alerts yet" hint="Alerts are created only when a detection rule matches real stored events." /> : (
            <ul className="divide-y divide-line/60">{data.alerts.latest.map((a: any) => (
              <li key={a.id} className="flex items-center justify-between gap-3 py-2"><div className="min-w-0"><Link to={`/alerts/${a.id}`} className="block truncate">{a.title}</Link>
                <span className="text-xs text-muted">{a.host_name} · {relTime(a.last_seen)} <ClassBadge value={a.data_class} /></span></div><SeverityBadge value={a.severity} /></li>))}</ul>)}
        </Card>
        <Card title="Open incidents" actions={<Link to="/incidents">All incidents</Link>}>
          {data.incidents.items.length === 0 ? <Empty title="No open incidents" /> : (
            <ul className="divide-y divide-line/60">{data.incidents.items.map((i: any) => (
              <li key={i.id} className="flex items-center justify-between gap-3 py-2"><div className="min-w-0"><Link to={`/incidents/${i.id}`} className="block truncate">{i.title}</Link>
                <span className="text-xs text-muted">{i.alert_count} alert(s) · {relTime(i.updated_at)}</span></div><div className="flex gap-2"><SeverityBadge value={i.severity} /><StatusBadge value={i.status} /></div></li>))}</ul>)}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Top hosts by events">
          {data.events.top_hosts.length === 0 ? <Empty title="No data" /> : data.events.top_hosts.map((h: any) => (
            <button key={h.host} onClick={() => nav(`/events?host=${encodeURIComponent(h.host)}`)} className="flex w-full justify-between py-1.5 hover:text-accent"><span>{h.host}</span><span className="text-muted">{h.count}</span></button>))}
        </Card>
        <Card title="Endpoint health and last seen" className="lg:col-span-2">
          {data.assets.length === 0 ? <Empty title="No endpoints registered" hint="Register an endpoint under Endpoints, then install the agent or point a syslog device at SentinelX." /> : (
            <table className="w-full"><thead><tr><th className="th">Host</th><th className="th">Data</th><th className="th">Status</th><th className="th">Last seen</th><th className="th">Events</th></tr></thead>
              <tbody>{data.assets.map((a: any) => (<tr key={a.id}><td className="td">{a.hostname}</td><td className="td"><ClassBadge value={a.status === 'offline' ? 'offline' : a.data_class} /></td><td className="td"><StatusBadge value={a.status} /></td>
                <td className="td text-muted" title={fmtTime(a.last_seen_at || a.last_heartbeat_at)}>{relTime(a.last_seen_at || a.last_heartbeat_at)}</td><td className="td">{a.events_received}</td></tr>))}</tbody></table>)}
        </Card>
      </div>

      {p && <div className="mt-4 flex flex-wrap gap-x-6 gap-y-1 rounded-lg border border-line bg-panel px-4 py-3 text-xs text-muted" aria-label="Pipeline counters">
        <span>Platform pipeline:</span>
        {['received', 'rejected', 'queued', 'processed', 'duplicates', 'quarantined', 'failed', 'dead_letter'].map((k) => <span key={k}>{k.replace('_', '-')} <b className="text-fg">{p[k] ?? 0}</b></span>)}
        <span>queue depth <b className="text-fg">{p.depth}</b></span><span>dead-letter backlog <b className={p.dead_letter_depth ? 'text-bad' : 'text-fg'}>{p.dead_letter_depth}</b></span>
      </div>}
    </>
  )
}
