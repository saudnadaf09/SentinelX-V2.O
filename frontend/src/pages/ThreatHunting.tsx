import { useState } from 'react'
import { api } from '../services/api'
import { errText, fmtTime, useApi } from '../services/hooks'
import { Button, Card, Empty, ErrorBox, Modal, PageHeader, Pager, Select } from '../components/ui'
import { EventDrawer, summarize } from './LiveEvents'

const FIELDS = ['host.name', 'user.name', 'source.ip', 'destination.ip', 'destination.port', 'process.name', 'process.executable', 'process.command_line', 'process.parent.name', 'event.action', 'event.category', 'event.dataset', 'event.outcome', 'file.path', 'group.name', 'rule.name', 'network.transport', 'observer.product']
const OPS = [{ value: 'eq', label: 'equals' }, { value: 'ne', label: 'not equals' }, { value: 'contains', label: 'contains' }, { value: 'prefix', label: 'starts with' }]
type Row = { field: string; op: string; value: string }

export default function ThreatHunting() {
  const [rows, setRows] = useState<Row[]>([{ field: 'process.command_line', op: 'contains', value: '' }])
  const [text, setText] = useState(''), [hours, setHours] = useState('24'), [page, setPage] = useState(1)
  const [result, setResult] = useState<any>(null), [error, setError] = useState<any>(null), [busy, setBusy] = useState(false)
  const [sel, setSel] = useState<any>(null), [saving, setSaving] = useState(false), [name, setName] = useState('')
  const { data: saved, reload } = useApi(() => api.get('/hunt/saved'), [])

  const definition = () => ({ text, hours, filters: rows.filter((r) => r.value.trim()) })
  async function run(p = 1) {
    setBusy(true); setError(null); setPage(p)
    try {
      const end = new Date(Date.now() + 60000), start = new Date(Date.now() - Number(hours) * 3600000)
      setResult(await api.post('/hunt/search', { start: start.toISOString(), end: end.toISOString(), text: text || null, filters: rows.filter((r) => r.value.trim()), page: p, size: 50 }))
    } catch (e) { setError(e) } finally { setBusy(false) }
  }
  const update = (i: number, patch: Partial<Row>) => setRows(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)))

  return (
    <>
      <PageHeader title="Threat Hunting" subtitle="Build a structured query over normalized events. Only allow-listed fields and operators are accepted; time range is required and capped." />
      <div className="mb-4 grid gap-4 lg:grid-cols-3">
        <Card title="Query" className="lg:col-span-2">
          {rows.map((r, i) => (
            <div key={i} className="mb-2 grid grid-cols-12 gap-2">
              <div className="col-span-4"><Select value={r.field} onChange={(v) => update(i, { field: v })} options={FIELDS} /></div>
              <div className="col-span-3"><Select value={r.op} onChange={(v) => update(i, { op: v })} options={OPS} /></div>
              <input className="field col-span-4" placeholder="value" value={r.value} onChange={(e) => update(i, { value: e.target.value })} aria-label="Filter value" onKeyDown={(e) => e.key === 'Enter' && run(1)} />
              <Button className="col-span-1" aria-label="Remove filter" onClick={() => setRows(rows.filter((_, j) => j !== i))} disabled={rows.length === 1}>x</Button>
            </div>))}
          <div className="mb-3"><Button disabled={rows.length >= 10} onClick={() => setRows([...rows, { field: 'host.name', op: 'eq', value: '' }])}>Add filter</Button></div>
          <div className="grid gap-2 md:grid-cols-2">
            <input className="field" placeholder="Free text (optional)" value={text} onChange={(e) => setText(e.target.value)} aria-label="Free text" />
            <Select value={hours} onChange={setHours} options={[{ value: '1', label: 'Last hour' }, { value: '24', label: 'Last 24 hours' }, { value: '168', label: 'Last 7 days' }, { value: '720', label: 'Last 30 days' }]} />
          </div>
          <div className="mt-3 flex gap-2"><Button variant="primary" disabled={busy} onClick={() => run(1)}>{busy ? 'Searching...' : 'Run hunt'}</Button><Button onClick={() => setSaving(true)}>Save query</Button></div>
        </Card>
        <Card title="Saved hunts">
          {!saved || saved.items.length === 0 ? <p className="text-muted">No saved hunts yet.</p> : (
            <ul className="space-y-2">{saved.items.map((s: any) => (
              <li key={s.id} className="flex items-center justify-between gap-2">
                <button className="truncate text-left text-accent hover:underline" onClick={() => { const d = s.definition; setRows(d.filters?.length ? d.filters : rows); setText(d.text || ''); setHours(d.hours || '24') }}>{s.name}</button>
                <Button variant="ghost" aria-label={`Delete ${s.name}`} onClick={async () => { await api.del(`/hunt/saved/${s.id}`); reload() }}>Delete</Button></li>))}</ul>
          )}
        </Card>
      </div>
      <ErrorBox error={error} />
      {result && (
        <Card title="Results" className="!p-0">
          {result.items.length === 0 ? <Empty title="No matching events" hint="Loosen a filter or extend the time range." /> : (
            <div className="overflow-x-auto"><table className="w-full"><thead><tr><th className="th">Time</th><th className="th">Host</th><th className="th">User</th><th className="th">Action</th><th className="th">Detail</th></tr></thead>
              <tbody>{result.items.map((e: any) => (
                <tr key={e.event.id} className="cursor-pointer hover:bg-raised" onClick={() => setSel(e)}><td className="td whitespace-nowrap text-muted">{fmtTime(e['@timestamp'])}</td><td className="td">{e.host?.name}</td><td className="td">{e.user?.name}</td><td className="td">{e.event?.action}</td><td className="td max-w-xl truncate font-mono text-xs">{summarize(e)}</td></tr>))}</tbody></table>
              <Pager page={page} size={50} total={result.total} onPage={run} /></div>
          )}
        </Card>)}
      {sel && <EventDrawer event={sel} onClose={() => setSel(null)} />}
      {saving && (
        <Modal title="Save hunt" onClose={() => setSaving(false)}>
          <input className="field mb-3" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <div className="flex justify-end gap-2"><Button onClick={() => setSaving(false)}>Cancel</Button>
            <Button variant="primary" disabled={!name.trim()} onClick={async () => { try { await api.post('/hunt/saved', { name, definition: definition() }); setName(''); setSaving(false); reload() } catch (e) { setError(e); setSaving(false) } }}>Save</Button></div>
        </Modal>)}
    </>
  )
}
