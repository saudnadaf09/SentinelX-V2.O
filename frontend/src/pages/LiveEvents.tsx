import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../services/api'
import { fmtTime, useApi } from '../services/hooks'
import { Button, Card, Empty, ErrorBox, Json, Loading, Modal, Mono, PageHeader, Pager, Select } from '../components/ui'

const RANGES: Record<string, number> = { '1': 1, '6': 6, '24': 24, '168': 168 }

export function EventDrawer({ event, onClose }: { event: any; onClose: () => void }) {
  const [raw, setRaw] = useState(false)
  const { raw: rawDoc, ...normalized } = event
  return (
    <Modal wide title={`Event ${event.event?.original_id || ''}`} onClose={onClose}>
      <div className="mb-3 flex gap-2">
        <Button variant={raw ? 'default' : 'primary'} onClick={() => setRaw(false)}>Normalized</Button>
        <Button variant={raw ? 'primary' : 'default'} onClick={() => setRaw(true)}>Raw source fields</Button>
      </div>
      <div className="mb-2 text-xs text-muted">Event ID: <Mono>{event.event?.id}</Mono></div>
      <Json data={raw ? rawDoc : normalized} />
    </Modal>
  )
}

export function summarize(e: any) {
  return e.process?.command_line || e.message || [e.event?.action, e.source?.ip && `src ${e.source.ip}`, e.destination?.ip && `dst ${e.destination.ip}:${e.destination.port ?? ''}`].filter(Boolean).join(' ')
}

export default function LiveEvents() {
  const [sp, setSp] = useSearchParams()
  const [page, setPage] = useState(1)
  const [auto, setAuto] = useState(false)
  const [sel, setSel] = useState<any>(null)
  const q = sp.get('q') || '', host = sp.get('host') || '', dataset = sp.get('dataset') || '', range = sp.get('range') || '24'
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); v ? n.set(k, v) : n.delete(k); setSp(n); setPage(1) }
  const { data, error, loading, reload } = useApi(() => {
    const end = new Date(Date.now() + 60000), start = new Date(Date.now() - RANGES[range] * 3600000)
    return api.get('/events', { q, host, dataset, start: start.toISOString(), end: end.toISOString(), page, size: 50 })
  }, [q, host, dataset, range, page], auto ? 5000 : 0)

  return (
    <>
      <PageHeader title="Live Events" subtitle="Normalized security events. Search text matches command lines, users, hosts, IPs and messages."
        actions={<><label className="flex items-center gap-2 text-muted"><input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />Auto-refresh (5s)</label><Button onClick={reload}>Refresh</Button></>} />
      <div className="mb-4 grid gap-2 md:grid-cols-4">
        <input className="field" placeholder="Search text" defaultValue={q} onKeyDown={(e) => e.key === 'Enter' && set('q', (e.target as HTMLInputElement).value)} aria-label="Search text" />
        <input className="field" placeholder="Host name (exact)" defaultValue={host} onKeyDown={(e) => e.key === 'Enter' && set('host', (e.target as HTMLInputElement).value)} aria-label="Host" />
        <Select value={dataset} onChange={(v) => set('dataset', v)} placeholder="All sources" options={['sysmon', 'windows.security', 'linux.auth', 'suricata']} />
        <Select value={range} onChange={(v) => set('range', v)} options={[{ value: '1', label: 'Last hour' }, { value: '6', label: 'Last 6 hours' }, { value: '24', label: 'Last 24 hours' }, { value: '168', label: 'Last 7 days' }]} />
      </div>
      <ErrorBox error={error} onRetry={reload} />
      <Card className="!p-0">
        {!data ? <Loading /> : data.items.length === 0 ? <Empty title="No events match" hint="Widen the time range, clear filters, or replay the sample data." /> : (
          <div className="overflow-x-auto">
            <table className="w-full"><thead><tr><th className="th">Time</th><th className="th">Host</th><th className="th">Source</th><th className="th">Action</th><th className="th">User</th><th className="th">Detail</th></tr></thead>
              <tbody>{data.items.map((e: any) => (
                <tr key={e.event.id} className="cursor-pointer hover:bg-raised" onClick={() => setSel(e)} tabIndex={0} onKeyDown={(k) => k.key === 'Enter' && setSel(e)}>
                  <td className="td whitespace-nowrap text-muted">{fmtTime(e['@timestamp'])}</td><td className="td">{e.host?.name}</td><td className="td text-muted">{e.event?.dataset}</td>
                  <td className="td">{e.event?.action}</td><td className="td">{e.user?.name}</td><td className="td max-w-xl truncate font-mono text-xs" title={summarize(e)}>{summarize(e)}</td></tr>))}</tbody></table>
            <Pager page={page} size={50} total={data.total} onPage={setPage} />
          </div>
        )}
      </Card>
      {loading && data && <div className="mt-2 text-xs text-muted">Refreshing...</div>}
      {sel && <EventDrawer event={sel} onClose={() => setSel(null)} />}
    </>
  )
}
