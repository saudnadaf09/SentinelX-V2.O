import { FormEvent, useEffect, useState } from 'react'
import { api } from '../services/api'
import { errText, fmtTime, useApi } from '../services/hooks'
import { Button, Card, ErrorBox, Field, Loading, PageHeader, Select, StatusBadge } from '../components/ui'

export default function AISettings() {
  const { data: prov } = useApi(() => api.get('/ai/providers'), [])
  const { data: cur, error, reload } = useApi(() => api.get('/ai/settings'), [])
  const [provider, setProvider] = useState('openai'), [model, setModel] = useState(''), [key, setKey] = useState(''), [enabled, setEnabled] = useState(true)
  const [msg, setMsg] = useState<{ ok: boolean; t: string } | null>(null), [test, setTest] = useState<any>(null), [busy, setBusy] = useState(false)
  const org = cur?.organization, eff = cur?.effective
  const meta = prov?.items.find((p: any) => p.id === provider)

  useEffect(() => { if (org) { setProvider(org.provider); setModel(org.model); setEnabled(org.enabled) } }, [org?.provider, org?.model])
  useEffect(() => { if (!org && meta && !model) setModel(meta.default_model) }, [meta])

  async function save(e: FormEvent) {
    e.preventDefault(); setMsg(null); setBusy(true)
    try { await api.put('/ai/settings', { provider, model, api_key: key || undefined, enabled }); setKey(''); setTest(null); setMsg({ ok: true, t: 'Saved. The key is stored encrypted on the server and is never shown again.' }); reload() }
    catch (x: any) { setMsg({ ok: false, t: errText(x) }) } finally { setBusy(false) }
  }
  async function runTest() {
    setBusy(true); setTest(null)
    try { setTest(await api.post('/ai/settings/test', key ? { provider, model, api_key: key } : {})); reload() } catch (x: any) { setTest({ ok: false, message: errText(x) }) } finally { setBusy(false) }
  }
  if (!cur || !prov) return error ? <ErrorBox error={error} onRetry={reload} /> : <Loading />
  return (
    <>
      <PageHeader title="AI provider settings" subtitle="Connect a provider so the AI Investigator can analyze your alerts and incidents. Keys stay on the server, encrypted; the browser never receives them." />
      <Card title="Connection status" className="mb-4">
        <div className="flex flex-wrap items-center gap-3">
          <StatusBadge value={eff.state} />
          <span>{eff.configured ? `${eff.provider} / ${eff.model} (${eff.source} configuration)${eff.key_hint ? ` · key ${eff.key_hint}` : ''}` : 'No provider configured: AI features are unavailable.'}</span>
        </div>
        <p className="mt-2 text-sm text-muted">{eff.message}{eff.last_test_at ? ` Last test: ${fmtTime(eff.last_test_at)}.` : ''}</p>
        <p className="mt-1 text-xs text-muted">"Connected" appears only after a real test request to the provider succeeds. Saving a key does not prove it works.</p>
      </Card>
      <Card title="Provider">
        <form onSubmit={save} className="max-w-xl">
          <Field label="Provider"><Select value={provider} onChange={(v) => { setProvider(v); setModel(prov.items.find((p: any) => p.id === v)?.default_model || '') }} options={prov.items.map((p: any) => ({ value: p.id, label: p.label }))} /></Field>
          <Field label="Model" hint="Suggestions below; type any model name your account can use."><input className="field" list="models" required value={model} onChange={(e) => setModel(e.target.value)} />
            <datalist id="models">{(meta?.models || []).map((m: string) => <option key={m} value={m} />)}</datalist></Field>
          <Field label={org?.key_set ? `API key (leave empty to keep the saved key ${org.key_hint})` : 'API key'}><input className="field" type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} placeholder={org?.key_set ? '••••••••' : 'Paste your provider API key'} /></Field>
          <label className="mb-4 flex items-center gap-2"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />Enabled</label>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="primary" disabled={busy || (!org?.key_set && !key)}>Save</Button>
            <Button type="button" disabled={busy || (!org?.key_set && !key)} onClick={runTest}>{busy ? 'Working...' : 'Test connection'}</Button>
            {org && <Button type="button" variant="danger" onClick={async () => { await api.del('/ai/settings'); setTest(null); reload() }}>Remove configuration</Button>}
            {msg && <span role="status" className={msg.ok ? 'text-ok' : 'text-bad'}>{msg.t}</span>}
          </div>
        </form>
        {test && <div role="status" className={`mt-4 rounded-md border p-3 ${test.ok ? 'border-ok/40 bg-ok/10 text-ok' : 'border-bad/40 bg-bad/10 text-bad'}`}>
          {test.ok ? `Connected: the provider answered a live request in ${test.latency_ms} ms.` : `Connection FAILED${test.error_kind ? ` (${test.error_kind})` : ''}: ${test.message}`}</div>}
      </Card>
    </>
  )
}
