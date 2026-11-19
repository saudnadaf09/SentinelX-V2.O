import { useState } from 'react'
import { api } from '../services/api'
import { errText, fmtTime, useApi } from '../services/hooks'
import { useAuth } from '../auth/AuthContext'
import { Button, Card, ErrorBox, Loading, Modal, PageHeader, SeverityBadge, StatusBadge } from '../components/ui'

const template = (prefix: string) => `id: ${prefix}CUSTOM-001
title: Example custom rule
description: Describe what this detects.
version: 1
severity: low
type: match
tags: [custom]
mitre:
  - technique_id: T1059
match:
  all:
    - {field: event.action, op: eq, value: process_creation}
    - {field: process.name, op: eq, value: example.exe}
group_by: [host.name]
dedupe_window_seconds: 300
false_positives: [Describe known benign causes]
next_checks: [Describe what an analyst should verify]
`

export default function ThreatDetection() {
  const { can } = useAuth()
  const { data, error, reload } = useApi(() => api.get('/rules'), [])
  const [view, setView] = useState<any>(null), [creating, setCreating] = useState(false), [msg, setMsg] = useState('')
  const write = can('rules:org_write'), override = can('rules:override'), global = can('rules:write')

  async function toggle(r: any) {
    setMsg('')
    try { await api.patch(`/rules/${r.id}`, { enabled: !r.enabled_for_org, scope: 'organization' }); reload() } catch (e: any) { setMsg(errText(e)) }
  }
  return (
    <>
      <PageHeader title="Threat Detection" subtitle="Deterministic YAML rules. Platform rules apply to everyone and you can switch them off for your workspace. Your own rules (ids start with your prefix) apply only to your data. New rules start disabled."
        actions={write && <Button variant="primary" onClick={() => setCreating(true)}>New rule</Button>} />
      {msg && <div role="alert" className="mb-3 text-bad">{msg}</div>}
      <ErrorBox error={error} onRetry={reload} />
      <Card className="!p-0">
        {!data ? <Loading /> : (
          <div className="overflow-x-auto"><table className="w-full"><thead><tr><th className="th">Rule</th><th className="th">Severity</th><th className="th">Type</th><th className="th">ATT&CK</th><th className="th">Scope</th><th className="th">Version</th><th className="th">Updated</th><th className="th">Active for you</th></tr></thead>
            <tbody>{data.items.map((r: any) => (
              <tr key={r.id} className="hover:bg-raised">
                <td className="td"><button className="text-left text-accent hover:underline" onClick={async () => setView(await api.get(`/rules/${r.id}`))}>{r.title}</button><div className="text-xs text-muted">{r.rule_key} · {r.origin}</div></td>
                <td className="td"><SeverityBadge value={r.severity} /></td><td className="td">{r.type}</td>
                <td className="td text-xs">{r.mitre.map((m: any) => m.technique_id).join(', ')}</td><td className="td text-xs text-muted">{r.scope === 'organization' ? 'your organization' : 'platform'}</td><td className="td">v{r.version}</td><td className="td text-muted">{fmtTime(r.updated_at)}</td>
                <td className="td">{(r.scope === 'organization' ? write : override) ? <label className="flex items-center gap-2"><input type="checkbox" checked={r.enabled_for_org} onChange={() => toggle(r)} aria-label={`Enable ${r.rule_key}`} />{r.enabled_for_org ? 'on' : 'off'}</label> : <StatusBadge value={r.enabled_for_org ? 'active' : 'revoked'} />}{global && r.scope === 'global' && <div className="text-[10px] text-muted">global: {r.enabled_global ? 'on' : 'off'}</div>}</td></tr>))}</tbody></table></div>
        )}
      </Card>
      {view && <Modal wide title={`${view.rule_key} v${view.version}`} onClose={() => setView(null)}><p className="mb-3 text-muted">{view.description}</p>
        <pre className="max-h-[28rem] overflow-auto rounded-md border border-line bg-ink p-3 font-mono text-xs">{view.yaml}</pre></Modal>}
      {creating && <RuleEditor prefix={data?.org_rule_prefix || 'ORG-'} onClose={() => setCreating(false)} onSaved={() => { setCreating(false); reload() }} />}
    </>
  )
}

function RuleEditor({ onClose, onSaved, prefix }: any) {
  const [yaml, setYaml] = useState(template(prefix)), [result, setResult] = useState<any>(null), [err, setErr] = useState('')
  return (
    <Modal wide title="New detection rule" onClose={onClose}>
      <textarea className="field h-80 font-mono text-xs" value={yaml} onChange={(e) => { setYaml(e.target.value); setResult(null) }} spellCheck={false} aria-label="Rule YAML" />
      {result && <div className={`mt-2 ${result.valid ? 'text-ok' : 'text-bad'}`} role="status">{result.valid ? `Valid ${result.type} rule ${result.rule_key}` : result.error}</div>}
      {err && <div role="alert" className="mt-2 text-bad">{err}</div>}
      <div className="mt-3 flex justify-end gap-2">
        <Button onClick={async () => { try { setResult(await api.post('/rules/validate', { yaml, scope: 'organization' })) } catch (e: any) { setErr(errText(e)) } }}>Validate</Button>
        <Button variant="primary" onClick={async () => { setErr(''); try { await api.post('/rules', { yaml, scope: 'organization' }); onSaved() } catch (e: any) { setErr(errText(e)) } }}>Save (disabled)</Button>
      </div>
    </Modal>
  )
}
