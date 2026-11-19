import { useNavigate } from 'react-router-dom'
import { api } from '../services/api'
import { useApi } from '../services/hooks'
import { Card, ErrorBox, Loading, PageHeader } from '../components/ui'

export default function Mitre() {
  const nav = useNavigate()
  const { data, error, reload } = useApi(() => api.get('/mitre/techniques'), [])
  if (!data) return error ? <ErrorBox error={error} onRetry={reload} /> : <Loading />
  const used = data.tactics.filter((t: string) => data.items.some((i: any) => i.tactics.includes(t)))
  const covered = data.items.filter((i: any) => i.rules.length).length
  return (
    <>
      <PageHeader title="MITRE ATT&CK" subtitle={`${data.dataset}. Mappings come from detection rules, so every technique below traces to a rule. Techniques with no rule are not covered.`} />
      <div className="mb-4 text-muted">{covered} of {data.items.length} listed techniques have at least one rule.</div>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {used.map((tactic: string) => (
          <Card key={tactic} title={tactic}>
            <ul className="space-y-2">
              {data.items.filter((i: any) => i.tactics.includes(tactic)).map((t: any) => (
                <li key={t.technique_id} className={`rounded-md border p-2 ${t.rules.length ? 'border-accentdim bg-accentdim/20' : 'border-line opacity-60'}`}>
                  <div className="flex items-start justify-between gap-2">
                    <a href={t.url} target="_blank" rel="noreferrer noopener">{t.technique_id} {t.name}</a>
                    {t.alert_count > 0 && <button className="shrink-0 rounded bg-bad/20 px-2 text-xs text-bad" onClick={() => nav(`/alerts?technique=${t.technique_id}`)}>{t.alert_count} alert{t.alert_count > 1 ? 's' : ''}</button>}
                  </div>
                  <div className="mt-1 text-xs text-muted">{t.rules.length ? t.rules.map((r: any) => r.rule_key + (r.enabled ? '' : ' (off)')).join(', ') : 'no rule coverage'}</div>
                </li>))}
            </ul>
          </Card>))}
      </div>
    </>
  )
}
