import { Link } from 'react-router-dom'
import { api } from '../services/api'
import { useApi } from '../services/hooks'
import { useAuth } from '../auth/AuthContext'
import { Card, ErrorBox, Loading, PageHeader, StatusBadge } from '../components/ui'

export default function Settings() {
  const { user, can } = useAuth()
  return (
    <>
      <PageHeader title="Settings" subtitle={`Signed in as ${user?.email} (${user?.role.replace('_', ' ')}) in ${user?.organization?.name}.`} />
      <div className="mb-4 grid gap-4 md:grid-cols-3">
        <Card title="Account"><p className="mb-2 text-muted">Profile, password, sessions.</p><Link to="/profile">My profile</Link></Card>
        {can('users:manage') && <Card title="Team and roles"><p className="mb-2 text-muted">Members, invitations, role changes, access revocation.</p><Link to="/team">Manage team</Link></Card>}
        {can('ai:configure') && <Card title="AI provider"><p className="mb-2 text-muted">OpenAI, Gemini or Anthropic: model, key, connection test.</p><Link to="/ai-settings">AI settings</Link></Card>}
      </div>
      {can('settings:read') && <System />}
    </>
  )
}

function System() {
  const { data, error } = useApi(() => api.get('/settings/system'), [])
  const { data: ready } = useApi(() => api.get('/health/ready'), [], 20000)
  if (error) return <ErrorBox error={error} />
  if (!data) return <Loading />
  const rows: [string, any][] = [['Version', data.version], ['Environment', data.environment], ['Queue backend', data.queue_backend], ['Event store', data.store_backend],
    ['Platform event retention (days)', data.event_retention_days], ['Collector key lifetime (days)', data.collector_key_ttl_days], ['Active detection rules', data.active_rules],
    ['Correlation window (s)', data.correlation_window_seconds], ['Response adapter', data.response_adapter], ['Approval window (min)', data.approval_ttl_minutes],
    ['Registration', data.registration_enabled ? 'open' : 'disabled'], ['Email', data.mail_mode === 'smtp' ? 'SMTP (real delivery)' : 'console mode (no real email is sent)'],
    ['Email verification required', data.email_verification_required ? 'yes' : 'no'], ['Syslog UDP port', data.syslog_udp_port || 'disabled'],
    ['AI', data.ai.configured ? `${data.ai.provider} / ${data.ai.model} (${data.ai.state})` : 'unavailable (not configured)']]
  return (
    <Card title="System (read-only; change values in backend/.env and restart)">
      <dl className="grid gap-x-8 gap-y-2 md:grid-cols-2">{rows.map(([k, v]) => <div key={k} className="flex justify-between border-b border-line/50 py-1"><dt className="text-muted">{k}</dt><dd>{String(v)}</dd></div>)}</dl>
      {ready && <div className="mt-3 flex gap-4 text-xs">{Object.entries(ready.checks).map(([k, v]) => <span key={k} className={v ? 'text-ok' : 'text-bad'}>{k}: {v ? 'ok' : 'down'}</span>)}</div>}
    </Card>
  )
}
