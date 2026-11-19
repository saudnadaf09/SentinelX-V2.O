import { FormEvent, useState } from 'react'
import { api } from '../services/api'
import { errText, fmtTime, useApi } from '../services/hooks'
import { useAuth } from '../auth/AuthContext'
import { Button, Card, Empty, ErrorBox, Field, Loading, Mono, PageHeader, Select, StatusBadge } from '../components/ui'

const ROLE_HELP: Record<string, string> = {
  org_admin: 'Owner: members, roles, endpoints, settings, AI provider, audit.',
  analyst: 'Investigate events, review alerts, manage incidents, reports, AI investigations.',
  engineer: 'Detection rules (organization), collectors and API keys, technical settings.',
  viewer: 'Read-only dashboards, events, alerts, incidents and reports.',
}

export default function Team() {
  const { user } = useAuth()
  const { data: m, error, reload } = useApi(() => api.get('/org/members'), [])
  const { data: inv, reload: reloadInv } = useApi(() => api.get('/org/invitations'), [])
  const { data: org } = useApi(() => api.get('/org'), [])
  const { data: roles } = useApi(() => api.get('/org/roles'), [])
  const [email, setEmail] = useState(''), [role, setRole] = useState('analyst'), [msg, setMsg] = useState(''), [link, setLink] = useState<any>(null)

  async function patch(id: string, body: any) { setMsg(''); try { await api.patch(`/org/members/${id}`, body); reload() } catch (e: any) { setMsg(errText(e)) } }
  async function invite(e: FormEvent) {
    e.preventDefault(); setMsg(''); setLink(null)
    try { const r = await api.post('/org/invitations', { email, role }); setEmail(''); setLink(r.delivery); reloadInv() } catch (x: any) { setMsg(errText(x)) }
  }
  const individual = org?.kind === 'individual'
  return (
    <>
      <PageHeader title="Team and roles" subtitle="Members of your workspace. Permissions are enforced on the server for every request." />
      {msg && <div role="alert" className="mb-3 text-bad">{msg}</div>}
      <ErrorBox error={error} onRetry={reload} />
      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Members" className="lg:col-span-2 !p-0">
          {!m ? <Loading /> : <div className="overflow-x-auto"><table className="w-full"><thead><tr><th className="th">Member</th><th className="th">Role</th><th className="th">Status</th><th className="th">Last login</th><th className="th" /></tr></thead>
            <tbody>{m.items.map((u: any) => (<tr key={u.id}><td className="td">{u.full_name || u.email}<div className="text-xs text-muted">{u.email}{u.username ? ` · @${u.username}` : ''}</div></td>
              <td className="td w-40">{u.role === 'super_admin' ? <span className="text-muted">platform admin</span> : <Select value={u.role} onChange={(v) => patch(u.id, { role: v })} options={roles?.assignable || ['org_admin', 'analyst', 'engineer', 'viewer']} />}</td>
              <td className="td"><StatusBadge value={u.is_active ? 'active' : 'revoked'} /></td><td className="td text-muted">{fmtTime(u.last_login_at)}</td>
              <td className="td text-right">{u.id !== user?.id && u.role !== 'super_admin' && <Button onClick={() => patch(u.id, { is_active: !u.is_active })}>{u.is_active ? 'Revoke access' : 'Restore'}</Button>}</td></tr>))}</tbody></table></div>}
        </Card>
        <Card title="Invite a member">
          {individual ? <p className="text-muted">Individual workspaces cannot have additional members. Register an Organization account for team features.</p> : (
            <form onSubmit={invite}>
              <Field label="Email"><input className="field" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
              <Field label="Role" hint={ROLE_HELP[role]}><Select value={role} onChange={setRole} options={roles?.assignable || ['org_admin', 'analyst', 'engineer', 'viewer']} /></Field>
              <Button variant="primary">Send invitation</Button>
            </form>)}
          {link && <div className={`mt-3 rounded-md border p-2 text-xs ${link.delivered ? 'border-ok/40 text-ok' : 'border-warn/40 text-warn'}`}>
            {link.delivered ? 'Invitation emailed.' : 'Email NOT sent (console mail mode). Share this link manually:'}
            {link.invite_link && <div className="mt-1"><Mono>{link.invite_link}</Mono></div>}</div>}
        </Card>
      </div>
      <Card title="Pending invitations" className="mt-4 !p-0">
        {!inv || inv.items.length === 0 ? <Empty title="No pending invitations" /> : (
          <table className="w-full"><thead><tr><th className="th">Email</th><th className="th">Role</th><th className="th">Expires</th><th className="th" /></tr></thead>
            <tbody>{inv.items.map((i: any) => (<tr key={i.id}><td className="td">{i.email}</td><td className="td">{i.role}</td><td className="td text-muted">{fmtTime(i.expires_at)}</td>
              <td className="td text-right"><Button variant="danger" onClick={async () => { await api.del(`/org/invitations/${i.id}`); reloadInv() }}>Revoke</Button></td></tr>))}</tbody></table>)}
      </Card>
      <Card title="Role reference (read-only)" className="mt-4">
        <div className="grid gap-3 md:grid-cols-2">{Object.entries(ROLE_HELP).map(([r, d]) => (
          <div key={r} className="rounded-md border border-line p-3"><div className="font-medium">{r.replace('_', ' ')}</div><div className="text-muted">{d}</div>
            <div className="mt-2 text-[11px] leading-relaxed text-muted">{(roles?.permissions?.[r] || []).join(' · ')}</div></div>))}</div>
      </Card>
    </>
  )
}
