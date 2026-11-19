import { FormEvent, useState } from 'react'
import { api } from '../services/api'
import { errText, fmtTime, useApi } from '../services/hooks'
import { useAuth } from '../auth/AuthContext'
import { Button, Card, ErrorBox, Field, PageHeader } from '../components/ui'

export default function Profile() {
  const { user, refresh } = useAuth()
  const [name, setName] = useState(user?.full_name || ''), [msg, setMsg] = useState<{ ok: boolean; t: string } | null>(null)
  const [cur, setCur] = useState(''), [next, setNext] = useState(''), [pmsg, setPmsg] = useState<{ ok: boolean; t: string } | null>(null)
  const { data: sess, reload, error } = useApi(() => api.get('/auth/sessions'), [])

  async function saveName(e: FormEvent) { e.preventDefault(); setMsg(null); try { await api.patch('/auth/profile', { full_name: name }); await refresh(); setMsg({ ok: true, t: 'Saved' }) } catch (x: any) { setMsg({ ok: false, t: errText(x) }) } }
  async function pw(e: FormEvent) { e.preventDefault(); setPmsg(null); try { await api.post('/auth/change-password', { current_password: cur, new_password: next }); setCur(''); setNext(''); setPmsg({ ok: true, t: 'Password changed. Other sessions were signed out.' }) } catch (x: any) { setPmsg({ ok: false, t: errText(x) }) } }
  async function resend() { try { const r = await api.post('/auth/resend-verification'); setMsg({ ok: !!r.sent, t: r.sent ? 'Verification email sent.' : 'Not emailed (console mail mode): check the server window for the link.' }) } catch (x: any) { setMsg({ ok: false, t: errText(x) }) } }
  if (!user) return null
  return (
    <>
      <PageHeader title="My profile" subtitle="Your account, workspace membership and active sessions." />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Account">
          <dl className="mb-4 space-y-2">
            <div className="flex justify-between"><dt className="text-muted">Email</dt><dd>{user.email}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Username</dt><dd>{user.username || '-'}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Role</dt><dd>{user.role.replace('_', ' ')}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Workspace</dt><dd>{user.organization?.name} ({user.organization?.kind})</dd></div>
            <div className="flex items-center justify-between"><dt className="text-muted">Email verified</dt><dd className={user.email_verified ? 'text-ok' : 'text-warn'}>{user.email_verified ? 'Yes' : 'No'} {!user.email_verified && <Button className="ml-2" onClick={resend}>Resend link</Button>}</dd></div>
          </dl>
          <form onSubmit={saveName}><Field label="Full name"><input className="field" required minLength={2} value={name} onChange={(e) => setName(e.target.value)} /></Field>
            <Button variant="primary">Save</Button>{msg && <span role="status" className={`ml-3 ${msg.ok ? 'text-ok' : 'text-bad'}`}>{msg.t}</span>}</form>
        </Card>
        <Card title="Change password">
          <form onSubmit={pw}>
            <Field label="Current password"><input className="field" type="password" autoComplete="current-password" required value={cur} onChange={(e) => setCur(e.target.value)} /></Field>
            <Field label="New password (12+ characters, mix of types)"><input className="field" type="password" autoComplete="new-password" required value={next} onChange={(e) => setNext(e.target.value)} /></Field>
            <Button variant="primary">Update password</Button>{pmsg && <span role="status" className={`ml-3 ${pmsg.ok ? 'text-ok' : 'text-bad'}`}>{pmsg.t}</span>}
          </form>
        </Card>
        <Card title="Active sessions" className="lg:col-span-2" actions={<Button variant="danger" onClick={async () => { await api.post('/auth/sessions/revoke-all'); reload() }}>Sign out everywhere</Button>}>
          <ErrorBox error={error} />
          <table className="w-full"><thead><tr><th className="th">Started</th><th className="th">Expires</th><th className="th">IP</th><th className="th">Device</th></tr></thead>
            <tbody>{(sess?.items || []).map((s: any) => (<tr key={s.id}><td className="td">{fmtTime(s.created_at)}</td><td className="td text-muted">{fmtTime(s.expires_at)}</td><td className="td">{s.ip || '-'}</td><td className="td max-w-xs truncate text-xs text-muted" title={s.user_agent}>{s.user_agent || '-'}</td></tr>))}</tbody></table>
        </Card>
      </div>
    </>
  )
}
