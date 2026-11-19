import { FormEvent, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../services/api'
import { useApi } from '../services/hooks'
import { AuthShell } from './Login'

export default function Register() {
  const { data: cfg } = useApi(() => api.get('/auth/config'), [])
  const [type, setType] = useState<'individual' | 'organization'>('individual')
  const [f, setF] = useState<any>({ full_name: '', email: '', username: '', password: '', confirm_password: '', organization_name: '', organization_email: '', organization_details: '' })
  const [errs, setErrs] = useState<Record<string, string>>({}), [top, setTop] = useState(''), [busy, setBusy] = useState(false), [done, setDone] = useState<any>(null)
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value })

  async function submit(e: FormEvent) {
    e.preventDefault(); setTop(''); setErrs({})
    if (f.password !== f.confirm_password) { setErrs({ confirm_password: 'Passwords do not match' }); return }
    setBusy(true)
    try {
      const body: any = { full_name: f.full_name, email: f.email, username: f.username, password: f.password, confirm_password: f.confirm_password, account_type: type }
      if (type === 'organization') Object.assign(body, { organization_name: f.organization_name, organization_email: f.organization_email, organization_details: f.organization_details })
      setDone(await api.post('/auth/register', body))
    } catch (err: any) {
      if (err.details?.length) setErrs(Object.fromEntries(err.details.map((d: any) => [d.field, d.message])))
      setTop(err.message || 'Registration failed')
    } finally { setBusy(false) }
  }
  const input = (k: string, label: string, props: any = {}) => (
    <label className="mb-3 block"><span className="mb-1 block text-xs text-muted">{label}</span>
      <input className="field" value={f[k]} onChange={set(k)} {...props} />
      {errs[k] && <span role="alert" className="mt-1 block text-xs text-bad">{errs[k]}</span>}</label>
  )

  if (done) return (
    <AuthShell title="Account created">
      <div className="rounded-lg border border-line bg-panel p-6">
        <p>Your {done.user.organization?.kind === 'organization' ? 'organization workspace' : 'personal workspace'} <b>{done.user.organization?.name}</b> was created. You are its owner.</p>
        <p className={`mt-3 rounded-md border px-3 py-2 text-sm ${done.verification.delivered ? 'border-ok/40 text-ok' : 'border-warn/40 text-warn'}`}>{done.verification.message}</p>
        <p className="mt-3 text-sm text-muted">Your email is <b>not verified</b> until you open the link in that email.</p>
        <Link to="/" className="mt-4 inline-block rounded-md bg-accent px-4 py-2 font-medium text-ink hover:no-underline">Go to sign in</Link>
      </div>
    </AuthShell>
  )
  return (
    <AuthShell title="Create your account" subtitle="Start a personal workspace or register your organization.">
      {cfg && !cfg.registration_enabled && <div role="alert" className="mb-4 rounded-md border border-bad/40 bg-bad/10 px-3 py-2 text-bad">Registration is disabled on this server.</div>}
      {cfg?.mail_notice && <div className="mb-4 rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-xs text-warn">{cfg.mail_notice}</div>}
      <form onSubmit={submit} className="rounded-lg border border-line bg-panel p-6">
        {top && <div role="alert" className="mb-4 rounded-md border border-bad/40 bg-bad/10 px-3 py-2 text-bad">{top}</div>}
        <div className="mb-4 grid grid-cols-2 gap-2" role="radiogroup" aria-label="Account type">
          {(['individual', 'organization'] as const).map((t) => (
            <button key={t} type="button" role="radio" aria-checked={type === t} onClick={() => setType(t)}
              className={`rounded-md border px-3 py-2 text-left ${type === t ? 'border-accent bg-accentdim/40' : 'border-line hover:border-accent'}`}>
              <div className="font-medium capitalize">{t}</div><div className="text-xs text-muted">{t === 'individual' ? 'Personal workspace' : 'Team workspace with members'}</div></button>))}
        </div>
        {input('full_name', 'Full name', { required: true, autoComplete: 'name' })}
        {input('email', 'Email address', { type: 'email', required: true, autoComplete: 'email' })}
        {input('username', 'Username', { required: true, autoComplete: 'username', placeholder: '3-32 letters, digits, . _ -' })}
        {input('password', 'Password (12+ characters, mix of types)', { type: 'password', required: true, autoComplete: 'new-password' })}
        {input('confirm_password', 'Confirm password', { type: 'password', required: true, autoComplete: 'new-password' })}
        {type === 'organization' && <>
          <div className="my-4 border-t border-line pt-4 text-xs uppercase tracking-wider text-muted">Organization</div>
          {input('organization_name', 'Organization name', { required: true })}
          {input('organization_email', 'Organization email', { type: 'email', required: true })}
          <label className="mb-3 block"><span className="mb-1 block text-xs text-muted">Organization details</span>
            <textarea className="field" rows={3} required minLength={10} value={f.organization_details} onChange={set('organization_details')} placeholder="What the organization does, team size, environments to monitor" />
            {errs.organization_details && <span role="alert" className="mt-1 block text-xs text-bad">{errs.organization_details}</span>}</label>
        </>}
        <button disabled={busy || (cfg && !cfg.registration_enabled)} className="mt-2 w-full rounded-md bg-accent py-2.5 font-medium text-ink hover:brightness-110 disabled:opacity-60">{busy ? 'Creating account...' : 'Create account'}</button>
      </form>
      <p className="mt-4 text-sm text-muted">Already registered? <Link to="/">Sign in</Link></p>
    </AuthShell>
  )
}
