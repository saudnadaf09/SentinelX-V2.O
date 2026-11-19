import { FormEvent, useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../services/api'
import { errText } from '../services/hooks'
import { AuthShell } from './Login'

export function ForgotPassword() {
  const [email, setEmail] = useState(''), [sent, setSent] = useState(false), [err, setErr] = useState('')
  async function submit(e: FormEvent) { e.preventDefault(); setErr(''); try { await api.post('/auth/forgot-password', { email }); setSent(true) } catch (x: any) { setErr(errText(x)) } }
  return (
    <AuthShell title="Reset your password" subtitle="We will email a single-use link, valid for 30 minutes.">
      {sent ? <div className="rounded-lg border border-line bg-panel p-6" role="status">If an account exists for that email, a reset link has been sent. If mail is in console mode, the link is printed in the server window instead of being emailed.</div> : (
        <form onSubmit={submit} className="rounded-lg border border-line bg-panel p-6">
          {err && <div role="alert" className="mb-3 text-bad">{err}</div>}
          <label className="mb-4 block"><span className="mb-1 block text-xs text-muted">Email address</span><input className="field" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <button className="w-full rounded-md bg-accent py-2.5 font-medium text-ink">Send reset link</button>
        </form>)}
      <p className="mt-4 text-sm"><Link to="/">Back to sign in</Link></p>
    </AuthShell>
  )
}

export function ResetPassword() {
  const [sp] = useSearchParams(), token = sp.get('token') || ''
  const [pw, setPw] = useState(''), [pw2, setPw2] = useState(''), [err, setErr] = useState(''), [ok, setOk] = useState(false)
  async function submit(e: FormEvent) {
    e.preventDefault(); setErr('')
    if (pw !== pw2) { setErr('Passwords do not match'); return }
    try { await api.post('/auth/reset-password', { token, new_password: pw }); setOk(true) } catch (x: any) { setErr(errText(x)) }
  }
  return (
    <AuthShell title="Choose a new password">
      {ok ? <div className="rounded-lg border border-ok/40 bg-panel p-6 text-ok" role="status">Password changed. All other sessions were signed out. <Link to="/">Sign in</Link></div> : (
        <form onSubmit={submit} className="rounded-lg border border-line bg-panel p-6">
          {!token && <div role="alert" className="mb-3 text-bad">This link has no token. Request a new reset email.</div>}
          {err && <div role="alert" className="mb-3 text-bad">{err}</div>}
          <label className="mb-3 block"><span className="mb-1 block text-xs text-muted">New password (12+ characters)</span><input className="field" type="password" required autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} /></label>
          <label className="mb-4 block"><span className="mb-1 block text-xs text-muted">Confirm new password</span><input className="field" type="password" required autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} /></label>
          <button disabled={!token} className="w-full rounded-md bg-accent py-2.5 font-medium text-ink disabled:opacity-60">Set password</button>
        </form>)}
    </AuthShell>
  )
}

export function VerifyEmail() {
  const [sp] = useSearchParams(), token = sp.get('token') || ''
  const [state, setState] = useState<'working' | 'ok' | 'fail'>('working'), [msg, setMsg] = useState('')
  useEffect(() => {
    if (!token) { setState('fail'); setMsg('This link has no token.'); return }
    api.post('/auth/verify-email', { token }).then(() => setState('ok')).catch((e) => { setState('fail'); setMsg(errText(e)) })
  }, [token])
  return (
    <AuthShell title="Email verification">
      <div className="rounded-lg border border-line bg-panel p-6" role="status">
        {state === 'working' && 'Verifying...'}
        {state === 'ok' && <span className="text-ok">Your email address is now verified.</span>}
        {state === 'fail' && <span className="text-bad">Verification failed: {msg}</span>}
        <div className="mt-4"><Link to="/">Continue</Link></div>
      </div>
    </AuthShell>
  )
}

export function AcceptInvite() {
  const [sp] = useSearchParams(), token = sp.get('token') || ''
  const [f, setF] = useState({ full_name: '', username: '', password: '', confirm_password: '' }), [err, setErr] = useState(''), [ok, setOk] = useState(false)
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value })
  async function submit(e: FormEvent) {
    e.preventDefault(); setErr('')
    if (f.password !== f.confirm_password) { setErr('Passwords do not match'); return }
    try { await api.post('/auth/accept-invite', { token, ...f }); setOk(true) } catch (x: any) { setErr(errText(x)) }
  }
  return (
    <AuthShell title="Join your team" subtitle="Create your account to accept the invitation.">
      {ok ? <div className="rounded-lg border border-ok/40 bg-panel p-6 text-ok" role="status">Account created. <Link to="/">Sign in</Link> with the email address the invitation was sent to.</div> : (
        <form onSubmit={submit} className="rounded-lg border border-line bg-panel p-6">
          {err && <div role="alert" className="mb-3 text-bad">{err}</div>}
          {([['full_name', 'Full name', 'text'], ['username', 'Username', 'text'], ['password', 'Password (12+ characters)', 'password'], ['confirm_password', 'Confirm password', 'password']] as const).map(([k, l, t]) => (
            <label key={k} className="mb-3 block"><span className="mb-1 block text-xs text-muted">{l}</span><input className="field" type={t} required value={(f as any)[k]} onChange={set(k)} /></label>))}
          <button disabled={!token} className="w-full rounded-md bg-accent py-2.5 font-medium text-ink disabled:opacity-60">Create account</button>
        </form>)}
    </AuthShell>
  )
}
