import { Link, NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'

type Item = { to: string; label: string; perm?: string }
const groups: { title: string; items: Item[] }[] = [
  { title: 'Monitor', items: [
    { to: '/', label: 'Overview', perm: 'dashboard:read' },
    { to: '/events', label: 'Live Events', perm: 'events:read' },
    { to: '/alerts', label: 'Alerts', perm: 'alerts:read' },
    { to: '/incidents', label: 'Incidents', perm: 'incidents:read' },
  ] },
  { title: 'Investigate', items: [
    { to: '/hunt', label: 'Threat Hunting', perm: 'hunt:run' },
    { to: '/ai', label: 'AI Investigator', perm: 'alerts:read' },
    { to: '/response', label: 'Response Center', perm: 'response:read' },
  ] },
  { title: 'Detect', items: [
    { to: '/detection', label: 'Threat Detection', perm: 'rules:read' },
    { to: '/mitre', label: 'MITRE ATT&CK', perm: 'mitre:read' },
    { to: '/assets', label: 'Endpoints', perm: 'assets:read' },
  ] },
  { title: 'Govern', items: [
    { to: '/reports', label: 'Reports', perm: 'reports:read' },
    { to: '/audit', label: 'Audit Logs', perm: 'audit:read' },
  ] },
  { title: 'Workspace', items: [
    { to: '/team', label: 'Team and Roles', perm: 'users:manage' },
    { to: '/organization', label: 'Organization' },
    { to: '/ai-settings', label: 'AI Provider', perm: 'ai:configure' },
    { to: '/platform', label: 'Platform Admin', perm: 'platform:manage' },
    { to: '/profile', label: 'My Profile' },
    { to: '/settings', label: 'Settings' },
  ] },
]

export default function Layout() {
  const { user, logout, can } = useAuth()
  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-line bg-panel" aria-label="Primary">
        <div className="px-4 py-4">
          <div className="text-lg font-semibold tracking-tight">SentinelX</div>
          <div className="text-xs text-muted">SIEM + XDR-lite</div>
        </div>
        <nav className="flex-1 overflow-y-auto px-2 pb-4">
          {groups.map((g) => {
            const items = g.items.filter((i) => !i.perm || can(i.perm))
            if (!items.length) return null
            return (
              <div key={g.title} className="mb-3">
                <div className="px-2 pb-1 text-xs text-muted">{g.title}</div>
                {items.map((i) => (
                  <NavLink key={i.to} to={i.to} end={i.to === '/'}
                    className={({ isActive }) => `block rounded-md px-3 py-1.5 hover:no-underline ${isActive ? 'bg-accentdim text-fg' : 'text-fg/80 hover:bg-raised'}`}>
                    {i.label}
                  </NavLink>
                ))}
              </div>
            )
          })}
        </nav>
        <div className="border-t border-line p-3 text-xs">
          <div className="truncate font-medium" title={user?.organization?.name}>{user?.organization?.name}</div>
          <div className="truncate" title={user?.email}>{user?.email}</div>
          <div className="mb-2 text-muted">{user?.role.replace('_', ' ')} · {user?.organization?.kind}</div>
          <button onClick={logout} className="rounded-md border border-line px-2 py-1 hover:border-accent">Sign out</button>
          <div className="mt-3 text-[10px] leading-snug text-muted">&copy; 2026 Saud Nadaf. All rights reserved.</div>
        </div>
      </aside>
      <main className="min-w-0 flex-1 overflow-y-auto p-6">
        {user && !user.email_verified && (
          <div role="status" className="mb-4 rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-warn">
            Your email address is not verified yet. <Link to="/profile">Open your profile</Link> to resend the verification link.
          </div>)}
        <Outlet />
      </main>
    </div>
  )
}
