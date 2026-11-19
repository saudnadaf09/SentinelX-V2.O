import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './auth/AuthContext'
import Layout from './components/Layout'
import { Loading } from './components/ui'
import Login from './pages/Login'
import Register from './pages/Register'
import { AcceptInvite, ForgotPassword, ResetPassword, VerifyEmail } from './pages/AccountLinks'
import Overview from './pages/Overview'
import LiveEvents from './pages/LiveEvents'
import ThreatDetection from './pages/ThreatDetection'
import Alerts from './pages/Alerts'
import AlertDetail from './pages/AlertDetail'
import Incidents from './pages/Incidents'
import IncidentDetail from './pages/IncidentDetail'
import ThreatHunting from './pages/ThreatHunting'
import Assets from './pages/Assets'
import Mitre from './pages/Mitre'
import AIInvestigator from './pages/AIInvestigator'
import ResponseCenter from './pages/ResponseCenter'
import AuditLogs from './pages/AuditLogs'
import Reports from './pages/Reports'
import Settings from './pages/Settings'
import Profile from './pages/Profile'
import Team from './pages/Team'
import Organization from './pages/Organization'
import AISettings from './pages/AISettings'
import Platform from './pages/Platform'

export default function App() {
  const { user, loading } = useAuth()
  if (loading) return <Loading text="Restoring session..." />
  if (!user) {
    return (
      <Routes>
        <Route path="/register" element={<Register />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/verify-email" element={<VerifyEmail />} />
        <Route path="/accept-invite" element={<AcceptInvite />} />
        <Route path="*" element={<Login />} />
      </Routes>
    )
  }
  return (
    <Routes>
      <Route path="/verify-email" element={<VerifyEmail />} />
      <Route element={<Layout />}>
        <Route path="/" element={<Overview />} />
        <Route path="/events" element={<LiveEvents />} />
        <Route path="/detection" element={<ThreatDetection />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/alerts/:id" element={<AlertDetail />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/incidents/:id" element={<IncidentDetail />} />
        <Route path="/hunt" element={<ThreatHunting />} />
        <Route path="/assets" element={<Assets />} />
        <Route path="/mitre" element={<Mitre />} />
        <Route path="/ai" element={<AIInvestigator />} />
        <Route path="/ai-settings" element={<AISettings />} />
        <Route path="/response" element={<ResponseCenter />} />
        <Route path="/audit" element={<AuditLogs />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/team" element={<Team />} />
        <Route path="/organization" element={<Organization />} />
        <Route path="/platform" element={<Platform />} />
        <Route path="/profile" element={<Profile />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
