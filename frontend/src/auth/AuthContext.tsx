import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { api, hasSession, login as apiLogin, logout as apiLogout, onSessionEnd } from '../services/api'

type User = { id: string; email: string; username?: string; full_name: string; role: string; email_verified: boolean; permissions: string[]; organization?: { id: string; name: string; kind: string } }
type Ctx = {
  user: User | null; loading: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
  can: (permission: string) => boolean
  refresh: () => Promise<void>
}
const AuthCtx = createContext<Ctx>(null as any)
export const useAuth = () => useContext(AuthCtx)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(hasSession())

  useEffect(() => {
    onSessionEnd(() => setUser(null))
    if (hasSession()) {
      api.get('/auth/me').then(setUser).catch(() => setUser(null)).finally(() => setLoading(false))
    }
  }, [])

  const value: Ctx = {
    user, loading,
    login: async (email, password) => { setUser(await apiLogin(email, password)) },
    logout: async () => { await apiLogout(); setUser(null) },
    can: (p) => !!user?.permissions.includes(p),
    refresh: async () => { setUser(await api.get('/auth/me')) },
  }
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>
}
