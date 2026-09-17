import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react'
import { apiPost, apiGet, apiClient } from './api'

export interface AuthUser {
  id: number
  name: string
  mail: string
  role: string
  type: 'guest' | 'user' | 'api'
  privileges: string[]
}

interface AuthState {
  user: AuthUser | null
  loading: boolean
  login: (mail: string, password: string) => Promise<void>
  logout: () => Promise<void>
  isAuthenticated: boolean
}

const guestUser: AuthUser = {
  id: 0, name: '', mail: '', role: '', type: 'guest', privileges: [],
}

const AuthContext = createContext<AuthState>({
  user: null,
  loading: true,
  login: async () => {},
  logout: async () => {},
  isAuthenticated: false,
})

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchUser = useCallback(async () => {
    try {
      const info = await apiGet<any>('/v1/info')
      if (info && info.type !== 'guest') {
        setUser({
          id: info.user?.id || 0,
          name: info.user?.name || '',
          mail: info.user?.mail || '',
          role: info.role?.name || '',
          type: info.type || 'guest',
          privileges: info.privileges || [],
        })
      } else {
        setUser(guestUser)
      }
    } catch {
      setUser(guestUser)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchUser()
  }, [fetchUser])

  const login = useCallback(async (mail: string, password: string) => {
    await apiPost('/v1/auth/login', { mail, password })
    await fetchUser()
  }, [fetchUser])

  const logout = useCallback(async () => {
    try {
      await apiClient.get('/v1/auth/logout')
    } catch { /* ignore */ }
    setUser(guestUser)
  }, [])

  return (
    <AuthContext.Provider value={{
      user,
      loading,
      login,
      logout,
      isAuthenticated: !!user && user.type !== 'guest',
    }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
