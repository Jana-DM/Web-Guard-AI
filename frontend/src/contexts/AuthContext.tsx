import React, { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { apiRequest, clearStoredTokens, getStoredToken, setStoredTokens } from '../services/api/client'
import type { User } from '../types'

interface AuthContextValue {
  user: User | null
  loading: boolean
  login: (emailOrUsername: string, password: string) => Promise<void>
  register: (email: string, username: string, password: string, fullName?: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchMe = useCallback(async () => {
    if (!getStoredToken()) {
      setLoading(false)
      return
    }
    try {
      const me = await apiRequest<User>('/users/me')
      setUser(me)
    } catch {
      clearStoredTokens()
      setUser(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchMe()
  }, [fetchMe])

  const login = async (email_or_username: string, password: string) => {
    const tokens = await apiRequest<{ access_token: string; refresh_token: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email_or_username, password }),
    })
    setStoredTokens(tokens.access_token, tokens.refresh_token)
    const me = await apiRequest<User>('/users/me')
    setUser(me)
  }

  const register = async (email: string, username: string, password: string, full_name?: string) => {
    await apiRequest<User>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, username, password, full_name }),
    })
    await login(username, password)
  }

  const logout = () => {
    clearStoredTokens()
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
