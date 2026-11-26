import React, { useState } from 'react'
import { Lock, ShieldCheck } from 'lucide-react'
import { useAuth } from '../../contexts/AuthContext'
import { ErrorBanner } from '../../components/common/UIPrimitives'

export const AuthPage: React.FC = () => {
  const { login, register } = useAuth()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [username, setUsername] = useState('')
  const [fullName, setFullName] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      if (mode === 'login') {
        await login(username || email, password)
      } else {
        await register(email, username, password, fullName || undefined)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#060a13] flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-[#0c1322] border border-slate-800 rounded-2xl p-8 shadow-2xl space-y-6">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center">
            <ShieldCheck className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100">Web Guard AI</h1>
            <p className="text-xs text-slate-400">Continuous Cybersecurity Intelligence Platform</p>
          </div>
        </div>

        <div className="flex rounded-lg bg-[#060a13] p-1 border border-slate-800">
          <button
            type="button"
            onClick={() => setMode('login')}
            className={`flex-1 py-2 text-xs font-semibold rounded-md ${
              mode === 'login' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => setMode('register')}
            className={`flex-1 py-2 text-xs font-semibold rounded-md ${
              mode === 'register' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            Create Account
          </button>
        </div>

        {error && <ErrorBanner message={error} onClose={() => setError(null)} />}

        <form onSubmit={handleSubmit} className="space-y-4">
          {mode === 'register' && (
            <>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Work Email</label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
                  placeholder="analyst@company.com"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Full Name</label>
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  className="w-full bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
                  placeholder="Security Engineer"
                />
              </div>
            </>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              {mode === 'login' ? 'Username or Email' : 'Username'}
            </label>
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
              placeholder="sec_analyst"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Password</label>
            <input
              type="password"
              required
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
              placeholder="Minimum 8 characters"
            />
          </div>

          <button
            type="submit"
            disabled={busy}
            className="w-full inline-flex items-center justify-center gap-2 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold disabled:opacity-50"
          >
            <Lock className="w-4 h-4" />
            {busy ? 'Authenticating...' : mode === 'login' ? 'Access Security Console' : 'Register & Sign In'}
          </button>
        </form>
      </div>
    </div>
  )
}
