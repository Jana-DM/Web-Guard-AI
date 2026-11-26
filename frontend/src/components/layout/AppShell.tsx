import React, { useState } from 'react'
import { LogOut, Menu, ShieldCheck } from 'lucide-react'
import { useAuth } from '../../contexts/AuthContext'
import { Sidebar } from './Sidebar'

export const AppShell: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => {
  const { user, logout } = useAuth()
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div className="min-h-screen flex bg-[#060a13] text-slate-100">
      <Sidebar mobileOpen={mobileOpen} onClose={() => setMobileOpen(false)} />

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-16 border-b border-slate-800/80 bg-[#090f1d]/80 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-30">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileOpen((v) => !v)}
              className="lg:hidden p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
              aria-label="Toggle Navigation"
            >
              <Menu className="w-5 h-5" />
            </button>
            <h1 className="text-lg font-semibold text-slate-100 truncate">{title}</h1>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden sm:flex items-center gap-2 text-xs px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-300">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Evidence Validation Active</span>
            </div>
            {user && (
              <div className="flex items-center gap-3">
                <div className="text-right hidden sm:block">
                  <div className="text-xs font-medium text-slate-200">{user.username}</div>
                  <div className="text-[11px] text-slate-400 uppercase">{user.role}</div>
                </div>
                <button
                  onClick={logout}
                  className="p-2 rounded-lg text-slate-400 hover:text-red-300 hover:bg-slate-800/80 transition-colors"
                  title="Sign Out"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            )}
          </div>
        </header>

        <main className="flex-1 p-6 max-w-[1600px] w-full mx-auto space-y-6">{children}</main>
      </div>
    </div>
  )
}
