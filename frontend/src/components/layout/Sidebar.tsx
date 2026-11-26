import React from 'react'
import { NavLink } from 'react-router-dom'
import * as Icons from 'lucide-react'
import { MAIN_NAVIGATION } from '../../constants/navigation'

export const Sidebar: React.FC<{ mobileOpen: boolean; onClose: () => void }> = ({ mobileOpen, onClose }) => {
  return (
    <aside
      className={`fixed inset-y-0 left-0 z-40 w-64 bg-[#090f1d] border-r border-slate-800/80 transform transition-transform lg:translate-x-0 lg:static lg:inset-auto ${
        mobileOpen ? 'translate-x-0' : '-translate-x-full'
      }`}
    >
      <div className="flex items-center gap-3 px-5 py-5 border-b border-slate-800/80">
        <div className="w-9 h-9 rounded-lg bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center">
          <Icons.ShieldCheck className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <div className="font-bold text-slate-100 tracking-tight">WEB GUARD AI</div>
          <div className="text-[11px] text-cyan-400/90 font-medium">Evidence-First AppSec</div>
        </div>
      </div>

      <nav className="p-3 space-y-1 overflow-y-auto h-[calc(100vh-80px)]">
        {MAIN_NAVIGATION.map((item) => {
          const IconComponent = (Icons as unknown as Record<string, React.ComponentType<{ className?: string }>>)[
            item.icon
          ] || Icons.Shield
          return (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              onClick={onClose}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
                }`
              }
            >
              <IconComponent className="w-4 h-4 shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          )
        })}
      </nav>
    </aside>
  )
}
