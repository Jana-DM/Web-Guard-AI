import React from 'react'
import { Loader2, ShieldAlert, X } from 'lucide-react'

export const Card: React.FC<{
  title?: string
  subtitle?: string
  action?: React.ReactNode
  children: React.ReactNode
  className?: string
}> = ({ title, subtitle, action, children, className = '' }) => (
  <div className={`bg-[#0c1322] border border-slate-800/90 rounded-xl p-5 shadow-lg ${className}`}>
    {(title || action) && (
      <div className="flex items-start justify-between gap-4 mb-4">
        <div>
          {title && <h3 className="text-base font-semibold text-slate-100">{title}</h3>}
          {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
        </div>
        {action}
      </div>
    )}
    {children}
  </div>
)

export const Badge: React.FC<{ label: string; className?: string }> = ({ label, className = '' }) => (
  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${className}`}>
    {label}
  </span>
)

export const LoadingState: React.FC<{ message?: string }> = ({ message = 'Loading security telemetry...' }) => (
  <div className="flex items-center justify-center gap-3 py-12 text-slate-400">
    <Loader2 className="w-5 h-5 animate-spin text-cyan-400" />
    <span className="text-sm">{message}</span>
  </div>
)

export const ErrorBanner: React.FC<{ message: string; onClose?: () => void }> = ({ message, onClose }) => (
  <div className="flex items-center justify-between gap-3 bg-red-950/50 border border-red-500/40 text-red-200 px-4 py-3 rounded-lg text-sm">
    <div className="flex items-center gap-2">
      <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
      <span>{message}</span>
    </div>
    {onClose && (
      <button onClick={onClose} className="text-red-300 hover:text-white">
        <X className="w-4 h-4" />
      </button>
    )}
  </div>
)
