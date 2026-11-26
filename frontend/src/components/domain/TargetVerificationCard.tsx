import React, { useState } from 'react'
import { CheckCircle2, Play, ShieldAlert } from 'lucide-react'
import type { AuthorizedTarget } from '../../types'
import { Badge } from '../common/UIPrimitives'

export const TargetVerificationCard: React.FC<{
  target: AuthorizedTarget
  onVerify: (targetId: string, method: string, statement?: string) => Promise<void>
  onScan: (targetId: string) => Promise<void>
}> = ({ target, onVerify, onScan }) => {
  const [method, setMethod] = useState<'dns_txt' | 'http_well_known' | 'explicit_authorization'>('dns_txt')
  const [statement, setStatement] = useState('')
  const [busy, setBusy] = useState(false)

  const latestChallenge = target.verifications[target.verifications.length - 1]

  const handleVerify = async () => {
    setBusy(true)
    try {
      await onVerify(target.id, method, statement || undefined)
    } finally {
      setBusy(false)
    }
  }

  const handleScan = async () => {
    setBusy(true)
    try {
      await onScan(target.id)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="border border-slate-800 rounded-xl p-4 bg-[#111a2e]/60 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="font-semibold text-slate-100">{target.normalized_url}</div>
          <div className="text-xs text-slate-400">Domain: {target.domain}</div>
        </div>
        {target.is_authorized ? (
          <Badge
            label={`Authorized (${target.authorization_method || 'verified'})`}
            className="bg-emerald-500/15 text-emerald-300 border-emerald-500/40"
          />
        ) : (
          <Badge label="Verification Required" className="bg-amber-500/15 text-amber-300 border-amber-500/40" />
        )}
      </div>

      {!target.is_authorized && latestChallenge && (
        <div className="text-xs bg-[#060a13] border border-slate-800 rounded-lg p-3 space-y-2">
          <div className="flex items-center gap-1.5 text-amber-300 font-medium">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Ownership Verification Challenge</span>
          </div>
          <div className="text-slate-300 font-mono break-all">Token: {latestChallenge.challenge_token}</div>
          <div className="text-slate-400">
            DNS TXT: <code>_webguard-verify.{target.domain}</code> | HTTP: <code>{target.normalized_url}/.well-known/webguard-verify.txt</code>
          </div>
          <div className="flex flex-wrap gap-2 pt-1">
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value as typeof method)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100"
            >
              <option value="dns_txt">Verify via DNS TXT</option>
              <option value="http_well_known">Verify via HTTP .well-known</option>
              <option value="explicit_authorization">Explicit Signed Authorization</option>
            </select>
            {method === 'explicit_authorization' && (
              <input
                type="text"
                value={statement}
                onChange={(e) => setStatement(e.target.value)}
                placeholder="Authorized owner statement & scope approval..."
                className="flex-1 min-w-[240px] bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100"
              />
            )}
            <button
              disabled={busy}
              onClick={handleVerify}
              className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium disabled:opacity-50"
            >
              {busy ? 'Checking...' : 'Verify Ownership'}
            </button>
          </div>
        </div>
      )}

      {target.is_authorized && (
        <div className="flex items-center justify-between pt-1">
          <span className="text-xs text-emerald-300 flex items-center gap-1.5">
            <CheckCircle2 className="w-4 h-4" /> Non-destructive OWASP & TLS/DNS assessment permitted
          </span>
          <button
            disabled={busy}
            onClick={handleScan}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5" />
            {busy ? 'Scanning...' : 'Run Authorized Scan'}
          </button>
        </div>
      )}
    </div>
  )
}
