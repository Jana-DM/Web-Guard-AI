import React, { useEffect, useState } from 'react'
import { Card, ErrorBanner, LoadingState } from '../../components/common/UIPrimitives'
import { TargetVerificationCard } from '../../components/domain/TargetVerificationCard'
import { scannerApi } from '../../services/scanner/scannerApi'
import type { AuthorizedTarget, ScanJob } from '../../types'

export const DomainScannerPage: React.FC = () => {
  const [domainInput, setDomainInput] = useState('')
  const [scopeNotes, setScopeNotes] = useState('')
  const [targets, setTargets] = useState<AuthorizedTarget[]>([])
  const [lastScan, setLastScan] = useState<ScanJob | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadTargets = async () => {
    try {
      setTargets(await scannerApi.listTargets())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load targets')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadTargets()
  }, [])

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    try {
      await scannerApi.registerTarget(domainInput, scopeNotes || undefined)
      setDomainInput('')
      setScopeNotes('')
      await loadTargets()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Target registration blocked')
    }
  }

  const handleVerify = async (targetId: string, method: string, statement?: string) => {
    setError(null)
    try {
      await scannerApi.verifyTarget(targetId, method, statement)
      await loadTargets()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed')
    }
  }

  const handleScan = async (targetId: string) => {
    setError(null)
    try {
      const job = await scannerApi.startDomainScan(targetId, true)
      setLastScan(job)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Domain scan failed')
    }
  }

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onClose={() => setError(null)} />}

      <Card
        title="Register Authorized Domain Target"
        subtitle="Ownership verification or explicit scope authorization is strictly enforced before active checks. Private IPs and SSRF targets are blocked."
      >
        <form onSubmit={handleRegister} className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input
            type="text"
            required
            value={domainInput}
            onChange={(e) => setDomainInput(e.target.value)}
            placeholder="https://example.com"
            className="bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
          />
          <input
            type="text"
            value={scopeNotes}
            onChange={(e) => setScopeNotes(e.target.value)}
            placeholder="Scope notes (e.g., Production public portal)"
            className="bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
          />
          <button type="submit" className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold">
            Register Domain
          </button>
        </form>
      </Card>

      {lastScan && (
        <Card title="Latest Domain Assessment Result" subtitle={`Target: ${lastScan.target_label}`}>
          <pre className="bg-[#060a13] border border-slate-800 rounded-lg p-3 text-xs text-emerald-300 overflow-x-auto">
            {JSON.stringify(lastScan.summary, null, 2)}
          </pre>
        </Card>
      )}

      <Card title="Target Authorization & Scan Queue">
        {loading ? (
          <LoadingState />
        ) : targets.length === 0 ? (
          <div className="text-sm text-slate-500 py-4">No domain targets registered yet.</div>
        ) : (
          <div className="space-y-4">
            {targets.map((t) => (
              <TargetVerificationCard key={t.id} target={t} onVerify={handleVerify} onScan={handleScan} />
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
