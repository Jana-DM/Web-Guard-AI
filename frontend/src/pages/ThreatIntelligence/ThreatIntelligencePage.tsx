import React, { useEffect, useState } from 'react'
import { Card, ErrorBanner, LoadingState } from '../../components/common/UIPrimitives'
import { SyncStatusPanel } from '../../components/intelligence/SyncStatusPanel'
import { intelligenceApi } from '../../services/intelligence/intelligenceApi'
import type { SyncLog } from '../../types'

export const ThreatIntelligencePage: React.FC = () => {
  const [overview, setOverview] = useState<{
    total_cves: number
    kev_count: number
    advisories_count: number
    last_successful_sync: string | null
    recent_sync_logs: SyncLog[]
    recent_advisories: Array<Record<string, unknown>>
  } | null>(null)
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      setOverview(await intelligenceApi.getOverview())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load intelligence')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const handleSync = async () => {
    setSyncing(true)
    setError(null)
    try {
      await intelligenceApi.triggerSync()
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Intelligence sync failed')
    } finally {
      setSyncing(false)
    }
  }

  if (loading) return <LoadingState />

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onClose={() => setError(null)} />}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card title="Stored CVEs"><div className="text-3xl font-bold text-cyan-400">{overview?.total_cves ?? 0}</div></Card>
        <Card title="CISA KEV Catalog"><div className="text-3xl font-bold text-red-400">{overview?.kev_count ?? 0}</div></Card>
        <Card title="Vendor & OWASP Advisories"><div className="text-3xl font-bold text-emerald-400">{overview?.advisories_count ?? 0}</div></Card>
      </div>

      {overview && (
        <SyncStatusPanel
          lastSync={overview.last_successful_sync}
          logs={overview.recent_sync_logs}
          onTriggerSync={handleSync}
          syncing={syncing}
        />
      )}

      <Card title="Recent Security Advisories" subtitle="Collected from GitHub, OSV Vendor Feeds & OWASP">
        <div className="space-y-3">
          {overview?.recent_advisories.length ? (
            overview.recent_advisories.map((adv) => (
              <div key={String(adv.id)} className="border border-slate-800 rounded-lg p-3 bg-[#060a13]/70">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-cyan-300">{String(adv.advisory_id)} ({String(adv.source).toUpperCase()})</span>
                  <span className="uppercase text-amber-300">{String(adv.severity)}</span>
                </div>
                <div className="text-sm font-medium text-slate-100 mt-1">{String(adv.title)}</div>
                <p className="text-xs text-slate-400 mt-1">{String(adv.summary)}</p>
              </div>
            ))
          ) : (
            <div className="text-sm text-slate-500 py-4">No advisories ingested yet. Trigger synchronization above.</div>
          )}
        </div>
      </Card>
    </div>
  )
}
