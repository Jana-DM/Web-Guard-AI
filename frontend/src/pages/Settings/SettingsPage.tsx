import React, { useEffect, useState } from 'react'
import { Card, ErrorBanner, LoadingState } from '../../components/common/UIPrimitives'
import { intelligenceApi } from '../../services/intelligence/intelligenceApi'

export const SettingsPage: React.FC = () => {
  const [settings, setSettings] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [savedMsg, setSavedMsg] = useState<string | null>(null)

  useEffect(() => {
    intelligenceApi
      .getSettings()
      .then(setSettings)
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load settings'))
      .finally(() => setLoading(false))
  }, [])

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!settings) return
    setError(null)
    setSavedMsg(null)
    try {
      await intelligenceApi.updateSettings({
        scan_http_timeout_seconds: Number(settings.scan_http_timeout_seconds),
        scan_max_redirects: Number(settings.scan_max_redirects),
        scan_max_endpoints: Number(settings.scan_max_endpoints),
        intelligence_sync_hour_utc: Number(settings.intelligence_sync_hour_utc),
      })
      setSavedMsg('Platform scanner & intelligence schedule settings updated.')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Settings update failed (Admin role required)')
    }
  }

  if (loading) return <LoadingState />

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onClose={() => setError(null)} />}
      {savedMsg && (
        <div className="bg-emerald-950/50 border border-emerald-500/40 text-emerald-200 px-4 py-3 rounded-lg text-sm">
          {savedMsg}
        </div>
      )}

      {settings && (
        <Card title="Scanner Safety & Sync Configuration" subtitle="SSRF protection and non-destructive policies remain permanently enforced.">
          <form onSubmit={handleSave} className="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-2xl">
            <div>
              <label className="block text-xs text-slate-400 mb-1">HTTP Timeout (seconds)</label>
              <input
                type="number"
                step="0.5"
                value={Number(settings.scan_http_timeout_seconds ?? 8)}
                onChange={(e) => setSettings({ ...settings, scan_http_timeout_seconds: e.target.value })}
                className="w-full bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Max Redirect Hops</label>
              <input
                type="number"
                value={Number(settings.scan_max_redirects ?? 3)}
                onChange={(e) => setSettings({ ...settings, scan_max_redirects: e.target.value })}
                className="w-full bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Max Endpoints Per Scan</label>
              <input
                type="number"
                value={Number(settings.scan_max_endpoints ?? 40)}
                onChange={(e) => setSettings({ ...settings, scan_max_endpoints: e.target.value })}
                className="w-full bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Daily Sync Hour (UTC)</label>
              <input
                type="number"
                min={0}
                max={23}
                value={Number(settings.intelligence_sync_hour_utc ?? 2)}
                onChange={(e) => setSettings({ ...settings, intelligence_sync_hour_utc: e.target.value })}
                className="w-full bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
              />
            </div>
            <div className="md:col-span-2">
              <button type="submit" className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold">
                Save Configuration
              </button>
            </div>
          </form>
        </Card>
      )}
    </div>
  )
}
