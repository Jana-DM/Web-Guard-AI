import React, { useEffect, useState } from 'react'
import { Card, ErrorBanner, LoadingState } from '../../components/common/UIPrimitives'
import { scannerApi } from '../../services/scanner/scannerApi'

export const AttackSurfacePage: React.FC = () => {
  const [overview, setOverview] = useState<{ targets: Array<Record<string, unknown>>; technologies: Array<Record<string, unknown>> } | null>(null)
  const [selectedSurface, setSelectedSurface] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    scannerApi
      .getAttackSurfaceOverview()
      .then(setOverview)
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load attack surface'))
      .finally(() => setLoading(false))
  }, [])

  const inspectTarget = async (id: string) => {
    try {
      setSelectedSurface(await scannerApi.getTargetAttackSurface(id))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load target surface')
    }
  }

  if (loading) return <LoadingState />

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onClose={() => setError(null)} />}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Monitored Domains & Scope" subtitle="Click a target to inspect endpoints, DNS, TLS, and CVE correlations">
          <div className="space-y-2">
            {overview?.targets.length ? (
              overview.targets.map((t) => (
                <button
                  key={String(t.id)}
                  onClick={() => inspectTarget(String(t.id))}
                  className="w-full text-left border border-slate-800 hover:border-cyan-500/50 rounded-lg p-3 bg-[#060a13]/70 flex items-center justify-between"
                >
                  <div>
                    <div className="text-sm font-medium text-slate-100">{String(t.domain)}</div>
                    <div className="text-xs text-slate-400">{String(t.normalized_url)}</div>
                  </div>
                  <span className={`text-xs ${t.is_authorized ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {t.is_authorized ? 'Authorized' : 'Pending'}
                  </span>
                </button>
              ))
            ) : (
              <div className="text-sm text-slate-500">No targets registered yet.</div>
            )}
          </div>
        </Card>

        <Card title="Fingerprinted Stack & Dependencies" subtitle="Detected across domain and code scans">
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {overview?.technologies.length ? (
              overview.technologies.map((tech) => (
                <div key={String(tech.id)} className="border border-slate-800 rounded-lg p-2.5 bg-[#060a13]/70 flex items-center justify-between text-xs">
                  <div>
                    <span className="font-semibold text-cyan-300">{String(tech.product_name)}</span>{' '}
                    <span className="text-slate-400">{tech.version ? `v${String(tech.version)}` : '(version unverified)'}</span>
                  </div>
                  <span className="text-slate-400">{String(tech.detection_source)}</span>
                </div>
              ))
            ) : (
              <div className="text-sm text-slate-500">No technologies fingerprinted yet.</div>
            )}
          </div>
        </Card>
      </div>

      {selectedSurface && (
        <Card title="Target Attack Surface & CVE Correlation">
          <pre className="bg-[#060a13] border border-slate-800 rounded-lg p-4 text-xs text-slate-200 overflow-x-auto max-h-96">
            {JSON.stringify(selectedSurface, null, 2)}
          </pre>
        </Card>
      )}
    </div>
  )
}
