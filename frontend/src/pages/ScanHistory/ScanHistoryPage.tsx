import React, { useEffect, useState } from 'react'
import { Card, ErrorBanner, LoadingState } from '../../components/common/UIPrimitives'
import { scannerApi } from '../../services/scanner/scannerApi'
import type { ScanJob } from '../../types'
import { formatDate } from '../../utils/formatters'

export const ScanHistoryPage: React.FC = () => {
  const [scans, setScans] = useState<ScanJob[]>([])
  const [detail, setDetail] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    scannerApi
      .listScans()
      .then(setScans)
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load scan history'))
      .finally(() => setLoading(false))
  }, [])

  const inspect = async (scanId: string) => {
    try {
      setDetail(await scannerApi.getScanDetail(scanId))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load scan detail')
    }
  }

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onClose={() => setError(null)} />}

      <Card title="Scan Execution History">
        {loading ? (
          <LoadingState />
        ) : scans.length === 0 ? (
          <div className="text-sm text-slate-500 py-6">No scans have been executed yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2 pr-4">Target</th>
                  <th className="py-2 pr-4">Type</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Progress</th>
                  <th className="py-2 pr-4">Created</th>
                  <th className="py-2">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {scans.map((s) => (
                  <tr key={s.id} className="text-slate-300">
                    <td className="py-2.5 pr-4 font-medium">{s.target_label}</td>
                    <td className="py-2.5 pr-4 uppercase text-cyan-400">{s.scan_type}</td>
                    <td className="py-2.5 pr-4">{s.status}</td>
                    <td className="py-2.5 pr-4">{s.progress}%</td>
                    <td className="py-2.5 pr-4 text-slate-400">{formatDate(s.created_at)}</td>
                    <td className="py-2.5">
                      <button
                        onClick={() => inspect(s.id)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-700 text-slate-200"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {detail && (
        <Card title="Scan Telemetry Details">
          <pre className="bg-[#060a13] border border-slate-800 rounded-lg p-4 text-xs text-slate-200 overflow-x-auto max-h-96">
            {JSON.stringify(detail, null, 2)}
          </pre>
        </Card>
      )}
    </div>
  )
}
