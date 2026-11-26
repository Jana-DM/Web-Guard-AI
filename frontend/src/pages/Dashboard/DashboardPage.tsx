import React, { useEffect, useState } from 'react'
import { Activity, AlertTriangle, CheckCircle2, Database, Globe, ShieldCheck } from 'lucide-react'
import { Card, ErrorBanner, LoadingState } from '../../components/common/UIPrimitives'
import { DashboardCharts } from '../../components/dashboard/DashboardCharts'
import { intelligenceApi } from '../../services/intelligence/intelligenceApi'
import type { DashboardSummary } from '../../types'
import { formatDate } from '../../utils/formatters'

export const DashboardPage: React.FC = () => {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    intelligenceApi
      .getDashboardSummary()
      .then(setSummary)
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load dashboard'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <LoadingState />
  if (error) return <ErrorBanner message={error} />
  if (!summary) return null

  const statCards = [
    { label: 'Confirmed Vulnerabilities', value: summary.metrics.confirmed_vulnerabilities, icon: AlertTriangle, tone: 'text-emerald-400' },
    { label: 'Total Findings Recorded', value: summary.metrics.total_vulnerabilities, icon: ShieldCheck, tone: 'text-cyan-400' },
    { label: 'Verified Targets', value: `${summary.metrics.verified_targets}/${summary.metrics.total_targets}`, icon: Globe, tone: 'text-sky-400' },
    { label: 'Synced CVEs (CISA KEV)', value: `${summary.metrics.total_cves} (${summary.metrics.kev_cves})`, icon: Database, tone: 'text-amber-400' },
    { label: 'Executed Scans', value: summary.metrics.total_scans, icon: Activity, tone: 'text-violet-400' },
    { label: 'Approved Remediations', value: summary.metrics.remediated_count, icon: CheckCircle2, tone: 'text-emerald-400' },
  ]

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {statCards.map((item) => {
          const Icon = item.icon
          return (
            <Card key={item.label} className="p-4">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>{item.label}</span>
                <Icon className={`w-4 h-4 ${item.tone}`} />
              </div>
              <div className="text-2xl font-bold text-slate-100 mt-2">{item.value}</div>
            </Card>
          )
        })}
      </div>

      <DashboardCharts
        severity={summary.severity_distribution}
        classification={summary.classification_distribution}
      />

      <Card
        title="Recent Security Assessments"
        subtitle={`Last intelligence feed sync: ${formatDate(summary.last_intelligence_sync)}`}
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-2 pr-4">Target</th>
                <th className="py-2 pr-4">Type</th>
                <th className="py-2 pr-4">Status</th>
                <th className="py-2 pr-4">Findings</th>
                <th className="py-2">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {summary.recent_scans.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-6 text-center text-slate-500">
                    No scans executed yet. Register an authorized domain or upload source code to begin.
                  </td>
                </tr>
              ) : (
                summary.recent_scans.map((scan) => (
                  <tr key={scan.id} className="text-slate-300">
                    <td className="py-2.5 pr-4 font-medium">{scan.target_label}</td>
                    <td className="py-2.5 pr-4 uppercase text-cyan-400">{scan.scan_type}</td>
                    <td className="py-2.5 pr-4">{scan.status}</td>
                    <td className="py-2.5 pr-4">{String((scan.summary as Record<string, unknown>)?.total_findings ?? 0)}</td>
                    <td className="py-2.5 text-slate-400">{formatDate(scan.created_at)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}
