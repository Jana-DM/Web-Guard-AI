import { apiRequest } from '../api/client'
import type { CVERecord, DashboardSummary, SyncLog } from '../../types'

export const intelligenceApi = {
  getDashboardSummary: () => apiRequest<DashboardSummary>('/dashboard/summary'),
  getOverview: () =>
    apiRequest<{
      total_cves: number
      kev_count: number
      advisories_count: number
      last_successful_sync: string | null
      recent_sync_logs: SyncLog[]
      recent_advisories: Array<Record<string, unknown>>
    }>('/intelligence/overview'),
  triggerSync: (sources?: string[], days_back = 7) =>
    apiRequest<SyncLog[]>('/intelligence/sync', {
      method: 'POST',
      body: JSON.stringify({
        sources: sources || ['nvd', 'cisa_kev', 'github', 'cve_program', 'vendor'],
        days_back,
      }),
    }),
  searchCves: (params?: { q?: string; severity?: string; kev_only?: boolean }) => {
    const qs = new URLSearchParams()
    if (params?.q) qs.set('q', params.q)
    if (params?.severity) qs.set('severity', params.severity)
    if (params?.kev_only) qs.set('kev_only', 'true')
    const suffix = qs.toString() ? `?${qs.toString()}` : ''
    return apiRequest<{ total: number; items: CVERecord[] }>(`/cve${suffix}`)
  },
  getCveDetail: (cveId: string) =>
    apiRequest<{ record: CVERecord; ai_explanation: string }>(`/cve/${encodeURIComponent(cveId)}`),
  correlateCves: (technologies: Array<{ product_name: string; version?: string }>, scan_job_id?: string) =>
    apiRequest<{ count: number; correlations: Array<Record<string, unknown>> }>('/cve/correlate', {
      method: 'POST',
      body: JSON.stringify({ technologies, scan_job_id }),
    }),
  generateReport: (format: 'json' | 'markdown' | 'html', scan_job_id?: string) =>
    apiRequest<Record<string, unknown>>('/reports/generate', {
      method: 'POST',
      body: JSON.stringify({ format, scan_job_id, include_non_confirmed: true }),
    }),
  listReports: () =>
    apiRequest<Array<{ filename: string; size_bytes: number; download_url: string }>>('/reports'),
  getSettings: () => apiRequest<Record<string, unknown>>('/settings'),
  updateSettings: (payload: Record<string, unknown>) =>
    apiRequest<Record<string, unknown>>('/settings', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
}
