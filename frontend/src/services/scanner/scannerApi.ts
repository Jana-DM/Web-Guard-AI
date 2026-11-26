import { apiRequest } from '../api/client'
import type { AuthorizedTarget, RemediationRecord, ScanJob, Vulnerability } from '../../types'

export const scannerApi = {
  listTargets: () => apiRequest<AuthorizedTarget[]>('/domain-scans/targets'),
  registerTarget: (domain_or_url: string, scope_notes?: string) =>
    apiRequest<AuthorizedTarget>('/domain-scans/targets', {
      method: 'POST',
      body: JSON.stringify({ domain_or_url, scope_notes }),
    }),
  verifyTarget: (targetId: string, method: string, signed_statement?: string) =>
    apiRequest<AuthorizedTarget>(`/domain-scans/targets/${targetId}/verify`, {
      method: 'POST',
      body: JSON.stringify({ method, signed_statement }),
    }),
  startDomainScan: (target_id: string, enable_safe_owasp_checks = true) =>
    apiRequest<ScanJob>('/domain-scans', {
      method: 'POST',
      body: JSON.stringify({ target_id, enable_safe_owasp_checks }),
    }),
  listScans: (scanType?: string) =>
    apiRequest<ScanJob[]>(scanType ? `/domain-scans?scan_type=${encodeURIComponent(scanType)}` : '/domain-scans'),
  getScanDetail: (scanId: string) =>
    apiRequest<{ job: ScanJob; results: Array<{ module: string; status: string; data: Record<string, unknown> }>; fingerprints: Array<Record<string, unknown>>; vulnerabilities_count: number }>(`/domain-scans/${scanId}`),
  uploadCodeScan: async (
    files: FileList | File[],
    onProgress?: (info: { uploaded: number; total: number; stage: 'uploading' | 'analyzing' }) => void
  ) => {
    const fileArray = Array.from(files)
    const getRelPath = (file: File) =>
      (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name

    if (fileArray.length <= 300) {
      onProgress?.({ uploaded: fileArray.length, total: fileArray.length, stage: 'analyzing' })
      const formData = new FormData()
      fileArray.forEach((file) => formData.append('files', file, getRelPath(file)))
      return apiRequest<ScanJob>('/code-scans/upload', {
        method: 'POST',
        body: formData,
      })
    }

    const roots = new Set(
      fileArray
        .map((f) => getRelPath(f).replace(/\\/g, '/'))
        .filter((p) => p.includes('/'))
        .map((p) => p.split('/')[0])
    )
    const targetLabel =
      roots.size === 1
        ? `${Array.from(roots)[0]} (${fileArray.length} files)`
        : `${fileArray.length} uploaded items`

    const job = await apiRequest<ScanJob>('/code-scans/upload/init', {
      method: 'POST',
      body: JSON.stringify({ target_label: targetLabel, total_files: fileArray.length }),
    })

    const chunkSize = 250
    for (let i = 0; i < fileArray.length; i += chunkSize) {
      const batch = fileArray.slice(i, i + chunkSize)
      const formData = new FormData()
      batch.forEach((file) => formData.append('files', file, getRelPath(file)))
      await apiRequest<{ uploaded_files: number }>(`/code-scans/upload/${job.id}/chunk`, {
        method: 'POST',
        body: formData,
      })
      onProgress?.({
        uploaded: Math.min(i + batch.length, fileArray.length),
        total: fileArray.length,
        stage: 'uploading',
      })
    }

    onProgress?.({ uploaded: fileArray.length, total: fileArray.length, stage: 'analyzing' })
    return apiRequest<ScanJob>(`/code-scans/upload/${job.id}/execute`, {
      method: 'POST',
    })
  },
  scanGitHubRepo: (repository_url: string, branch?: string) =>
    apiRequest<ScanJob>('/code-scans/github', {
      method: 'POST',
      body: JSON.stringify({ repository_url, branch: branch || undefined }),
    }),
  listVulnerabilities: (params?: { severity?: string; classification?: string; scan_job_id?: string }) => {
    const qs = new URLSearchParams()
    if (params?.severity) qs.set('severity', params.severity)
    if (params?.classification) qs.set('classification', params.classification)
    if (params?.scan_job_id) qs.set('scan_job_id', params.scan_job_id)
    const suffix = qs.toString() ? `?${qs.toString()}` : ''
    return apiRequest<{ total: number; items: Vulnerability[] }>(`/vulnerabilities${suffix}`)
  },
  getVulnerabilityDetail: (id: string) =>
    apiRequest<{ vulnerability: Vulnerability; ai_explanation: string }>(`/vulnerabilities/${id}`),
  runValidation: (scanJobId: string) =>
    apiRequest<Vulnerability[]>(`/validation/run/${scanJobId}`, { method: 'POST' }),
  askAiAnalyst: (payload: { question: string; vulnerability_id?: string; scan_job_id?: string; cve_id?: string }) =>
    apiRequest<{ answer: string; citations: Array<{ type: string; id: string; label: string }>; grounded: boolean }>(
      '/validation/ai-analyze',
      { method: 'POST', body: JSON.stringify(payload) }
    ),
  listRemediations: () => apiRequest<RemediationRecord[]>('/remediation'),
  generateRemediation: (vulnId: string) =>
    apiRequest<{ remediation: RemediationRecord; ai_guidance: string }>(`/remediation/generate/${vulnId}`, {
      method: 'POST',
    }),
  approveRemediation: (remId: string, approved: boolean, review_comment?: string) =>
    apiRequest<RemediationRecord>(`/remediation/${remId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ approved, review_comment }),
    }),
  verifyRemediation: (remId: string) =>
    apiRequest<Record<string, unknown>>(`/verification/run/${remId}`, { method: 'POST' }),
  getAttackSurfaceOverview: () =>
    apiRequest<{ targets: Array<Record<string, unknown>>; technologies: Array<Record<string, unknown>> }>('/attack-surface'),
  getTargetAttackSurface: (targetId: string) =>
    apiRequest<Record<string, unknown>>(`/attack-surface/${targetId}`),
}
