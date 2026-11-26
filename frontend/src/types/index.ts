export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Classification = 'CONFIRMED' | 'POTENTIAL' | 'NEEDS REVIEW' | 'NOT REPRODUCED'

export interface User {
  id: string
  email: string
  username: string
  full_name?: string | null
  role: string
  is_active: boolean
  created_at: string
}

export interface DashboardSummary {
  metrics: {
    total_scans: number
    total_targets: number
    verified_targets: number
    total_cves: number
    kev_cves: number
    total_vulnerabilities: number
    confirmed_vulnerabilities: number
    remediated_count: number
  }
  severity_distribution: Record<Severity, number>
  classification_distribution: Record<Classification, number>
  last_intelligence_sync: string | null
  recent_scans: ScanJob[]
}

export interface TargetVerification {
  id: string
  method: string
  challenge_token: string
  verified: boolean
  verification_details: Record<string, unknown>
  verified_at: string | null
}

export interface AuthorizedTarget {
  id: string
  project_id?: string | null
  domain: string
  normalized_url: string
  target_type: string
  scope_notes?: string | null
  allowed_paths: string[]
  is_authorized: boolean
  authorization_method?: string | null
  authorized_at?: string | null
  created_at: string
  verifications: TargetVerification[]
}

export interface ScanJob {
  id: string
  scan_type: string
  target_label: string
  status: string
  progress: number
  summary: Record<string, unknown>
  error_message?: string | null
  started_at?: string | null
  completed_at?: string | null
  created_at: string
}

export interface EvidenceRecord {
  id: string
  evidence_type: string
  source: string
  summary: string
  raw_artifact: Record<string, unknown>
  is_verifiable: boolean
  weight: number
  created_at: string
}

export interface Vulnerability {
  id: string
  scan_job_id: string
  target_id?: string | null
  title: string
  description: string
  category: string
  source_engine: string
  severity: Severity
  cvss_score?: number | null
  cwe_id?: string | null
  cve_id?: string | null
  classification: Classification
  confidence_score: number
  validation_summary?: string | null
  validation_stages: Record<string, unknown>
  location: string
  file_path?: string | null
  line_number?: number | null
  code_snippet?: string | null
  status: string
  remediation_advice?: string | null
  created_at: string
  evidence_records: EvidenceRecord[]
}

export interface CVERecord {
  id: string
  cve_id: string
  title: string
  description: string
  severity: Severity
  cvss_score?: number | null
  cvss_vector?: string | null
  cwe_ids: string[]
  affected_products: Array<Record<string, unknown>>
  is_kev: boolean
  kev_date_added?: string | null
  patch_available: boolean
  patch_urls: string[]
  references: string[]
  sources: string[]
  published_at?: string | null
  last_modified_at?: string | null
}

export interface SyncLog {
  id: string
  source: string
  status: string
  records_fetched: number
  records_created: number
  records_updated: number
  duplicates_skipped: number
  error_message?: string | null
  started_at: string
  completed_at?: string | null
}

export interface RemediationRecord {
  id: string
  vulnerability_id: string
  file_path?: string | null
  original_code: string
  proposed_code: string
  diff_preview: string
  rationale: string
  status: string
  backup_path?: string | null
  change_history: Array<Record<string, unknown>>
  approved_at?: string | null
  applied_at?: string | null
  created_at: string
}
