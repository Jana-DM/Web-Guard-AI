export interface NavItem {
  path: string
  label: string
  icon: string
}

export const MAIN_NAVIGATION: NavItem[] = [
  { path: '/', label: 'Dashboard', icon: 'LayoutDashboard' },
  { path: '/intelligence', label: 'Threat Intelligence', icon: 'Radio' },
  { path: '/cve-database', label: 'CVE Database', icon: 'Database' },
  { path: '/domain-scanner', label: 'Domain Scanner', icon: 'Globe' },
  { path: '/import-project', label: 'Import Project', icon: 'FolderInput' },
  { path: '/attack-surface', label: 'Attack Surface', icon: 'Network' },
  { path: '/validation', label: 'Vulnerability Validation', icon: 'ShieldCheck' },
  { path: '/ai-analyst', label: 'AI Security Assistant', icon: 'Bot' },
  { path: '/remediation', label: 'Remediation Center', icon: 'Wrench' },
  { path: '/reports', label: 'Reports', icon: 'FileText' },
  { path: '/scan-history', label: 'Scan History', icon: 'History' },
  { path: '/settings', label: 'Settings', icon: 'Settings' },
]
