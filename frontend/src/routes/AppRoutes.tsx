import React from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { LoadingState } from '../components/common/UIPrimitives'
import { AppShell } from '../components/layout/AppShell'
import { useAuth } from '../contexts/AuthContext'
import { ScanPipelineProvider } from '../contexts/ScanPipelineContext'
import { AIAnalystPage } from '../pages/AIAnalyst/AIAnalystPage'
import { AttackSurfacePage } from '../pages/AttackSurface/AttackSurfacePage'
import { AuthPage } from '../pages/Authentication/AuthPage'
import { CVEDatabasePage } from '../pages/CVEDatabase/CVEDatabasePage'
import { CodeScannerPage } from '../pages/CodeScanner/CodeScannerPage'
import { DashboardPage } from '../pages/Dashboard/DashboardPage'
import { DomainScannerPage } from '../pages/DomainScanner/DomainScannerPage'
import { ImportProjectPage } from '../pages/ImportProject/ImportProjectPage'
import { PipelinePage } from '../pages/Pipeline/PipelinePage'
import { RemediationPage } from '../pages/Remediation/RemediationPage'
import { ReportsPage } from '../pages/Reports/ReportsPage'
import { ScanHistoryPage } from '../pages/ScanHistory/ScanHistoryPage'
import { SettingsPage } from '../pages/Settings/SettingsPage'
import { ThreatIntelligencePage } from '../pages/ThreatIntelligence/ThreatIntelligencePage'
import { VulnerabilityValidationPage } from '../pages/VulnerabilityValidation/VulnerabilityValidationPage'

export const AppRoutes: React.FC = () => {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="min-h-screen bg-[#060a13] flex items-center justify-center">
        <LoadingState message="Initializing Web Guard AI..." />
      </div>
    )
  }

  if (!user) {
    return <AuthPage />
  }

  return (
    <BrowserRouter>
      <ScanPipelineProvider>
        <Routes>
          <Route path="/" element={<AppShell title="Security Operations Dashboard"><DashboardPage /></AppShell>} />
          <Route path="/intelligence" element={<AppShell title="Daily Threat Intelligence"><ThreatIntelligencePage /></AppShell>} />
          <Route path="/cve-database" element={<AppShell title="CVE Intelligence Database"><CVEDatabasePage /></AppShell>} />
          <Route path="/domain-scanner" element={<AppShell title="Authorized Domain Scanner"><DomainScannerPage /></AppShell>} />
          <Route path="/code-scanner" element={<AppShell title="Source Code Security Scanner"><CodeScannerPage /></AppShell>} />
          <Route path="/import-project" element={<AppShell title="Import Project — Full Security Pipeline"><ImportProjectPage /></AppShell>} />
          <Route path="/pipeline" element={<AppShell title="Security Pipeline — Live Scan"><PipelinePage /></AppShell>} />
          <Route path="/attack-surface" element={<AppShell title="Attack Surface & CVE Correlation"><AttackSurfacePage /></AppShell>} />
          <Route path="/validation" element={<AppShell title="AI Vulnerability Validation"><VulnerabilityValidationPage /></AppShell>} />
          <Route path="/ai-analyst" element={<AppShell title="AI Security Assistant"><AIAnalystPage /></AppShell>} />
          <Route path="/remediation" element={<AppShell title="Remediation & Verification Center"><RemediationPage /></AppShell>} />
          <Route path="/reports" element={<AppShell title="Security Reports"><ReportsPage /></AppShell>} />
          <Route path="/scan-history" element={<AppShell title="Scan History"><ScanHistoryPage /></AppShell>} />
          <Route path="/settings" element={<AppShell title="Platform Settings"><SettingsPage /></AppShell>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </ScanPipelineProvider>
    </BrowserRouter>
  )
}
