/**
 * PipelinePage
 * ─────────────────────────────────────────────────────────────────────────────
 * Automatic guided pipeline after project import:
 *
 *  Stage: code-scanning   → spinning loader (upload in progress)
 *  Stage: code-done       → Code Scanner results + "→ Attack Surface" button
 *  Stage: attack-surface  → Attack Surface analysis + "→ Validation" button
 *  Stage: validation      → Vulnerability list + "→ AI Explain" button
 *  Stage: ai-explain      → AI Security Assistant explains all findings + "Done → Ask to Fix?"
 *  Stage: fix-prompt      → "Do you want us to fix?" YES / NO
 *  Stage: remediation     → Remediation Center
 *  Stage: reports         → Reports page (if NO)
 */
import React, { useEffect, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowRight,
  Bot,
  CheckCircle2,
  ChevronRight,
  Download,
  FileCode2,
  FileText,
  KeyRound,
  Layers,
  Lock,
  Network,
  Play,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Wrench,
  XCircle,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Card, ErrorBanner } from '../../components/common/UIPrimitives'
import { DiffViewer } from '../../components/remediation/DiffViewer'
import { useScanPipeline } from '../../contexts/ScanPipelineContext'
import { intelligenceApi } from '../../services/intelligence/intelligenceApi'
import { scannerApi } from '../../services/scanner/scannerApi'
import { API_BASE, getStoredToken } from '../../services/api/client'
import type { RemediationRecord, Vulnerability } from '../../types'
import { classificationStyle, severityStyle } from '../../utils/formatters'

// ── helpers ──────────────────────────────────────────────────────────────────
const SevBadge: React.FC<{ label: string }> = ({ label }) => {
  const cls = {
    critical: 'bg-red-600 text-white',
    high: 'bg-orange-600 text-white',
    medium: 'bg-yellow-600 text-white',
    low: 'bg-slate-600 text-white',
    info: 'bg-blue-700 text-white',
  }[label.toLowerCase()] || 'bg-slate-700 text-slate-200'
  return <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wide ${cls}`}>{label}</span>
}

const StepBar: React.FC<{ current: string }> = ({ current }) => {
  const steps = [
    { key: 'code-scanning', label: 'Code Scanner' },
    { key: 'code-done', label: 'Code Scanner' },
    { key: 'attack-surface', label: 'Attack Surface' },
    { key: 'validation', label: 'Vuln Validation' },
    { key: 'ai-explain', label: 'AI Explain' },
    { key: 'fix-prompt', label: 'Fix?' },
    { key: 'remediation', label: 'Remediation' },
    { key: 'reports', label: 'Reports' },
  ]
  const unique = [
    { key: 'code', label: 'Code Scanner', keys: ['code-scanning', 'code-done'] },
    { key: 'attack-surface', label: 'Attack Surface', keys: ['attack-surface'] },
    { key: 'validation', label: 'Vuln Validation', keys: ['validation'] },
    { key: 'ai-explain', label: 'AI Explain', keys: ['ai-explain', 'fix-prompt'] },
    { key: 'remediation', label: 'Remediation / Reports', keys: ['remediation', 'reports'] },
  ]
  const activeIdx = unique.findIndex(s => s.keys.includes(current))
  return (
    <div className="flex items-center gap-0 overflow-x-auto pb-1 mb-2">
      {unique.map((s, i) => {
        const done = i < activeIdx
        const active = i === activeIdx
        return (
          <React.Fragment key={s.key}>
            <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold shrink-0 transition-all ${
              active ? 'bg-cyan-500/20 border border-cyan-500/50 text-cyan-300' :
              done ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400' :
              'text-slate-500 border border-slate-800 bg-[#060a13]'
            }`}>
              <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[11px] font-bold ${
                active ? 'bg-cyan-500 text-white' :
                done ? 'bg-emerald-500 text-white' :
                'bg-slate-800 text-slate-500'
              }`}>{done ? '✓' : i + 1}</span>
              {s.label}
            </div>
            {i < unique.length - 1 && <div className="w-4 h-px bg-slate-700 shrink-0 mx-0.5" />}
          </React.Fragment>
        )
      })}
    </div>
  )
}

// ── MAIN COMPONENT ────────────────────────────────────────────────────────────
export const PipelinePage: React.FC = () => {
  const navigate = useNavigate()
  const pipeline = useScanPipeline()
  const { stage, scanJob, projectName } = pipeline

  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  // Attack surface
  const [attackData, setAttackData] = useState<{ targets: any[]; technologies: any[] } | null>(null)

  // Vulnerabilities
  const [vulns, setVulns] = useState<Vulnerability[]>([])
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null)

  // AI explanation
  const [aiMessages, setAiMessages] = useState<{ role: 'assistant' | 'user'; text: string }[]>([])
  const [aiLoading, setAiLoading] = useState(false)
  const aiExplainedRef = useRef(false)

  // Remediation
  const [remRecords, setRemRecords] = useState<RemediationRecord[]>([])

  // Reports
  const [reportFormat, setReportFormat] = useState<'markdown' | 'json' | 'html'>('markdown')
  const [reportGenerated, setReportGenerated] = useState<Record<string, unknown> | null>(null)
  const [reportList, setReportList] = useState<{ filename: string; size_bytes: number }[]>([])
  const [reportBusy, setReportBusy] = useState(false)

  // Redirect if no scan
  useEffect(() => {
    if (stage === 'import' && !scanJob) navigate('/import-project')
  }, [stage, scanJob])

  // ── auto-advance code-done → attack-surface ──────────────────────────────
  useEffect(() => {
    if (stage !== 'attack-surface') return
    setBusy(true)
    scannerApi.getAttackSurfaceOverview()
      .then(data => { setAttackData(data); setBusy(false) })
      .catch(err => { setError(err?.message || 'Failed to load attack surface'); setBusy(false) })
  }, [stage])

  // ── auto-advance validation stage ────────────────────────────────────────
  useEffect(() => {
    if (stage !== 'validation' || !pipeline.scanJobId) return
    setBusy(true)
    scannerApi.listVulnerabilities({ scan_job_id: pipeline.scanJobId })
      .then(res => {
        pipeline.setVulnerabilities(res.items)
        setVulns(res.items)
        setBusy(false)
      })
      .catch(err => { setError(err?.message || 'Failed to load vulnerabilities'); setBusy(false) })
  }, [stage, pipeline.scanJobId])

  // ── auto-trigger AI explanation when ai-explain stage starts ─────────────
  useEffect(() => {
    if (stage !== 'ai-explain' || aiExplainedRef.current || vulns.length === 0) return
    aiExplainedRef.current = true
    setAiLoading(true)

    const topVulns = vulns.slice(0, 5)
    const question = `Analyze this web project "${projectName}" security scan. Found ${vulns.length} vulnerabilities total. The top findings are:\n${
      topVulns.map((v, i) => `${i + 1}. [${v.severity?.toUpperCase()}] ${v.title} at ${v.location} (${v.classification})`).join('\n')
    }\n\nPlease explain each finding in simple terms: what it is, why it's dangerous, and what developers should do to fix it. Be concise and practical.`

    scannerApi.askAiAnalyst({ question, scan_job_id: pipeline.scanJobId || undefined })
      .then(res => {
        setAiMessages([{ role: 'assistant', text: res.answer }])
        setAiLoading(false)
      })
      .catch(() => {
        setAiMessages([{
          role: 'assistant',
          text: `Security analysis for ${projectName} complete.\n\n${topVulns.map((v, i) =>
            `${i + 1}. ${v.title}\n   Severity: ${v.severity?.toUpperCase()}\n   Location: ${v.location}\n   Classification: ${v.classification}\n   Recommendation: Review and apply secure coding practices for this vulnerability type.`
          ).join('\n\n')}`
        }])
        setAiLoading(false)
      })
  }, [stage, vulns, projectName])

  // ── load remediations ─────────────────────────────────────────────────────
  useEffect(() => {
    if (stage !== 'remediation') return
    scannerApi.listRemediations()
      .then(setRemRecords)
      .catch(() => {})
  }, [stage])

  // ── load reports ──────────────────────────────────────────────────────────
  useEffect(() => {
    if (stage !== 'reports') return
    intelligenceApi.listReports()
      .then(setReportList)
      .catch(() => {})
  }, [stage])

  // ── stage helpers ─────────────────────────────────────────────────────────
  const goToAttackSurface = () => pipeline.setStage('attack-surface')
  const goToValidation = () => pipeline.setStage('validation')
  const goToAiExplain = () => pipeline.setStage('ai-explain')
  const goToFixPrompt = () => pipeline.setStage('fix-prompt')
  const chooseYes = async () => {
    // generate remediation for all confirmed findings
    const confirmed = vulns.filter(v => v.classification === 'CONFIRMED')
    for (const v of confirmed.slice(0, 5)) {
      try { await scannerApi.generateRemediation(v.id) } catch {}
    }
    pipeline.setStage('remediation')
  }
  const chooseNo = () => pipeline.setStage('reports')

  const handleApproveRem = async (id: string, approved: boolean) => {
    try { await scannerApi.approveRemediation(id, approved); setRemRecords(await scannerApi.listRemediations()) } catch {}
  }
  const handleVerifyRem = async (id: string) => {
    try { await scannerApi.verifyRemediation(id); setRemRecords(await scannerApi.listRemediations()) } catch {}
  }

  const generateReport = async () => {
    setReportBusy(true)
    try {
      const res = await intelligenceApi.generateReport(reportFormat)
      setReportGenerated(res)
      setReportList(await intelligenceApi.listReports())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Report failed')
    } finally { setReportBusy(false) }
  }

  const downloadReport = async (filename: string) => {
    const token = getStoredToken()
    const resp = await fetch(`${API_BASE}/reports/${encodeURIComponent(filename)}/download`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!resp.ok) return
    const blob = await resp.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = filename; a.click()
    URL.revokeObjectURL(url)
  }

  const summary = (scanJob?.summary || {}) as Record<string, any>

  // ── RENDER ────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onClose={() => setError(null)} />}

      <StepBar current={stage} />

      {/* ═══ STAGE: code-scanning ══════════════════════════════════════════ */}
      {stage === 'code-scanning' && (
        <div className="bg-[#0c1322] border border-cyan-500/40 rounded-2xl p-10 shadow-2xl flex flex-col items-center justify-center text-center">
          <div className="relative w-20 h-20 mb-6">
            <div className="w-20 h-20 rounded-full border-4 border-slate-800 border-t-cyan-400 animate-spin" />
            <div className="absolute inset-0 flex items-center justify-center">
              <Shield className="w-7 h-7 text-cyan-400 animate-pulse" />
            </div>
          </div>
          <h3 className="text-xl font-bold text-slate-100 tracking-wide">Running Full Security Pipeline</h3>
          <p className="text-xs text-cyan-300 font-mono mt-2.5 max-w-lg leading-relaxed animate-pulse">
            Validating technologies → Detecting secrets → Scanning vulnerabilities…
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3 text-xs text-slate-300">
            {['1. Tech & Framework Validation', '2. Sensitive Key Detection', '3. Deep Vulnerability Audit', '4. Evidence-Based Classification'].map((s, i) => (
              <span key={i} className="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#060a13] border border-slate-800 shadow-sm">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                {s}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ═══ STAGE: code-done ══════════════════════════════════════════════ */}
      {stage === 'code-done' && scanJob && (
        <div className="space-y-6">
          {/* Header */}
          <div className="bg-[#0c1322] border border-emerald-500/40 rounded-xl p-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-slate-100">Step 1: Code Scanner Complete</h3>
                  <p className="text-xs text-slate-400">Project: <span className="text-cyan-300">{projectName}</span></p>
                </div>
              </div>
              <button
                onClick={goToAttackSurface}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-bold shadow-md"
              >
                Next: Attack Surface Analysis <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { icon: Layers, color: 'cyan', label: 'Files Discovered', value: summary.total_files_discovered ?? 0 },
              { icon: FileCode2, color: 'emerald', label: 'Files Scanned', value: summary.total_files_scanned ?? 0 },
              { icon: XCircle, color: 'slate', label: 'Files Excluded', value: summary.total_files_excluded ?? 0 },
              { icon: KeyRound, color: 'red', label: 'Sensitive Secrets', value: (summary.sensitive_information_findings || []).length },
            ].map(({ icon: Icon, color, label, value }) => (
              <div key={label} className={`bg-[#0c1322] border border-${color}-500/30 rounded-xl p-4`}>
                <div className={`flex items-center gap-2 text-${color}-400 text-xs mb-2`}><Icon className="w-4 h-4" />{label}</div>
                <div className={`text-2xl font-bold text-${color}-300`}>{value}</div>
              </div>
            ))}
          </div>

          {/* Tech + Classifications */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5">
              <h4 className="text-sm font-semibold text-slate-200 mb-3">Detected Technologies</h4>
              <div className="flex flex-wrap gap-2">
                {((summary.detected_technologies || []) as string[]).map(t => (
                  <span key={t} className="px-2.5 py-1 rounded-md bg-cyan-950/50 border border-cyan-500/30 text-cyan-300 text-xs font-medium">{t}</span>
                ))}
                {!(summary.detected_technologies?.length) && <span className="text-slate-500 text-sm">Web Standard</span>}
              </div>
            </div>
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5">
              <h4 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2"><Shield className="w-4 h-4 text-cyan-400" />Findings</h4>
              <div className="grid grid-cols-3 gap-3 text-center text-xs">
                {[
                  { label: 'Confirmed', val: summary.classification_breakdown?.confirmed ?? summary.confirmed_findings ?? 0, cls: 'emerald' },
                  { label: 'Potential', val: summary.classification_breakdown?.potential ?? summary.potential_findings ?? 0, cls: 'amber' },
                  { label: 'Info', val: summary.classification_breakdown?.informational ?? summary.informational_findings ?? 0, cls: 'blue' },
                ].map(({ label, val, cls }) => (
                  <div key={label} className={`p-3 rounded-lg bg-${cls}-950/20 border border-${cls}-500/30`}>
                    <div className={`text-lg font-bold text-${cls}-400`}>{val}</div>
                    <div className={`text-[11px] font-semibold text-${cls}-300`}>{label}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Sensitive secrets */}
          {(summary.sensitive_information_findings || []).length > 0 && (
            <Card title="Sensitive Information Detected" subtitle="All secret values are masked — never stored in cleartext">
              <div className="space-y-3">
                {(summary.sensitive_information_findings as any[]).map((f: any, i: number) => (
                  <div key={i} className="p-4 rounded-xl border border-red-500/40 bg-red-950/15 flex flex-col md:flex-row md:items-start justify-between gap-3">
                    <div className="space-y-1 flex-1">
                      <div className="flex items-center gap-2">
                        <SevBadge label={f.severity} />
                        <span className="text-sm font-semibold text-slate-100 flex items-center gap-1.5">
                          <Lock className="w-3.5 h-3.5 text-red-400" />{f.type}
                        </span>
                      </div>
                      <div className="text-xs text-slate-300">
                        File: <code className="text-cyan-300 font-mono bg-slate-900 px-1 rounded">{f.file_path}</code> Line: <strong>{f.line_number}</strong>
                      </div>
                      <div className="text-xs text-slate-400"><strong className="text-emerald-400">Fix:</strong> {f.recommended_remediation}</div>
                    </div>
                    <div className="bg-[#060a13] border border-slate-800 rounded-lg p-2 text-xs font-mono text-cyan-200 shrink-0">
                      <span className="text-slate-500 text-[10px] block">Masked:</span>{f.masked_value}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}

          <button onClick={goToAttackSurface} className="w-full inline-flex items-center justify-center gap-2 px-6 py-4 rounded-xl bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white font-bold shadow-lg shadow-cyan-500/20 text-base">
            Continue to Step 2: Attack Surface Analysis <ArrowRight className="w-5 h-5" />
          </button>
        </div>
      )}

      {/* ═══ STAGE: attack-surface ════════════════════════════════════════ */}
      {stage === 'attack-surface' && (
        <div className="space-y-6">
          <div className="bg-[#0c1322] border border-indigo-500/40 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-indigo-500/15 border border-indigo-500/40 flex items-center justify-center">
                <Network className="w-5 h-5 text-indigo-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-100">Step 2: Attack Surface Analysis</h3>
                <p className="text-xs text-slate-400">Mapping exposed technologies, monitored domains, and fingerprinted dependencies</p>
              </div>
            </div>
            {!busy && (
              <button onClick={goToValidation} className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-bold">
                Next: Vulnerability Validation <ArrowRight className="w-4 h-4" />
              </button>
            )}
          </div>

          {busy ? (
            <div className="flex items-center justify-center py-12">
              <div className="w-10 h-10 rounded-full border-4 border-slate-800 border-t-indigo-400 animate-spin" />
              <span className="ml-4 text-slate-400">Loading attack surface data…</span>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card title="Monitored Domains & Scope" subtitle="Registered targets and their authorization status">
                <div className="space-y-2">
                  {attackData?.targets.length ? attackData.targets.map((t: any) => (
                    <div key={t.id} className="border border-slate-800 rounded-lg p-3 bg-[#060a13]/70 flex items-center justify-between text-xs">
                      <div>
                        <div className="text-sm font-medium text-slate-100">{t.domain}</div>
                        <div className="text-slate-400">{t.normalized_url}</div>
                      </div>
                      <span className={t.is_authorized ? 'text-emerald-400' : 'text-amber-400'}>{t.is_authorized ? 'Authorized' : 'Pending'}</span>
                    </div>
                  )) : (
                    <div className="py-6 text-center">
                      <Network className="w-8 h-8 text-slate-700 mx-auto mb-2" />
                      <p className="text-sm text-slate-500">No domains registered yet.</p>
                      <p className="text-xs text-slate-600 mt-1">Use Domain Scanner to add monitored targets.</p>
                    </div>
                  )}
                </div>
              </Card>
              <Card title="Fingerprinted Tech Stack" subtitle="Detected from code scan and dependency analysis">
                <div className="space-y-2 max-h-72 overflow-y-auto">
                  {attackData?.technologies.length ? attackData.technologies.map((t: any) => (
                    <div key={t.id} className="border border-slate-800 rounded-lg p-2.5 bg-[#060a13]/70 flex justify-between text-xs">
                      <span className="font-semibold text-cyan-300">{t.product_name} <span className="text-slate-400">{t.version ? `v${t.version}` : ''}</span></span>
                      <span className="text-slate-400">{t.detection_source}</span>
                    </div>
                  )) : (
                    <div className="py-6 text-center">
                      <Shield className="w-8 h-8 text-slate-700 mx-auto mb-2" />
                      <p className="text-sm text-slate-500">Technologies detected from code scan:</p>
                      <div className="flex flex-wrap gap-2 justify-center mt-3">
                        {((summary.detected_technologies || []) as string[]).map(t => (
                          <span key={t} className="px-2 py-1 rounded bg-cyan-950/40 border border-cyan-500/30 text-cyan-300 text-xs">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </Card>
            </div>
          )}

          {!busy && (
            <button onClick={goToValidation} className="w-full inline-flex items-center justify-center gap-2 px-6 py-4 rounded-xl bg-gradient-to-r from-indigo-600 to-indigo-500 hover:from-indigo-500 hover:to-indigo-400 text-white font-bold shadow-lg text-base">
              Continue to Step 3: Vulnerability Validation <ArrowRight className="w-5 h-5" />
            </button>
          )}
        </div>
      )}

      {/* ═══ STAGE: validation ════════════════════════════════════════════ */}
      {stage === 'validation' && (
        <div className="space-y-6">
          <div className="bg-[#0c1322] border border-amber-500/40 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-amber-500/15 border border-amber-500/40 flex items-center justify-center">
                <ShieldCheck className="w-5 h-5 text-amber-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-100">Step 3: Vulnerability Validation</h3>
                <p className="text-xs text-slate-400">{vulns.length} findings classified — Confirmed · Potential · Informational</p>
              </div>
            </div>
            {!busy && <button onClick={goToAiExplain} className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-sm font-bold">
              Next: AI Explain Findings <ArrowRight className="w-4 h-4" />
            </button>}
          </div>

          {busy ? (
            <div className="flex items-center justify-center py-12">
              <div className="w-10 h-10 rounded-full border-4 border-slate-800 border-t-amber-400 animate-spin" />
              <span className="ml-4 text-slate-400">Loading vulnerability findings…</span>
            </div>
          ) : vulns.length === 0 ? (
            <div className="bg-[#0c1322] border border-emerald-500/30 rounded-xl p-10 text-center">
              <ShieldCheck className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
              <h3 className="text-lg font-bold text-emerald-300">No Vulnerabilities Found!</h3>
              <p className="text-sm text-slate-400 mt-2">Your project passed the security audit with zero findings.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {vulns.map(v => (
                <div
                  key={v.id}
                  onClick={() => setSelectedVuln(selectedVuln?.id === v.id ? null : v)}
                  className="border border-slate-800 hover:border-cyan-500/50 rounded-xl p-4 bg-[#060a13]/70 cursor-pointer transition-all"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <SevBadge label={v.severity} />
                        <span className="text-sm font-semibold text-slate-100 truncate">{v.title}</span>
                      </div>
                      <div className="text-xs text-slate-400 mt-1 font-mono truncate">{v.location}</div>
                      {v.line_number && <div className="text-xs text-slate-500 mt-0.5">Line: <strong className="text-slate-300">{v.line_number}</strong></div>}
                    </div>
                    <div className="flex flex-col items-end gap-1 shrink-0">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${classificationStyle(v.classification)}`}>{v.classification}</span>
                      <span className="text-[11px] text-slate-500">{Math.round(v.confidence_score * 100)}% confidence</span>
                    </div>
                  </div>

                  {/* Expanded detail */}
                  {selectedVuln?.id === v.id && (
                    <div className="mt-3 pt-3 border-t border-slate-800 space-y-2">
                      {v.description && <p className="text-xs text-slate-300">{v.description}</p>}
                      {v.code_snippet && (
                        <div className="bg-[#060a13] border border-red-500/30 rounded-lg p-3">
                          <span className="text-[11px] text-red-400 font-semibold block mb-1">Evidence snippet:</span>
                          <code className="text-xs font-mono text-red-200 whitespace-pre-wrap">{v.code_snippet}</code>
                        </div>
                      )}
                      {v.remediation_advice && (
                        <div className="bg-[#060a13] border border-emerald-500/30 rounded-lg p-3">
                          <span className="text-[11px] text-emerald-400 font-semibold block mb-1">Recommended Fix:</span>
                          <p className="text-xs text-emerald-200">{v.remediation_advice}</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {!busy && (
            <button onClick={goToAiExplain} className="w-full inline-flex items-center justify-center gap-2 px-6 py-4 rounded-xl bg-gradient-to-r from-amber-600 to-amber-500 hover:from-amber-500 hover:to-amber-400 text-white font-bold shadow-lg text-base">
              Continue to Step 4: AI Security Assistant <ArrowRight className="w-5 h-5" />
            </button>
          )}
        </div>
      )}

      {/* ═══ STAGE: ai-explain ════════════════════════════════════════════ */}
      {stage === 'ai-explain' && (
        <div className="space-y-6">
          <div className="bg-[#0c1322] border border-violet-500/40 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-violet-500/15 border border-violet-500/40 flex items-center justify-center">
                <Bot className="w-5 h-5 text-violet-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-100">Step 4: AI Security Assistant</h3>
                <p className="text-xs text-slate-400">Explaining all findings in plain language with actionable fixes</p>
              </div>
            </div>
          </div>

          <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 min-h-[200px]">
            {aiLoading ? (
              <div className="flex items-center gap-3 py-8 justify-center">
                <div className="w-6 h-6 rounded-full border-4 border-slate-700 border-t-violet-400 animate-spin" />
                <span className="text-slate-400 text-sm animate-pulse">AI analyzing {vulns.length} vulnerabilities…</span>
              </div>
            ) : (
              aiMessages.map((m, i) => (
                <div key={i} className="bg-[#060a13] border border-violet-500/30 rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Bot className="w-4 h-4 text-violet-400" />
                    <span className="text-xs font-semibold text-violet-300 uppercase">Web Guard AI Security Assistant</span>
                  </div>
                  <div className="text-sm text-slate-200 whitespace-pre-wrap leading-relaxed">{m.text}</div>
                </div>
              ))
            )}
          </div>

          {!aiLoading && (
            <button onClick={goToFixPrompt} className="w-full inline-flex items-center justify-center gap-2 px-6 py-4 rounded-xl bg-gradient-to-r from-violet-600 to-violet-500 hover:from-violet-500 hover:to-violet-400 text-white font-bold shadow-lg text-base">
              I've Read the Explanation — What's Next? <ArrowRight className="w-5 h-5" />
            </button>
          )}
        </div>
      )}

      {/* ═══ STAGE: fix-prompt ════════════════════════════════════════════ */}
      {stage === 'fix-prompt' && (
        <div className="space-y-6">
          <div className="bg-[#0c1322] border border-cyan-500/40 rounded-2xl p-10 text-center">
            <div className="w-16 h-16 rounded-full bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center mx-auto mb-5">
              <Wrench className="w-8 h-8 text-cyan-400" />
            </div>
            <h2 className="text-2xl font-bold text-slate-100 mb-2">Do you want us to fix the vulnerabilities?</h2>
            <p className="text-slate-400 text-sm max-w-lg mx-auto">
              Web Guard AI can generate secure code patches for all <strong className="text-amber-300">{vulns.filter(v => v.classification === 'CONFIRMED').length} confirmed</strong> vulnerabilities.
              Patches are shown as diff previews — <strong className="text-cyan-300">you must approve each one</strong> before any file is changed.
            </p>

            <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
              <button
                onClick={chooseYes}
                className="inline-flex items-center gap-3 px-8 py-4 rounded-xl bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 text-white text-lg font-bold shadow-xl shadow-emerald-500/30 transition-all"
              >
                <CheckCircle2 className="w-6 h-6" />
                Yes, Fix It!
              </button>
              <button
                onClick={chooseNo}
                className="inline-flex items-center gap-3 px-8 py-4 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-lg font-bold transition-all"
              >
                <FileText className="w-6 h-6 text-cyan-400" />
                No, Just Show Report
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ═══ STAGE: remediation ═══════════════════════════════════════════ */}
      {stage === 'remediation' && (
        <div className="space-y-6">
          <div className="bg-[#0c1322] border border-emerald-500/40 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center">
                <Wrench className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-100">Step 5: Remediation Center</h3>
                <p className="text-xs text-slate-400">Review secure patches — approve each fix before it's applied</p>
              </div>
            </div>
            <button onClick={() => pipeline.setStage('reports')} className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-sm font-bold">
              Done — View Reports <ArrowRight className="w-4 h-4" />
            </button>
          </div>

          {remRecords.length === 0 ? (
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-10 text-center">
              <RefreshCw className="w-8 h-8 text-slate-600 mx-auto mb-3 animate-spin" />
              <p className="text-slate-400 text-sm">Generating secure remediation patches…</p>
            </div>
          ) : (
            <div className="space-y-4">
              {remRecords.map(rec => (
                <DiffViewer key={rec.id} record={rec} onApprove={handleApproveRem} onVerify={handleVerifyRem} />
              ))}
            </div>
          )}

          <button onClick={() => pipeline.setStage('reports')} className="w-full inline-flex items-center justify-center gap-2 px-6 py-4 rounded-xl bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 text-white font-bold shadow-lg text-base">
            All Done — Generate Final Security Report <ArrowRight className="w-5 h-5" />
          </button>
        </div>
      )}

      {/* ═══ STAGE: reports ══════════════════════════════════════════════ */}
      {stage === 'reports' && (
        <div className="space-y-6">
          <div className="bg-[#0c1322] border border-cyan-500/40 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center">
                <FileText className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-100">Step 6: Security Report</h3>
                <p className="text-xs text-slate-400">Download a detailed vulnerability report with file paths and line numbers</p>
              </div>
            </div>
          </div>

          {/* Vuln summary table */}
          <Card title="Vulnerability Summary" subtitle="All findings with file location and line number">
            {vulns.length === 0 ? (
              <div className="py-6 text-center text-slate-500 text-sm">No vulnerabilities found in this scan.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-slate-300">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="text-left py-2 pr-4">Severity</th>
                      <th className="text-left py-2 pr-4">Type</th>
                      <th className="text-left py-2 pr-4">File</th>
                      <th className="text-left py-2 pr-4">Line</th>
                      <th className="text-left py-2">Classification</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {vulns.map(v => (
                      <tr key={v.id} className="hover:bg-slate-800/20 transition-colors">
                        <td className="py-2 pr-4"><SevBadge label={v.severity} /></td>
                        <td className="py-2 pr-4 font-medium text-slate-100">{v.title}</td>
                        <td className="py-2 pr-4 font-mono text-cyan-300">{v.location?.split(':')[0] || v.location}</td>
                        <td className="py-2 pr-4 font-bold text-slate-200">{v.line_number || '—'}</td>
                        <td className="py-2">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${classificationStyle(v.classification)}`}>{v.classification}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          {/* Generate Report */}
          <Card title="Download Full Report" subtitle="JSON, Markdown, or HTML — all findings with evidence and line numbers">
            <div className="flex flex-wrap items-center gap-3">
              <select
                value={reportFormat}
                onChange={e => setReportFormat(e.target.value as typeof reportFormat)}
                className="bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
              >
                <option value="markdown">Markdown (.md)</option>
                <option value="json">JSON (.json)</option>
                <option value="html">HTML Report (.html)</option>
              </select>
              <button
                onClick={generateReport}
                disabled={reportBusy}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold disabled:opacity-50"
              >
                <FileText className="w-4 h-4" />
                {reportBusy ? 'Generating…' : 'Generate & Download Report'}
              </button>
            </div>

            {reportList.length > 0 && (
              <div className="mt-4 space-y-2">
                {reportList.map(r => (
                  <div key={r.filename} className="flex items-center justify-between border border-slate-800 rounded-lg p-3 bg-[#060a13]/70 text-xs">
                    <div>
                      <span className="font-mono text-slate-200">{r.filename}</span>
                      <span className="text-slate-500 ml-3">{r.size_bytes} bytes</span>
                    </div>
                    <button
                      onClick={() => downloadReport(r.filename)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-cyan-700 text-slate-200"
                    >
                      <Download className="w-3.5 h-3.5" /> Download
                    </button>
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* Restart */}
          <button
            onClick={() => { pipeline.reset(); navigate('/import-project') }}
            className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-cyan-400 transition-colors"
          >
            <Play className="w-4 h-4" /> Scan Another Project
          </button>
        </div>
      )}
    </div>
  )
}
