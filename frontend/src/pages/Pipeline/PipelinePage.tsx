/**
 * PipelinePage — Full auto-flow guided security pipeline.
 *
 * Stage: pending-scan   → picks up files from context ref → starts upload
 * Stage: code-scanning  → spinner (scan running HERE, errors visible)
 * Stage: code-done      → Code Scanner results + "→ Attack Surface"
 * Stage: attack-surface → Attack Surface + "→ Validation"
 * Stage: validation     → Vuln list + "→ AI Explain"
 * Stage: ai-explain     → AI explanation + "→ Fix Prompt"
 * Stage: fix-prompt     → YES / NO dialog
 * Stage: remediation    → Remediation Center
 * Stage: reports        → Reports with vuln table (file + line)
 */
import React, { useEffect, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowRight,
  Bot,
  CheckCircle2,
  Download,
  FileCode2,
  FileText,
  FolderInput,
  KeyRound,
  Layers,
  Lock,
  Network,
  Play,
  RefreshCw,
  Shield,
  ShieldCheck,
  Wrench,
  XCircle,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Card, ErrorBanner } from '../../components/common/UIPrimitives'
import { DiffViewer } from '../../components/remediation/DiffViewer'
import { RealtimeScanConsole } from '../../components/scanner/RealtimeScanConsole'
import { useScanPipeline } from '../../contexts/ScanPipelineContext'
import { intelligenceApi } from '../../services/intelligence/intelligenceApi'
import { scannerApi } from '../../services/scanner/scannerApi'
import { API_BASE, getStoredToken } from '../../services/api/client'
import type { RemediationRecord, Vulnerability } from '../../types'
import { classificationStyle } from '../../utils/formatters'

// ── helpers ──────────────────────────────────────────────────────────────────
const SevBadge: React.FC<{ label: string }> = ({ label }) => {
  const cls: Record<string, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-orange-600 text-white',
    medium: 'bg-yellow-600 text-black',
    low: 'bg-slate-600 text-white',
    info: 'bg-blue-700 text-white',
  }
  return (
    <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wide ${cls[label?.toLowerCase()] ?? 'bg-slate-700 text-slate-200'}`}>
      {label}
    </span>
  )
}

const StepBar: React.FC<{ current: string }> = ({ current }) => {
  const steps = [
    { keys: ['pending-scan', 'code-scanning', 'code-done'], label: 'Code Scanner' },
    { keys: ['attack-surface'], label: 'Attack Surface' },
    { keys: ['validation'], label: 'Vuln Validation' },
    { keys: ['ai-explain', 'fix-prompt'], label: 'AI Explain' },
    { keys: ['remediation', 'reports'], label: 'Remediation / Reports' },
  ]
  const activeIdx = steps.findIndex(s => s.keys.includes(current))
  return (
    <div className="flex items-center gap-0 overflow-x-auto pb-1 mb-4">
      {steps.map((s, i) => {
        const done = i < activeIdx
        const active = i === activeIdx
        return (
          <React.Fragment key={s.label}>
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
            {i < steps.length - 1 && <div className="w-4 h-px bg-slate-700 shrink-0 mx-0.5" />}
          </React.Fragment>
        )
      })}
    </div>
  )
}

// ── MAIN ─────────────────────────────────────────────────────────────────────
export const PipelinePage: React.FC = () => {
  const navigate = useNavigate()
  const pipeline = useScanPipeline()
  const { stage, scanJob, projectName } = pipeline

  const [progressText, setProgressText] = useState('')
  const [scanError, setScanError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  // Attack surface
  const [attackData, setAttackData] = useState<{ targets: any[]; technologies: any[] } | null>(null)

  // Vulns (local copy)
  const [vulns, setVulns] = useState<Vulnerability[]>([])
  const [selectedVulnId, setSelectedVulnId] = useState<string | null>(null)

  // AI
  const [aiMessages, setAiMessages] = useState<{ text: string }[]>([])
  const [aiLoading, setAiLoading] = useState(false)
  const aiTriggeredRef = useRef(false)

  // Remediation
  const [remRecords, setRemRecords] = useState<RemediationRecord[]>([])

  // Reports
  const [reportFormat, setReportFormat] = useState<'markdown' | 'json' | 'html'>('markdown')
  const [reportList, setReportList] = useState<{ filename: string; size_bytes: number }[]>([])
  const [reportBusy, setReportBusy] = useState(false)

  // Guard: if no pending scan and no scan job → go back
  useEffect(() => {
    if (stage === 'import') {
      navigate('/import-project')
    }
  }, [stage])

  // ── STAGE: attack-surface ─────────────────────────────────────────────────
  useEffect(() => {
    if (stage !== 'attack-surface') return
    setBusy(true)
    scannerApi.getAttackSurfaceOverview()
      .then(d => { setAttackData(d); setBusy(false) })
      .catch(() => { setAttackData({ targets: [], technologies: [] }); setBusy(false) })
  }, [stage])

  // ── STAGE: validation ─────────────────────────────────────────────────────
  useEffect(() => {
    if (stage !== 'validation' || !pipeline.scanJobId) return
    setBusy(true)
    scannerApi.listVulnerabilities({ scan_job_id: pipeline.scanJobId })
      .then(res => { setVulns(res.items); pipeline.setVulnerabilities(res.items); setBusy(false) })
      .catch(() => setBusy(false))
  }, [stage, pipeline.scanJobId])

  // ── STAGE: ai-explain — auto-trigger once ─────────────────────────────────
  useEffect(() => {
    if (stage !== 'ai-explain' || aiTriggeredRef.current) return
    aiTriggeredRef.current = true

    const allVulns = pipeline.vulnerabilities.length ? pipeline.vulnerabilities : vulns
    if (!allVulns.length) {
      setAiMessages([{ text: `Security scan of "${projectName}" is complete. No confirmed vulnerabilities were found — your project looks clean! Continue to the report for the full summary.` }])
      return
    }

    setAiLoading(true)
    const top = allVulns.slice(0, 6)
    const question = `You are a senior cybersecurity expert. Analyze this web project security scan for "${projectName}".

Found ${allVulns.length} vulnerabilities total. Top findings:
${top.map((v, i) => `${i + 1}. [${v.severity?.toUpperCase()}] ${v.title}
   File: ${v.file_path || v.location}${v.line_number ? `, Line ${v.line_number}` : ''}
   Classification: ${v.classification}
   ${v.description ? `Detail: ${v.description.slice(0, 120)}` : ''}`).join('\n')}

For each finding explain:
1. What is this vulnerability?
2. Why is it dangerous?
3. What is the recommended fix?

Keep answers concise and developer-friendly.`

    scannerApi.askAiAnalyst({ question, scan_job_id: pipeline.scanJobId || undefined })
      .then(res => { setAiMessages([{ text: res.answer }]); setAiLoading(false) })
      .catch(() => {
        const allV = allVulns
        setAiMessages([{ text: `Security Analysis for "${projectName}"\n\n${allV.slice(0, 6).map((v, i) =>
          `${i + 1}. [${v.severity?.toUpperCase()}] ${v.title}\n   📂 ${v.file_path || v.location}${v.line_number ? ` (Line ${v.line_number})` : ''}\n   🔍 ${v.classification}\n   💡 ${v.remediation_advice || 'Review and apply secure coding best practices for this vulnerability type.'}`
        ).join('\n\n')}` }])
        setAiLoading(false)
      })
  }, [stage])

  // ── STAGE: remediation — load records ────────────────────────────────────
  useEffect(() => {
    if (stage !== 'remediation') return
    scannerApi.listRemediations().then(setRemRecords).catch(() => {})
  }, [stage])

  // ── STAGE: reports ────────────────────────────────────────────────────────
  useEffect(() => {
    if (stage !== 'reports') return
    intelligenceApi.listReports().then(setReportList).catch(() => {})
  }, [stage])

  const summary = (scanJob?.summary || {}) as Record<string, any>
  const allVulns = pipeline.vulnerabilities.length ? pipeline.vulnerabilities : vulns

  const chooseYes = async () => {
    const confirmed = allVulns.filter(v => v.classification === 'CONFIRMED')
    for (const v of confirmed.slice(0, 5)) {
      try { await scannerApi.generateRemediation(v.id) } catch {}
    }
    pipeline.setStage('remediation')
  }
  const chooseNo = () => pipeline.setStage('reports')

  const generateReport = async () => {
    setReportBusy(true)
    try {
      await intelligenceApi.generateReport(reportFormat)
      setReportList(await intelligenceApi.listReports())
    } catch { } finally { setReportBusy(false) }
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

  // ── render ────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-6">
      <StepBar current={stage} />

      {/* ═══ STAGE: code-scanning / pending-scan ══════════════════════════ */}
      {(stage === 'pending-scan' || stage === 'code-scanning') && (
        <RealtimeScanConsole
          files={pipeline.pendingFilesRef.current}
          github={pipeline.pendingGitHub}
          onComplete={(job) => {
            const sum = (job.summary || {}) as Record<string, any>
            pipeline.setScanJob(job)
            pipeline.setScanJobId(job.id)
            pipeline.setProjectName(sum.project_name || job.target_label || 'Web Project')
            pipeline.setStage('code-done')
          }}
          onCancel={() => {
            pipeline.reset()
            navigate('/import-project')
          }}
        />
      )}

      {/* ═══ STAGE: code-done ════════════════════════════════════════════ */}
      {stage === 'code-done' && scanJob && (
        <div className="space-y-5">
          {/* Header */}
          <div className="bg-[#0c1322] border border-emerald-500/40 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-100">Step 1 Complete — Code Scanner</h3>
                <p className="text-xs text-slate-400">Project: <span className="text-cyan-300 font-medium">{projectName}</span></p>
              </div>
            </div>
            <button onClick={() => pipeline.setStage('attack-surface')}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-bold shadow-md">
              Next: Attack Surface <ArrowRight className="w-4 h-4" />
            </button>
          </div>

          {/* Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { icon: Layers, label: 'Files Discovered', val: summary.total_files_discovered ?? 0, color: 'cyan' },
              { icon: FileCode2, label: 'Files Scanned', val: summary.total_files_scanned ?? 0, color: 'emerald' },
              { icon: XCircle, label: 'Excluded', val: summary.total_files_excluded ?? 0, color: 'slate' },
              { icon: KeyRound, label: 'Sensitive Secrets', val: (summary.sensitive_information_findings ?? []).length, color: 'red' },
            ].map(({ icon: Icon, label, val, color }) => (
              <div key={label} className="bg-[#0c1322] border border-slate-800 rounded-xl p-4">
                <div className={`flex items-center gap-2 text-${color}-400 text-xs mb-2`}><Icon className="w-4 h-4" />{label}</div>
                <div className={`text-2xl font-bold text-${color}-300`}>{val}</div>
              </div>
            ))}
          </div>

          {/* Finding Classifications */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5">
              <h4 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2"><Shield className="w-4 h-4 text-cyan-400" />Finding Classifications</h4>
              <div className="grid grid-cols-3 gap-3 text-center">
                {[
                  { l: 'Confirmed', v: summary.classification_breakdown?.confirmed ?? summary.confirmed_findings ?? 0, c: 'emerald' },
                  { l: 'Potential', v: summary.classification_breakdown?.potential ?? summary.potential_findings ?? 0, c: 'amber' },
                  { l: 'Info', v: summary.classification_breakdown?.informational ?? summary.informational_findings ?? 0, c: 'blue' },
                ].map(({ l, v, c }) => (
                  <div key={l} className={`p-3 rounded-lg bg-${c}-950/20 border border-${c}-500/30`}>
                    <div className={`text-lg font-bold text-${c}-400`}>{v}</div>
                    <div className={`text-[11px] text-${c}-300 font-semibold`}>{l}</div>
                  </div>
                ))}
              </div>
            </div>
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5">
              <h4 className="text-sm font-semibold text-slate-200 mb-3">Detected Technologies</h4>
              <div className="flex flex-wrap gap-2">
                {((summary.detected_technologies ?? []) as string[]).map(t => (
                  <span key={t} className="px-2.5 py-1 rounded-md bg-cyan-950/50 border border-cyan-500/30 text-cyan-300 text-xs font-medium">{t}</span>
                ))}
                {!summary.detected_technologies?.length && <span className="text-slate-500 text-sm italic">Web Standard</span>}
              </div>
            </div>
          </div>

          {/* Sensitive secrets */}
          {(summary.sensitive_information_findings ?? []).length > 0 && (
            <Card title="🔑 Sensitive Information Detected" subtitle="All secret values are masked — never stored in cleartext">
              <div className="space-y-3">
                {(summary.sensitive_information_findings as any[]).map((f: any, i: number) => (
                  <div key={i} className="p-4 rounded-xl border border-red-500/40 bg-red-950/15 flex flex-col md:flex-row gap-3">
                    <div className="flex-1 space-y-1">
                      <div className="flex items-center gap-2">
                        <SevBadge label={f.severity} />
                        <span className="text-sm font-semibold text-slate-100 flex items-center gap-1.5">
                          <Lock className="w-3.5 h-3.5 text-red-400" />{f.type}
                        </span>
                      </div>
                      <div className="text-xs text-slate-300">File: <code className="text-cyan-300 bg-slate-900 px-1 rounded">{f.file_path}</code> Line: <strong>{f.line_number}</strong></div>
                      <div className="text-xs text-slate-400"><span className="text-emerald-400 font-semibold">Fix:</span> {f.recommended_remediation}</div>
                    </div>
                    <div className="bg-[#060a13] border border-slate-800 rounded-lg p-2 text-xs font-mono text-cyan-200 shrink-0">
                      <span className="text-slate-500 text-[10px] block">Masked:</span>{f.masked_value}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}

          <button onClick={() => pipeline.setStage('attack-surface')}
            className="w-full inline-flex items-center justify-center gap-2 px-6 py-4 rounded-xl bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white font-bold shadow-lg text-base">
            Continue → Step 2: Attack Surface Analysis <ArrowRight className="w-5 h-5" />
          </button>
        </div>
      )}

      {/* ═══ STAGE: attack-surface ══════════════════════════════════════ */}
      {stage === 'attack-surface' && (
        <div className="space-y-5">
          <div className="bg-[#0c1322] border border-indigo-500/40 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-indigo-500/15 border border-indigo-500/40 flex items-center justify-center">
                <Network className="w-5 h-5 text-indigo-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-100">Step 2 — Attack Surface Analysis</h3>
                <p className="text-xs text-slate-400">Mapping exposed technologies, monitored domains, and fingerprinted dependencies</p>
              </div>
            </div>
            {!busy && <button onClick={() => pipeline.setStage('validation')}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-bold">
              Next: Vulnerability Validation <ArrowRight className="w-4 h-4" />
            </button>}
          </div>

          {busy ? (
            <div className="flex items-center justify-center py-16">
              <div className="w-10 h-10 rounded-full border-4 border-slate-800 border-t-indigo-400 animate-spin" />
              <span className="ml-4 text-slate-400 text-sm">Loading attack surface…</span>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              <Card title="Monitored Domains & Scope">
                <div className="space-y-2">
                  {attackData?.targets.length ? attackData.targets.map((t: any) => (
                    <div key={t.id} className="border border-slate-800 rounded-lg p-3 bg-[#060a13]/70 flex justify-between text-xs">
                      <div>
                        <div className="text-sm font-medium text-slate-100">{t.domain}</div>
                        <div className="text-slate-400">{t.normalized_url}</div>
                      </div>
                      <span className={t.is_authorized ? 'text-emerald-400' : 'text-amber-400'}>{t.is_authorized ? 'Authorized' : 'Pending'}</span>
                    </div>
                  )) : (
                    <div className="py-6 text-center text-slate-500 text-sm">
                      <Network className="w-8 h-8 text-slate-700 mx-auto mb-2" />
                      No domains registered yet. Use Domain Scanner to add targets.
                    </div>
                  )}
                </div>
              </Card>
              <Card title="Fingerprinted Tech Stack">
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {attackData?.technologies.length ? attackData.technologies.map((t: any) => (
                    <div key={t.id} className="border border-slate-800 rounded-lg p-2.5 bg-[#060a13]/70 flex justify-between text-xs">
                      <span className="font-semibold text-cyan-300">{t.product_name} <span className="text-slate-400">{t.version ? `v${t.version}` : ''}</span></span>
                      <span className="text-slate-400">{t.detection_source}</span>
                    </div>
                  )) : (
                    <div className="py-4">
                      <p className="text-sm text-slate-500 mb-3">From code scan:</p>
                      <div className="flex flex-wrap gap-2">
                        {((summary.detected_technologies ?? []) as string[]).map(t => (
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
            <button onClick={() => pipeline.setStage('validation')}
              className="w-full inline-flex items-center justify-center gap-2 px-6 py-4 rounded-xl bg-gradient-to-r from-indigo-600 to-indigo-500 hover:from-indigo-500 hover:to-indigo-400 text-white font-bold shadow-lg text-base">
              Continue → Step 3: Vulnerability Validation <ArrowRight className="w-5 h-5" />
            </button>
          )}
        </div>
      )}

      {/* ═══ STAGE: validation ══════════════════════════════════════════ */}
      {stage === 'validation' && (
        <div className="space-y-5">
          <div className="bg-[#0c1322] border border-amber-500/40 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-amber-500/15 border border-amber-500/40 flex items-center justify-center">
                <ShieldCheck className="w-5 h-5 text-amber-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-100">Step 3 — Vulnerability Validation</h3>
                <p className="text-xs text-slate-400">{allVulns.length} findings — click any to see file path, line number & fix</p>
              </div>
            </div>
            {!busy && <button onClick={() => pipeline.setStage('ai-explain')}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-sm font-bold">
              Next: AI Explain <ArrowRight className="w-4 h-4" />
            </button>}
          </div>

          {busy ? (
            <div className="flex items-center justify-center py-16">
              <div className="w-10 h-10 rounded-full border-4 border-slate-800 border-t-amber-400 animate-spin" />
              <span className="ml-4 text-slate-400 text-sm">Loading vulnerability findings…</span>
            </div>
          ) : allVulns.length === 0 ? (
            <div className="bg-[#0c1322] border border-emerald-500/30 rounded-xl p-10 text-center">
              <ShieldCheck className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
              <h3 className="text-lg font-bold text-emerald-300">No Vulnerabilities Found!</h3>
              <p className="text-sm text-slate-400 mt-1">Your project passed the security audit with zero findings.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {allVulns.map(v => (
                <div key={v.id}
                  onClick={() => setSelectedVulnId(selectedVulnId === v.id ? null : v.id)}
                  className="border border-slate-800 hover:border-cyan-500/40 rounded-xl p-4 bg-[#060a13]/70 cursor-pointer transition-all">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <SevBadge label={v.severity} />
                        <span className="text-sm font-semibold text-slate-100 truncate">{v.title}</span>
                      </div>
                      <div className="text-xs text-slate-400 mt-1 font-mono truncate">
                        📂 {v.file_path || v.location?.split(':')[0] || v.location}
                        {v.line_number ? <span className="text-slate-300 font-bold ml-2">Line {v.line_number}</span> : null}
                      </div>
                    </div>
                    <div className="shrink-0 flex flex-col items-end gap-1">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${classificationStyle(v.classification)}`}>{v.classification}</span>
                      <span className="text-[11px] text-slate-500">{Math.round(v.confidence_score * 100)}% confidence</span>
                    </div>
                  </div>

                  {selectedVulnId === v.id && (
                    <div className="mt-3 pt-3 border-t border-slate-800 space-y-2">
                      {v.description && <p className="text-xs text-slate-300 leading-relaxed">{v.description}</p>}
                      {v.code_snippet && (
                        <div className="bg-[#060a13] border border-red-500/30 rounded-lg p-3">
                          <span className="text-[11px] text-red-400 font-semibold block mb-1">⚠ Vulnerable Code:</span>
                          <code className="text-xs font-mono text-red-200 whitespace-pre-wrap">{v.code_snippet}</code>
                        </div>
                      )}
                      {v.remediation_advice && (
                        <div className="bg-[#060a13] border border-emerald-500/30 rounded-lg p-3">
                          <span className="text-[11px] text-emerald-400 font-semibold block mb-1">✅ Recommended Fix:</span>
                          <p className="text-xs text-emerald-200 leading-relaxed">{v.remediation_advice}</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {!busy && (
            <button onClick={() => pipeline.setStage('ai-explain')}
              className="w-full inline-flex items-center justify-center gap-2 px-6 py-4 rounded-xl bg-gradient-to-r from-amber-600 to-amber-500 hover:from-amber-500 hover:to-amber-400 text-white font-bold shadow-lg text-base">
              Continue → Step 4: AI Security Assistant <ArrowRight className="w-5 h-5" />
            </button>
          )}
        </div>
      )}

      {/* ═══ STAGE: ai-explain ══════════════════════════════════════════ */}
      {stage === 'ai-explain' && (
        <div className="space-y-5">
          <div className="bg-[#0c1322] border border-violet-500/40 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-violet-500/15 border border-violet-500/40 flex items-center justify-center">
                <Bot className="w-5 h-5 text-violet-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-100">Step 4 — AI Security Assistant</h3>
                <p className="text-xs text-slate-400">Explaining all findings in plain language with actionable fixes</p>
              </div>
            </div>
          </div>

          <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 min-h-[220px]">
            {aiLoading ? (
              <div className="flex items-center gap-3 py-10 justify-center">
                <div className="w-6 h-6 rounded-full border-4 border-slate-700 border-t-violet-400 animate-spin" />
                <span className="text-slate-400 text-sm animate-pulse">AI analyzing {allVulns.length} vulnerabilities…</span>
              </div>
            ) : (
              aiMessages.map((m, i) => (
                <div key={i} className="bg-[#060a13] border border-violet-500/30 rounded-xl p-5">
                  <div className="flex items-center gap-2 mb-3">
                    <Bot className="w-4 h-4 text-violet-400" />
                    <span className="text-xs font-semibold text-violet-300 uppercase tracking-wide">Web Guard AI Security Assistant</span>
                  </div>
                  <div className="text-sm text-slate-200 whitespace-pre-wrap leading-relaxed">{m.text}</div>
                </div>
              ))
            )}
          </div>

          {!aiLoading && (
            <button onClick={() => pipeline.setStage('fix-prompt')}
              className="w-full inline-flex items-center justify-center gap-2 px-6 py-4 rounded-xl bg-gradient-to-r from-violet-600 to-violet-500 hover:from-violet-500 hover:to-violet-400 text-white font-bold shadow-lg text-base">
              I've Read the Explanation — What's Next? <ArrowRight className="w-5 h-5" />
            </button>
          )}
        </div>
      )}

      {/* ═══ STAGE: fix-prompt ══════════════════════════════════════════ */}
      {stage === 'fix-prompt' && (
        <div className="bg-[#0c1322] border border-cyan-500/40 rounded-2xl p-10 text-center">
          <div className="w-16 h-16 rounded-full bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center mx-auto mb-5">
            <Wrench className="w-8 h-8 text-cyan-400" />
          </div>
          <h2 className="text-2xl font-bold text-slate-100 mb-2">Do you want to fix the vulnerabilities?</h2>
          <p className="text-slate-400 text-sm max-w-lg mx-auto leading-relaxed">
            Web Guard AI can generate secure code patches for all{' '}
            <strong className="text-amber-300">{allVulns.filter(v => v.classification === 'CONFIRMED').length} confirmed</strong> vulnerabilities.
            Patches are shown as diff previews — <strong className="text-cyan-300">you must approve each one</strong> before any file is changed.
          </p>

          <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
            <button onClick={chooseYes}
              className="inline-flex items-center gap-3 px-10 py-4 rounded-xl bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 text-white text-lg font-bold shadow-xl shadow-emerald-500/30">
              <CheckCircle2 className="w-6 h-6" /> Yes, Fix It!
            </button>
            <button onClick={chooseNo}
              className="inline-flex items-center gap-3 px-10 py-4 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-lg font-bold">
              <FileText className="w-6 h-6 text-cyan-400" /> No, Just Show Report
            </button>
          </div>
        </div>
      )}

      {/* ═══ STAGE: remediation ════════════════════════════════════════ */}
      {stage === 'remediation' && (
        <div className="space-y-5">
          <div className="bg-[#0c1322] border border-emerald-500/40 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center">
                <Wrench className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-100">Step 5 — Remediation Center</h3>
                <p className="text-xs text-slate-400">Review secure patches — approve each fix before it's applied</p>
              </div>
            </div>
            <button onClick={() => pipeline.setStage('reports')}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-sm font-bold">
              Done — View Report <ArrowRight className="w-4 h-4" />
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
                <DiffViewer key={rec.id} record={rec}
                  onApprove={async (id, approved) => { await scannerApi.approveRemediation(id, approved); setRemRecords(await scannerApi.listRemediations()) }}
                  onVerify={async (id) => { await scannerApi.verifyRemediation(id); setRemRecords(await scannerApi.listRemediations()) }} />
              ))}
            </div>
          )}

          <button onClick={() => pipeline.setStage('reports')}
            className="w-full inline-flex items-center justify-center gap-2 px-6 py-4 rounded-xl bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 text-white font-bold shadow-lg text-base">
            All Done — View Final Security Report <ArrowRight className="w-5 h-5" />
          </button>
        </div>
      )}

      {/* ═══ STAGE: reports ════════════════════════════════════════════ */}
      {stage === 'reports' && (
        <div className="space-y-5">
          <div className="bg-[#0c1322] border border-cyan-500/40 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center">
                <FileText className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-100">Step 6 — Security Report</h3>
                <p className="text-xs text-slate-400">Full vulnerability report with file paths and exact line numbers</p>
              </div>
            </div>
            <button onClick={() => { pipeline.reset(); navigate('/import-project') }}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-sm">
              <Play className="w-3.5 h-3.5" /> Scan Another Project
            </button>
          </div>

          {/* Vuln table */}
          <Card title="Vulnerability Summary" subtitle="All findings — file location and line number">
            {allVulns.length === 0 ? (
              <div className="py-6 text-center text-slate-500 text-sm">No vulnerabilities found in this scan. 🎉</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-slate-300">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 text-left">
                      <th className="py-2 pr-3">Severity</th>
                      <th className="py-2 pr-3">Type</th>
                      <th className="py-2 pr-3">File</th>
                      <th className="py-2 pr-3">Line</th>
                      <th className="py-2">Classification</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {allVulns.map(v => (
                      <tr key={v.id} className="hover:bg-slate-800/20">
                        <td className="py-2 pr-3"><SevBadge label={v.severity} /></td>
                        <td className="py-2 pr-3 font-medium text-slate-100">{v.title}</td>
                        <td className="py-2 pr-3 font-mono text-cyan-300 max-w-[180px] truncate">{v.file_path || v.location?.split(':')[0] || '—'}</td>
                        <td className="py-2 pr-3 font-bold text-slate-200">{v.line_number ?? '—'}</td>
                        <td className="py-2"><span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${classificationStyle(v.classification)}`}>{v.classification}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          {/* Download Report */}
          <Card title="Download Full Report" subtitle="JSON, Markdown, or HTML — includes all evidence and line numbers">
            <div className="flex flex-wrap items-center gap-3">
              <select value={reportFormat} onChange={e => setReportFormat(e.target.value as typeof reportFormat)}
                className="bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100">
                <option value="markdown">Markdown (.md)</option>
                <option value="json">JSON (.json)</option>
                <option value="html">HTML Report (.html)</option>
              </select>
              <button onClick={generateReport} disabled={reportBusy}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold disabled:opacity-50">
                <FileText className="w-4 h-4" />{reportBusy ? 'Generating…' : 'Generate Report'}
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
                    <button onClick={() => downloadReport(r.filename)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-cyan-700 text-slate-200">
                      <Download className="w-3.5 h-3.5" /> Download
                    </button>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  )
}
