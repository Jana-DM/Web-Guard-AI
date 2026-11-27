import React, { useState } from 'react'
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Cpu,
  FileCode2,
  FolderOpen,
  GitBranch,
  KeyRound,
  Layers,
  Lock,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Wrench,
  XCircle,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Card, ErrorBanner } from '../../components/common/UIPrimitives'
import { CodeUploadDropzone } from '../../components/scanner/CodeUploadDropzone'
import { scannerApi } from '../../services/scanner/scannerApi'
import type { ScanJob } from '../../types'

type ScanMode = 'choose' | 'folder' | 'github'

export const CodeScannerPage: React.FC = () => {
  const navigate = useNavigate()
  const [mode, setMode] = useState<ScanMode>('choose')
  const [repoUrl, setRepoUrl] = useState('')
  const [branch, setBranch] = useState('')
  const [loading, setLoading] = useState(false)
  const [progressText, setProgressText] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ScanJob | null>(null)

  const handleUpload = async (files: File[]) => {
    setLoading(true)
    setError(null)
    setResult(null)
    setProgressText(`Validating project folder (${files.length} files)...`)
    try {
      const scanJob = await scannerApi.uploadCodeScan(files, ({ uploaded, total, stage }) => {
        if (stage === 'uploading') {
          setProgressText(`Uploading project batch: ${uploaded} / ${total} files...`)
        } else {
          setProgressText(`Validating web technologies & running multi-stage security audit across ${total} files...`)
        }
      })
      setResult(scanJob)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Project scan failed')
    } finally {
      setLoading(false)
      setProgressText(null)
    }
  }

  const handleGitHubScan = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await scannerApi.scanGitHubRepo(repoUrl, branch || undefined))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'GitHub repository scan failed')
    } finally {
      setLoading(false)
    }
  }

  const switchMode = (nextMode: ScanMode) => {
    setMode(nextMode)
    setError(null)
  }

  const summary = (result?.summary || {}) as Record<string, any>
  const projectName = summary.project_name || result?.target_label || 'Web Project'
  const validationStatus = summary.validation_status || (result ? 'VALIDATED' : null)
  const detectedFrameworks: string[] = summary.detected_frameworks || []
  const detectedBackend: string[] = summary.detected_backend || []
  const detectedTech: string[] = summary.detected_technologies || []
  const supportedLangs: string[] = summary.supported_languages || []
  const inventory = summary.inventory || {}
  const totalDiscovered = summary.total_files_discovered ?? inventory.total_discovered ?? 0
  const totalScanned = summary.total_files_scanned ?? inventory.total_scanned ?? 0
  const totalExcluded = summary.total_files_excluded ?? inventory.total_excluded ?? 0
  const excludedDetails: Record<string, number> = summary.excluded_details || inventory.excluded_breakdown || {}

  const sensitiveFindings: Array<{
    file_name: string
    file_path: string
    line_number: number
    type: string
    severity: string
    detection_reason: string
    recommended_remediation: string
    masked_value: string
  }> = summary.sensitive_information_findings || []

  const severityBreakdown = summary.severity_breakdown || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  }

  const classBreakdown = summary.classification_breakdown || {
    confirmed: summary.confirmed_findings || 0,
    potential: summary.potential_findings || 0,
    informational: summary.informational_findings || 0,
  }

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onClose={() => setError(null)} />}

      {mode === 'choose' ? (
        <Card
          title="Select Website Project Source"
          subtitle="Choose whether to scan a project folder on your device or a public GitHub repository"
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5 pt-2">
            <button
              type="button"
              onClick={() => switchMode('folder')}
              className="group text-left p-6 rounded-xl border border-slate-800 bg-[#060a13]/70 hover:border-cyan-500/70 hover:bg-cyan-950/15 transition-all"
            >
              <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mb-4 group-hover:bg-cyan-500/20">
                <FolderOpen className="w-6 h-6 text-cyan-400" />
              </div>
              <h4 className="text-base font-semibold text-slate-100">Scan Website Project Folder or ZIP</h4>
              <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                Upload or select an entire website project folder (React, Vite, Next.js, Node, Python, PHP, HTML) or a ZIP archive.
              </p>
              <span className="inline-block mt-4 text-xs font-semibold text-cyan-400 group-hover:translate-x-0.5 transition-transform">
                Browse Project Folder →
              </span>
            </button>

            <button
              type="button"
              onClick={() => switchMode('github')}
              className="group text-left p-6 rounded-xl border border-slate-800 bg-[#060a13]/70 hover:border-cyan-500/70 hover:bg-cyan-950/15 transition-all"
            >
              <div className="w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center mb-4 group-hover:bg-indigo-500/20">
                <GitBranch className="w-6 h-6 text-indigo-400" />
              </div>
              <h4 className="text-base font-semibold text-slate-100">Scan Public GitHub Repository</h4>
              <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                Validate technologies, inspect sensitive information in .env, and perform comprehensive security analysis.
              </p>
              <span className="inline-block mt-4 text-xs font-semibold text-indigo-400 group-hover:translate-x-0.5 transition-transform">
                Enter GitHub Repo →
              </span>
            </button>
          </div>
        </Card>
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <button
              type="button"
              onClick={() => switchMode('choose')}
              className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 hover:text-cyan-400 transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              Back to Scan Options
            </button>

            <div className="inline-flex rounded-lg border border-slate-800 bg-[#060a13] p-1">
              <button
                type="button"
                onClick={() => switchMode('folder')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  mode === 'folder' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <FolderOpen className="w-3.5 h-3.5" />
                Device Folder / Files
              </button>
              <button
                type="button"
                onClick={() => switchMode('github')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  mode === 'github' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <GitBranch className="w-3.5 h-3.5" />
                GitHub Repo
              </button>
            </div>
          </div>

          {mode === 'folder' ? (
            <Card
              title="Intelligent Web Project Validation &amp; Security Scanner"
              subtitle="Step 1: Technology Validation → Step 2: Sensitive Information Detection → Step 3: Complete Security Audit"
            >
              <CodeUploadDropzone
                onUpload={handleUpload}
                onValidationError={(msg) => {
                  setResult(null)
                  setError(msg)
                }}
                loading={loading}
                progressText={progressText}
              />
            </Card>
          ) : (
            <Card
              title="Scan Public GitHub Repository"
              subtitle="Shallow static clone with git hooks disabled, pre-validated for web content &amp; sensitive-file protection"
            >
              <form onSubmit={handleGitHubScan} className="space-y-4 max-w-2xl">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1.5">Repository URL</label>
                  <input
                    type="url"
                    required
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/repository"
                    className="w-full bg-[#060a13] border border-slate-700 rounded-lg px-3.5 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1.5">Branch (Optional)</label>
                  <input
                    type="text"
                    value={branch}
                    onChange={(e) => setBranch(e.target.value)}
                    placeholder="Default repository branch (e.g. main)"
                    className="w-full bg-[#060a13] border border-slate-700 rounded-lg px-3.5 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold disabled:opacity-50"
                >
                  <GitBranch className="w-4 h-4" />
                  {loading ? 'Validating &amp; Scanning Repo...' : 'Scan GitHub Repo'}
                </button>
              </form>
            </Card>
          )}
        </div>
      )}

      {/* STEP 6: PROFESSIONAL CYBERSECURITY DASHBOARD */}
      {result && (
        <div className="space-y-6 pt-2">
          {/* Top Status Banner */}
          <div className="bg-[#0c1322] border border-cyan-500/30 rounded-xl p-5 shadow-xl">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-3">
                  <h3 className="text-xl font-bold text-slate-100">{projectName}</h3>
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    Status: {validationStatus}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Scan ID: <code className="text-cyan-300">{result.id}</code> • Completed at {new Date().toLocaleTimeString()}
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => navigate('/validation')}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md transition-colors"
                >
                  <ShieldCheck className="w-4 h-4" />
                  View All Findings in Validation ({summary.total_findings || 0}) →
                </button>
                <button
                  type="button"
                  onClick={() => navigate('/remediation')}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold transition-colors"
                >
                  <Wrench className="w-4 h-4 text-cyan-400" />
                  Safe Remediation Center
                </button>
              </div>
            </div>

            {/* Technology & Framework Badges */}
            <div className="mt-5 pt-4 border-t border-slate-800/80 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div>
                <span className="text-slate-400 font-medium block mb-2">Detected Technologies &amp; Frameworks:</span>
                <div className="flex flex-wrap gap-1.5">
                  {detectedTech.length > 0 ? (
                    detectedTech.map((tech) => (
                      <span key={tech} className="px-2.5 py-1 rounded-md bg-cyan-950/50 border border-cyan-500/30 text-cyan-300 font-medium">
                        {tech}
                      </span>
                    ))
                  ) : (
                    <span className="text-slate-500 italic">Web Standard Technologies</span>
                  )}
                </div>
              </div>

              <div>
                <span className="text-slate-400 font-medium block mb-2">Supported Project Languages:</span>
                <div className="flex flex-wrap gap-1.5">
                  {supportedLangs.length > 0 ? (
                    supportedLangs.map((lang) => (
                      <span key={lang} className="px-2.5 py-1 rounded-md bg-indigo-950/50 border border-indigo-500/30 text-indigo-300 font-medium">
                        {lang}
                      </span>
                    ))
                  ) : (
                    <span className="text-slate-500 italic">General Web</span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Metrics Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-4">
              <div className="flex items-center gap-2 text-slate-400 text-xs">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span>Files Discovered</span>
              </div>
              <div className="text-2xl font-bold text-slate-100 mt-2">{totalDiscovered}</div>
              <div className="text-[11px] text-slate-500 mt-0.5">Recursive project scan</div>
            </div>

            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-4">
              <div className="flex items-center gap-2 text-slate-400 text-xs">
                <FileCode2 className="w-4 h-4 text-emerald-400" />
                <span>Files Scanned</span>
              </div>
              <div className="text-2xl font-bold text-emerald-400 mt-2">{totalScanned}</div>
              <div className="text-[11px] text-slate-500 mt-0.5">Source &amp; configuration files</div>
            </div>

            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-4">
              <div className="flex items-center gap-2 text-slate-400 text-xs">
                <XCircle className="w-4 h-4 text-slate-400" />
                <span>Excluded Files</span>
              </div>
              <div className="text-2xl font-bold text-slate-400 mt-2">{totalExcluded}</div>
              <div className="text-[11px] text-slate-500 mt-0.5">node_modules, git, binaries</div>
            </div>

            <div className="bg-[#0c1322] border border-red-500/30 rounded-xl p-4 bg-red-950/10">
              <div className="flex items-center gap-2 text-red-400 text-xs">
                <KeyRound className="w-4 h-4 text-red-400" />
                <span>Sensitive Secrets</span>
              </div>
              <div className="text-2xl font-bold text-red-400 mt-2">{sensitiveFindings.length}</div>
              <div className="text-[11px] text-red-300/70 mt-0.5">Masked for privacy</div>
            </div>
          </div>

          {/* Classification & Severity Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Finding Classifications */}
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5">
              <h4 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyan-400" />
                Evidence-Based Classifications
              </h4>
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/30 text-center">
                  <div className="text-lg font-bold text-emerald-400">{classBreakdown.confirmed}</div>
                  <div className="text-[11px] font-semibold text-emerald-300 mt-0.5">Confirmed</div>
                  <div className="text-[10px] text-slate-400 mt-1">Strong verifiable proof</div>
                </div>
                <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-500/30 text-center">
                  <div className="text-lg font-bold text-amber-400">{classBreakdown.potential}</div>
                  <div className="text-[11px] font-semibold text-amber-300 mt-0.5">Potential</div>
                  <div className="text-[10px] text-slate-400 mt-1">Manual review advised</div>
                </div>
                <div className="p-3 rounded-lg bg-blue-950/20 border border-blue-500/30 text-center">
                  <div className="text-lg font-bold text-blue-400">{classBreakdown.informational}</div>
                  <div className="text-[11px] font-semibold text-blue-300 mt-0.5">Informational</div>
                  <div className="text-[10px] text-slate-400 mt-1">Security hardening</div>
                </div>
              </div>
            </div>

            {/* Severity Distribution */}
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5">
              <h4 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Severity Breakdown
              </h4>
              <div className="grid grid-cols-4 gap-2 text-center text-xs">
                <div className="p-2.5 rounded-lg bg-red-950/30 border border-red-500/40">
                  <div className="font-bold text-red-400 text-base">{severityBreakdown.critical}</div>
                  <div className="text-[10px] font-semibold text-red-300 uppercase mt-0.5">Critical</div>
                </div>
                <div className="p-2.5 rounded-lg bg-orange-950/30 border border-orange-500/40">
                  <div className="font-bold text-orange-400 text-base">{severityBreakdown.high}</div>
                  <div className="text-[10px] font-semibold text-orange-300 uppercase mt-0.5">High</div>
                </div>
                <div className="p-2.5 rounded-lg bg-yellow-950/30 border border-yellow-500/40">
                  <div className="font-bold text-yellow-400 text-base">{severityBreakdown.medium}</div>
                  <div className="text-[10px] font-semibold text-yellow-300 uppercase mt-0.5">Medium</div>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-800/40 border border-slate-700">
                  <div className="font-bold text-slate-300 text-base">{severityBreakdown.low + severityBreakdown.info}</div>
                  <div className="text-[10px] font-semibold text-slate-400 uppercase mt-0.5">Low/Info</div>
                </div>
              </div>
            </div>
          </div>

          {/* SENSITIVE INFORMATION REPORT (STEP 2 REQUIREMENT) */}
          {sensitiveFindings.length > 0 && (
            <Card
              title="Step 2: Sensitive Information Detection Report"
              subtitle="Scanned across all files including .env — secrets are masked for privacy and never exposed in cleartext"
            >
              <div className="space-y-3 pt-1">
                {sensitiveFindings.map((finding, idx) => (
                  <div
                    key={`${finding.file_path}-${finding.line_number}-${idx}`}
                    className="p-4 rounded-xl border border-red-500/40 bg-red-950/15 flex flex-col md:flex-row md:items-start justify-between gap-4"
                  >
                    <div className="space-y-1.5 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-red-600 text-white uppercase tracking-wider">
                          {finding.severity}
                        </span>
                        <span className="text-sm font-semibold text-slate-100 flex items-center gap-1.5">
                          <Lock className="w-3.5 h-3.5 text-red-400" />
                          {finding.type}
                        </span>
                      </div>
                      <div className="text-xs text-slate-300">
                        File: <code className="text-cyan-300 font-mono bg-slate-900 px-1.5 py-0.5 rounded">{finding.file_path}</code> Line: <span className="font-bold text-slate-200">{finding.line_number}</span>
                      </div>
                      <div className="text-xs text-slate-400">
                        <strong className="text-slate-300">Detection Reason:</strong> {finding.detection_reason}
                      </div>
                      <div className="text-xs text-slate-400">
                        <strong className="text-emerald-400">Recommended Remediation:</strong> {finding.recommended_remediation}
                      </div>
                    </div>

                    <div className="bg-[#060a13] border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-cyan-200 shrink-0">
                      <span className="text-slate-500 text-[10px] block">Masked Secret Value:</span>
                      {finding.masked_value}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Excluded Files Inventory breakdown */}
          {Object.keys(excludedDetails).length > 0 && (
            <div className="p-4 rounded-xl bg-[#0c1322] border border-slate-800 text-xs text-slate-400 flex flex-wrap items-center justify-between gap-3">
              <span className="font-medium text-slate-300">Excluded Directories &amp; Files:</span>
              <div className="flex flex-wrap gap-2">
                {Object.entries(excludedDetails).map(([k, v]) => (
                  <span key={k} className="px-2 py-0.5 rounded bg-slate-800/80 text-slate-300">
                    {k}: <strong className="text-cyan-300">{v}</strong>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
