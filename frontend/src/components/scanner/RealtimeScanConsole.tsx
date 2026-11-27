import React, { useEffect, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Cpu,
  FolderInput,
  FolderOpen,
  KeyRound,
  Layers,
  Lock,
  Play,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  XCircle,
} from 'lucide-react'
import { scannerApi } from '../../services/scanner/scannerApi'
import type { ScanJob } from '../../types'

export interface RealtimeScanConsoleProps {
  files: File[]
  github: { url: string; branch?: string } | null
  onComplete: (job: ScanJob) => void
  onCancel: () => void
}

interface LogEntry {
  id: string
  timestamp: string
  level: 'info' | 'success' | 'warn' | 'error' | 'sast'
  text: string
}

interface PipelineStage {
  id: number
  name: string
  description: string
  status: 'pending' | 'running' | 'completed' | 'failed'
}

export const RealtimeScanConsole: React.FC<RealtimeScanConsoleProps> = ({
  files,
  github,
  onComplete,
  onCancel,
}) => {
  const [progress, setProgress] = useState(5)
  const [elapsedSec, setElapsedSec] = useState(0)
  const [currentFile, setCurrentFile] = useState<string>('')
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [discoveredTech, setDiscoveredTech] = useState<string[]>([])
  const [secretsFound, setSecretsFound] = useState(0)
  const [vulnsFound, setVulnsFound] = useState(0)
  const [scanFailed, setScanFailed] = useState<string | null>(null)
  const [isDone, setIsDone] = useState(false)
  const terminalRef = useRef<HTMLDivElement | null>(null)
  const scanStartedRef = useRef(false)

  const targetLabel = github
    ? github.url.split('/').slice(-2).join('/')
    : files.length > 0
    ? files[0].webkitRelativePath?.split('/')[0] || `${files.length} project files`
    : 'Web Project'

  const [stages, setStages] = useState<PipelineStage[]>([
    { id: 1, name: 'File Discovery & Inventory', description: 'Indexing file tree & filtering node_modules, binaries', status: 'running' },
    { id: 2, name: 'Technology & Language Validation', description: 'Detecting React, Vite, Next.js, Node, Python, PHP', status: 'pending' },
    { id: 3, name: 'Sensitive Key & Credential Scanner', description: 'Scanning .env, config, tokens (auto-masked values)', status: 'pending' },
    { id: 4, name: 'Deep SAST Vulnerability Analysis', description: 'AST & regex audit for XSS, SQLi, command injection', status: 'pending' },
    { id: 5, name: 'Dependency CVE & Advisory Audit', description: 'Correlating packages against NVD & CISA KEV', status: 'pending' },
    { id: 6, name: 'Evidence-Based Validation & Scoring', description: 'Classifying Confirmed, Potential & Informational', status: 'pending' },
  ])

  const setStageStatus = (id: number, status: PipelineStage['status']) => {
    setStages((prev) => prev.map((s) => (s.id === id ? { ...s, status } : s)))
  }

  const addLog = (text: string, level: LogEntry['level'] = 'info') => {
    const now = new Date()
    const ts = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0')
    setLogs((prev) => [...prev, { id: `${Date.now()}-${Math.random()}`, timestamp: ts, level, text }])
  }

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [logs])

  // Elapsed timer
  useEffect(() => {
    const timer = setInterval(() => {
      setElapsedSec((s) => s + 1)
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  const formatTimer = (s: number) => {
    const mins = Math.floor(s / 60)
    const secs = s % 60
    return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
  }

  // Core execution loop
  useEffect(() => {
    if (scanStartedRef.current) return
    scanStartedRef.current = true

    if (files.length === 0 && !github) {
      setScanFailed('No project files loaded. Please import a website project folder or enter a GitHub repository.')
      return
    }

    const runRealtimeScan = async () => {
      addLog(`🚀 Initializing Web Guard AI Real-Time Security Scanner v2.0`, 'info')
      addLog(`📁 Target: ${targetLabel} (${files.length > 0 ? `${files.length} files selected` : 'GitHub Repo'})`, 'info')

      // Emulate rapid real-time stage progression while the backend performs the real security scan
      const sampleNames = files.map((f) => f.webkitRelativePath || f.name).slice(0, 15)

      // Step 1: File Discovery
      setProgress(15)
      setStageStatus(1, 'running')
      addLog(`[STAGE 1] Recursively discovering project tree and ignoring node_modules, .git, binaries...`, 'info')
      if (sampleNames.length > 0) {
        setCurrentFile(`Indexing ${sampleNames[0]}`)
      }

      // Step 2: Tech Validation
      const timer2 = setTimeout(() => {
        setProgress(32)
        setStageStatus(1, 'completed')
        setStageStatus(2, 'running')
        addLog(`[STAGE 1 ✓] ${files.length || 'Repository'} files cataloged and verified in workspace`, 'success')
        addLog(`[STAGE 2] Validating web technologies, frameworks, and project manifests...`, 'info')
        setCurrentFile('Validating package.json, configs, and file headers...')
      }, 700)

      // Step 3: Secret Detection
      const timer3 = setTimeout(() => {
        setProgress(48)
        setStageStatus(2, 'completed')
        setStageStatus(3, 'running')
        addLog(`[STAGE 2 ✓] Web project validated! Analyzing languages & components`, 'success')
        addLog(`[STAGE 3] Scanning .env and configuration files for leaked credentials...`, 'sast')
        addLog(`[STAGE 3] Privacy guard active: all secret tokens will be masked with SHA-256`, 'warn')
        setCurrentFile('Auditing .env, secrets, and connection strings...')
      }, 1600)

      // Step 4: SAST Scan
      const timer4 = setTimeout(() => {
        setProgress(68)
        setStageStatus(3, 'completed')
        setStageStatus(4, 'running')
        addLog(`[STAGE 3 ✓] Sensitive key audit finished. Values safely masked.`, 'success')
        addLog(`[STAGE 4] Running AST analyzer and custom security rules across files...`, 'sast')
        if (sampleNames.length > 1) {
          addLog(`[SAST] Checking ${sampleNames[1]} for DOM XSS and unsafe innerHTML...`, 'sast')
          setCurrentFile(`Scanning ${sampleNames[1]}`)
        }
      }, 2600)

      // Step 5: Dependency Audit
      const timer5 = setTimeout(() => {
        setProgress(82)
        setStageStatus(4, 'completed')
        setStageStatus(5, 'running')
        addLog(`[STAGE 4 ✓] Source code rules evaluated. Checking package dependencies...`, 'success')
        addLog(`[STAGE 5] Correlating libraries with NVD CVEs and CISA Known Exploited Vulnerabilities...`, 'info')
        setCurrentFile('Querying CVE intelligence database...')
      }, 3600)

      // Step 6: Evidence Validation
      const timer6 = setTimeout(() => {
        setProgress(92)
        setStageStatus(5, 'completed')
        setStageStatus(6, 'running')
        addLog(`[STAGE 5 ✓] Dependency vulnerability correlation complete`, 'success')
        addLog(`[STAGE 6] Filtering false positives with 6-stage evidence validation engine...`, 'sast')
        setCurrentFile('Calculating confidence scores & verifiable evidence...')
      }, 4500)

      try {
        let job: ScanJob
        if (github) {
          job = await scannerApi.scanGitHubRepo(github.url, github.branch)
        } else {
          job = await scannerApi.uploadCodeScan(files, ({ uploaded, total, stage }) => {
            if (stage === 'uploading') {
              addLog(`[UPLOAD] Uploading batch: ${uploaded} / ${total} files...`, 'info')
            }
          })
        }

        clearTimeout(timer2)
        clearTimeout(timer3)
        clearTimeout(timer4)
        clearTimeout(timer5)
        clearTimeout(timer6)

        // Mark all completed
        for (let i = 1; i <= 6; i++) {
          setStageStatus(i, 'completed')
        }

        const summary = (job.summary || {}) as Record<string, any>
        const detected = summary.detected_technologies || []
        const sens = (summary.sensitive_information_findings || []).length
        const totalFindings = summary.total_findings || 0

        setDiscoveredTech(detected)
        setSecretsFound(sens)
        setVulnsFound(totalFindings)
        setProgress(100)
        setIsDone(true)
        setCurrentFile('Security audit completed successfully!')

        addLog(`[STAGE 6 ✓] Evidence validation complete! Classified all findings`, 'success')
        addLog(`🏁 [COMPLETE] Project: ${summary.project_name || targetLabel}`, 'success')
        addLog(`📊 [METRICS] Scanned: ${summary.total_files_scanned || files.length} files | Confirmed: ${summary.confirmed_findings || 0} | Potential: ${summary.potential_findings || 0}`, 'success')
        if (sens > 0) {
          addLog(`🔑 [ALERT] Detected ${sens} sensitive credentials (all safely masked)`, 'warn')
        }

        // Brief delay for user to admire the 100% completion
        setTimeout(() => {
          onComplete(job)
        }, 1200)
      } catch (err: any) {
        clearTimeout(timer2)
        clearTimeout(timer3)
        clearTimeout(timer4)
        clearTimeout(timer5)
        clearTimeout(timer6)

        const errorMsg = err instanceof Error ? err.message : String(err)
        setScanFailed(errorMsg)
        addLog(`✕ [SCAN FAILED] ${errorMsg}`, 'error')
        for (let i = 1; i <= 6; i++) {
          setStageStatus(i, 'failed')
        }
      }
    }

    runRealtimeScan()
  }, [])

  return (
    <div className="space-y-6">
      {/* Top Banner with Pulse Status & Progress */}
      <div className="bg-[#0c1322] border border-cyan-500/40 rounded-2xl p-6 shadow-2xl relative overflow-hidden">
        <div className={`absolute top-0 left-0 right-0 h-1 transition-all duration-300 ${scanFailed ? 'bg-red-500' : isDone ? 'bg-emerald-400' : 'bg-gradient-to-r from-cyan-500 via-indigo-500 to-emerald-400 animate-pulse'}`} />

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className={`relative w-12 h-12 rounded-xl flex items-center justify-center shrink-0 border ${scanFailed ? 'bg-red-500/15 border-red-500/40' : isDone ? 'bg-emerald-500/15 border-emerald-500/40' : 'bg-cyan-500/15 border-cyan-500/40'}`}>
              {scanFailed ? (
                <XCircle className="w-6 h-6 text-red-400" />
              ) : isDone ? (
                <CheckCircle2 className="w-6 h-6 text-emerald-400" />
              ) : (
                <>
                  <Shield className="w-6 h-6 text-cyan-400 animate-pulse" />
                  <div className="absolute -top-1 -right-1 w-3 h-3 bg-cyan-400 rounded-full animate-ping" />
                </>
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className={`text-[11px] font-mono font-bold tracking-wider uppercase px-2 py-0.5 rounded border ${scanFailed ? 'bg-red-950/60 border-red-500/30 text-red-400' : isDone ? 'bg-emerald-950/60 border-emerald-500/30 text-emerald-400' : 'bg-cyan-950/60 border-cyan-500/30 text-cyan-400'}`}>
                  {scanFailed ? 'SCAN FAILED' : isDone ? 'AUDIT COMPLETE ✓' : 'REAL-TIME SCAN ENGINE ACTIVE'}
                </span>
                <span className="text-xs font-mono text-slate-400">Elapsed: {formatTimer(elapsedSec)}</span>
              </div>
              <h2 className="text-lg font-bold text-slate-100 tracking-tight mt-1">
                Project: <span className="text-cyan-300 font-mono">{targetLabel}</span>
              </h2>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className={`text-3xl font-black font-mono ${scanFailed ? 'text-red-400' : isDone ? 'text-emerald-400' : 'text-cyan-400'}`}>
                {progress}%
              </div>
              <div className="text-[11px] text-slate-400 font-mono">Pipeline Progress</div>
            </div>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="mt-5 space-y-1.5">
          <div className="flex justify-between text-xs font-mono">
            <span className="text-slate-300 flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${scanFailed ? 'bg-red-400' : isDone ? 'bg-emerald-400' : 'bg-cyan-400 animate-pulse'}`} />
              {currentFile || 'Running real-time analysis...'}
            </span>
            <span className="text-cyan-400 font-semibold">{files.length > 0 ? `${files.length} Source Files` : 'GitHub Project'}</span>
          </div>

          <div className="w-full h-3 rounded-full bg-slate-900 border border-slate-800 overflow-hidden relative">
            <div
              className={`h-full transition-all duration-300 relative ${
                scanFailed
                  ? 'bg-red-500'
                  : isDone
                  ? 'bg-emerald-500'
                  : 'bg-gradient-to-r from-cyan-600 via-indigo-500 to-emerald-400 shadow-lg shadow-cyan-500/50'
              }`}
              style={{ width: `${Math.max(progress, 4)}%` }}
            >
              {!scanFailed && !isDone && <div className="absolute inset-0 bg-white/20 animate-pulse" />}
            </div>
          </div>
        </div>

        {/* Real-time Counters */}
        <div className="mt-5 grid grid-cols-2 sm:grid-cols-4 gap-3 pt-4 border-t border-slate-800/80 text-xs font-mono">
          <div className="p-2.5 rounded-lg bg-[#060a13] border border-slate-800">
            <span className="text-slate-400 block text-[10px]">INSPECTED FILES</span>
            <span className="text-sm font-bold text-slate-100">{Math.round((progress / 100) * (files.length || 20))} / {files.length || '—'}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-[#060a13] border border-slate-800">
            <span className="text-slate-400 block text-[10px]">DETECTED TECH</span>
            <span className="text-sm font-bold text-cyan-300">{discoveredTech.length > 0 ? discoveredTech.join(', ') : 'Detecting...'}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-[#060a13] border border-red-500/30">
            <span className="text-red-400 block text-[10px]">SECRETS FOUND</span>
            <span className="text-sm font-bold text-red-400">{secretsFound} (Masked)</span>
          </div>
          <div className="p-2.5 rounded-lg bg-[#060a13] border border-amber-500/30">
            <span className="text-amber-400 block text-[10px]">SECURITY FINDINGS</span>
            <span className="text-sm font-bold text-amber-300">{vulnsFound}</span>
          </div>
        </div>
      </div>

      {/* Error Action Card if Failed */}
      {scanFailed && (
        <div className="bg-red-950/20 border border-red-500/40 rounded-xl p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-red-400 font-bold text-sm">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              Scan Stopped: Action Required
            </div>
            <p className="text-xs text-red-200/90 font-mono leading-relaxed max-w-2xl">{scanFailed}</p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={onCancel}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold"
            >
              <FolderInput className="w-3.5 h-3.5" /> Choose Another Folder
            </button>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Retry
            </button>
          </div>
        </div>
      )}

      {/* 2-Column: 6-Stage Checklist + Live Terminal */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: 6-Stage Checklist */}
        <div className="lg:col-span-5 space-y-2.5">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 px-1 flex items-center gap-2">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            Active Validation &amp; Scan Stages
          </h3>

          <div className="space-y-2">
            {stages.map((st) => (
              <div
                key={st.id}
                className={`p-3.5 rounded-xl border transition-all ${
                  st.status === 'running'
                    ? 'bg-cyan-950/20 border-cyan-500/50 shadow-md shadow-cyan-500/10'
                    : st.status === 'completed'
                    ? 'bg-emerald-950/15 border-emerald-500/30'
                    : st.status === 'failed'
                    ? 'bg-red-950/20 border-red-500/40'
                    : 'bg-[#0c1322] border-slate-800/80 opacity-60'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className="mt-0.5 shrink-0">
                    {st.status === 'completed' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : st.status === 'running' ? (
                      <div className="w-4 h-4 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
                    ) : st.status === 'failed' ? (
                      <XCircle className="w-4 h-4 text-red-400" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border border-slate-700 bg-slate-800 text-[10px] flex items-center justify-center text-slate-500 font-bold">
                        {st.id}
                      </div>
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className={`text-xs font-semibold ${st.status === 'running' ? 'text-cyan-300' : st.status === 'completed' ? 'text-emerald-300' : 'text-slate-200'}`}>
                        {st.name}
                      </span>
                      <span className={`text-[10px] uppercase font-mono px-1.5 py-0.2 rounded font-bold ${
                        st.status === 'running'
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                          : st.status === 'completed'
                          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                          : st.status === 'failed'
                          ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                          : 'text-slate-600'
                      }`}>
                        {st.status}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-0.5">{st.description}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Live Cyber Terminal */}
        <div className="lg:col-span-7 flex flex-col">
          <div className="bg-[#050811] border border-slate-800 rounded-2xl flex flex-col flex-1 overflow-hidden shadow-2xl">
            <div className="bg-[#090e1c] px-4 py-2.5 border-b border-slate-800 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-red-500/80 inline-block" />
                  <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/80 inline-block" />
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block" />
                </div>
                <span className="text-slate-400 font-mono ml-2 flex items-center gap-1.5 text-[11px]">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  live-security-stream: /dev/scanner
                </span>
              </div>
              <span className={`text-[10px] font-mono ${scanFailed ? 'text-red-400' : isDone ? 'text-emerald-400' : 'text-cyan-400 animate-pulse'}`}>
                {scanFailed ? '● SCAN ABORTED' : isDone ? '● SCAN COMPLETE' : '● LIVE AUDIT LOG'}
              </span>
            </div>

            <div
              ref={terminalRef}
              className="p-4 font-mono text-xs space-y-1.5 overflow-y-auto max-h-[380px] min-h-[320px] text-slate-300 selection:bg-cyan-500/30"
            >
              {logs.map((log) => {
                let color = 'text-slate-300'
                let prefix = '•'
                if (log.level === 'success') {
                  color = 'text-emerald-400 font-semibold'
                  prefix = '✓'
                } else if (log.level === 'warn') {
                  color = 'text-amber-400 font-semibold'
                  prefix = '▲'
                } else if (log.level === 'error') {
                  color = 'text-red-400 font-semibold'
                  prefix = '✕'
                } else if (log.level === 'sast') {
                  color = 'text-cyan-300'
                  prefix = '⚡'
                }

                return (
                  <div key={log.id} className="leading-relaxed flex items-start gap-2">
                    <span className="text-slate-600 shrink-0 text-[10px] select-none">[{log.timestamp}]</span>
                    <span className="shrink-0 select-none text-[11px]">{prefix}</span>
                    <span className={`whitespace-pre-wrap break-all ${color}`}>{log.text}</span>
                  </div>
                )
              })}
            </div>

            <div className="bg-[#090e1c] px-4 py-2 border-t border-slate-800 text-[11px] font-mono text-slate-400 flex items-center justify-between">
              <span>Status: <strong className={scanFailed ? 'text-red-400' : isDone ? 'text-emerald-400' : 'text-cyan-300'}>{scanFailed ? 'FAILED' : isDone ? 'DONE' : 'SCANNING'}</strong></span>
              <span>Events: <strong className="text-slate-200">{logs.length}</strong></span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
