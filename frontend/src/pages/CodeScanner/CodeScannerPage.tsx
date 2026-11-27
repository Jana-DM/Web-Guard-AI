import React, { useState } from 'react'
import { ArrowLeft, CheckCircle2, FolderOpen, GitBranch, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Card, ErrorBanner } from '../../components/common/UIPrimitives'
import { CodeUploadDropzone, type UploadMetadata } from '../../components/scanner/CodeUploadDropzone'
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

  const handleUpload = async (files: File[], metadata: UploadMetadata) => {
    setLoading(true)
    setError(null)
    setResult(null)
    setProgressText(`Validating & preparing ${files.length} web file(s)...`)
    try {
      const scanJob = await scannerApi.uploadCodeScan(
        files,
        ({ uploaded, total, stage }) => {
          if (stage === 'uploading') {
            setProgressText(`Uploading folder batch: ${uploaded} / ${total} files...`)
          } else {
            setProgressText(`Running static security analysis across ${total} web file(s)...`)
          }
        },
        metadata
      )
      setResult(scanJob)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Code scan failed')
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
      setError(err instanceof Error ? err.message : 'GitHub scan failed')
    } finally {
      setLoading(false)
    }
  }

  const switchMode = (nextMode: ScanMode) => {
    setMode(nextMode)
    setError(null)
  }

  const sensitiveDetected = (result?.summary?.sensitive_detected as string[] | undefined) || []
  const skippedNonWeb = (result?.summary?.skipped_non_web as Record<string, number> | undefined) || {}

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onClose={() => setError(null)} />}

      {mode === 'choose' ? (
        <Card
          title="Select Code Scan Source"
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
              <h4 className="text-base font-semibold text-slate-100">Scan Folder or Files (Device)</h4>
              <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                Pick a local project folder, web files (HTML, CSS, JS, TS, Python, PHP), or ZIP straight from your computer.
              </p>
              <span className="inline-block mt-4 text-xs font-semibold text-cyan-400 group-hover:translate-x-0.5 transition-transform">
                Choose Local Folder →
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
              <h4 className="text-base font-semibold text-slate-100">Scan GitHub Repository</h4>
              <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                Validates web content, excludes sensitive files/folders without inspection, and runs static security analysis.
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
              title="Scan Project Folder or Files from Device"
              subtitle="Only valid web/source files are analyzed; media-only folders are rejected and sensitive items are never inspected or stored"
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
              subtitle="Shallow static clone with git hooks disabled, pre-validated for web content & sensitive-file protection"
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
                  {loading ? 'Validating & Scanning Repo...' : 'Scan GitHub Repo'}
                </button>
              </form>
            </Card>
          )}
        </div>
      )}

      {result && (
        <Card
          title="Static Code Analysis Completed"
          subtitle={`Target: ${result.target_label} • Scan ID: ${result.id}`}
          action={
            <button
              type="button"
              onClick={() => navigate('/validation')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-600/30 text-xs font-semibold"
            >
              <ShieldCheck className="w-4 h-4" />
              View Findings in Validation →
            </button>
          }
        >
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-xs text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
              <span>Scan completed and validated through the 6-stage pipeline.</span>
            </div>

            {sensitiveDetected.length > 0 && (
              <div className="p-3.5 rounded-lg bg-amber-950/40 border border-amber-500/40 text-xs text-amber-200">
                <div className="flex items-center gap-2 font-semibold text-amber-300">
                  <ShieldAlert className="w-4 h-4 shrink-0" />
                  <span>Sensitive Files / Folders Detected &amp; Skipped (Never Inspected or Stored):</span>
                </div>
                <p className="mt-1 break-all">
                  {sensitiveDetected.join(', ')}
                </p>
              </div>
            )}

            {Object.keys(skippedNonWeb).length > 0 && (
              <div className="text-xs text-slate-400">
                Skipped non-web files:{' '}
                {Object.entries(skippedNonWeb)
                  .map(([k, v]) => `${v} ${k.replace('_', ' ')}`)
                  .join(', ')}
              </div>
            )}

            <pre className="bg-[#060a13] border border-slate-800 rounded-lg p-4 text-xs text-cyan-200 overflow-x-auto">
              {JSON.stringify(result.summary, null, 2)}
            </pre>
          </div>
        </Card>
      )}
    </div>
  )
}
