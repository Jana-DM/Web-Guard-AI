import React, { useState } from 'react'
import { GitBranch } from 'lucide-react'
import { Card, ErrorBanner } from '../../components/common/UIPrimitives'
import { CodeUploadDropzone } from '../../components/scanner/CodeUploadDropzone'
import { scannerApi } from '../../services/scanner/scannerApi'
import type { ScanJob } from '../../types'

export const CodeScannerPage: React.FC = () => {
  const [repoUrl, setRepoUrl] = useState('')
  const [branch, setBranch] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ScanJob | null>(null)

  const handleUpload = async (files: FileList) => {
    setLoading(true)
    setError(null)
    try {
      setResult(await scannerApi.uploadCodeScan(files))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Code scan failed')
    } finally {
      setLoading(false)
    }
  }

  const handleGitHubScan = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      setResult(await scannerApi.scanGitHubRepo(repoUrl, branch || undefined))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'GitHub scan failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onClose={() => setError(null)} />}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Upload Source Files or ZIP Archive" subtitle="Python, JavaScript, TypeScript, requirements.txt, package.json">
          <CodeUploadDropzone onUpload={handleUpload} loading={loading} />
        </Card>

        <Card title="Scan Public GitHub Repository" subtitle="Shallow static clone with git hooks disabled">
          <form onSubmit={handleGitHubScan} className="space-y-3">
            <input
              type="url"
              required
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repository"
              className="w-full bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
            />
            <input
              type="text"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              placeholder="Optional branch (default: repo HEAD)"
              className="w-full bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
            />
            <button
              type="submit"
              disabled={loading}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold disabled:opacity-50"
            >
              <GitBranch className="w-4 h-4" />
              {loading ? 'Cloning & Scanning...' : 'Scan GitHub Repo'}
            </button>
          </form>
        </Card>
      </div>

      {result && (
        <Card title="Static Code Analysis Completed" subtitle={`Scan ID: ${result.id}`}>
          <pre className="bg-[#060a13] border border-slate-800 rounded-lg p-4 text-xs text-cyan-200 overflow-x-auto">
            {JSON.stringify(result.summary, null, 2)}
          </pre>
        </Card>
      )}
    </div>
  )
}
