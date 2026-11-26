import React, { useEffect, useState } from 'react'
import { Download, FileText } from 'lucide-react'
import { Card, ErrorBanner } from '../../components/common/UIPrimitives'
import { ReportPreviewPanel } from '../../components/reports/ReportPreviewModal'
import { API_BASE, getStoredToken } from '../../services/api/client'
import { intelligenceApi } from '../../services/intelligence/intelligenceApi'

export const ReportsPage: React.FC = () => {
  const [format, setFormat] = useState<'markdown' | 'json' | 'html'>('markdown')
  const [generated, setGenerated] = useState<Record<string, unknown> | null>(null)
  const [reports, setReports] = useState<Array<{ filename: string; size_bytes: number; download_url: string }>>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const loadList = async () => {
    try {
      setReports(await intelligenceApi.listReports())
    } catch {
      // ignore initial error
    }
  }

  useEffect(() => {
    loadList()
  }, [])

  const handleGenerate = async () => {
    setBusy(true)
    setError(null)
    try {
      const res = await intelligenceApi.generateReport(format)
      setGenerated(res)
      await loadList()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Report generation failed')
    } finally {
      setBusy(false)
    }
  }

  const handleDownload = async (filename: string) => {
    const token = getStoredToken()
    const resp = await fetch(`${API_BASE}/reports/${encodeURIComponent(filename)}/download`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!resp.ok) return
    const blob = await resp.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onClose={() => setError(null)} />}

      <Card title="Generate Security Assessment Report" subtitle="Grounded in verified scan findings and evidence records">
        <div className="flex flex-wrap items-center gap-3">
          <select
            value={format}
            onChange={(e) => setFormat(e.target.value as typeof format)}
            className="bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
          >
            <option value="markdown">Markdown (.md)</option>
            <option value="json">JSON (.json)</option>
            <option value="html">HTML Report (.html)</option>
          </select>
          <button
            disabled={busy}
            onClick={handleGenerate}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold disabled:opacity-50"
          >
            <FileText className="w-4 h-4" />
            {busy ? 'Generating...' : 'Generate Report'}
          </button>
        </div>
      </Card>

      <ReportPreviewPanel report={generated} />

      <Card title="Saved Report Artifacts">
        {reports.length === 0 ? (
          <div className="text-sm text-slate-500">No reports generated yet.</div>
        ) : (
          <div className="space-y-2">
            {reports.map((r) => (
              <div key={r.filename} className="flex items-center justify-between border border-slate-800 rounded-lg p-3 bg-[#060a13]/70 text-xs">
                <div>
                  <span className="font-mono text-slate-200">{r.filename}</span>
                  <span className="text-slate-500 ml-3">{r.size_bytes} bytes</span>
                </div>
                <button
                  onClick={() => handleDownload(r.filename)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-cyan-700 text-slate-200"
                >
                  <Download className="w-3.5 h-3.5" /> Download
                </button>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
