import React from 'react'

export const ReportPreviewPanel: React.FC<{ report: Record<string, unknown> | null }> = ({ report }) => {
  if (!report) return null
  return (
    <div className="border border-slate-800 rounded-xl p-5 bg-[#0c1322] space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-sm font-semibold text-slate-100">Generated Report: {String(report.filename)}</div>
        <span className="text-xs text-cyan-400 uppercase">{String(report.format)}</span>
      </div>
      <p className="text-xs text-slate-300">{String(report.executive_summary || '')}</p>
      <pre className="bg-[#060a13] border border-slate-800 rounded-lg p-3 text-xs text-slate-300 overflow-x-auto max-h-96">
        {String(report.preview || '')}
      </pre>
    </div>
  )
}
