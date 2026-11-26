import React from 'react'
import type { RemediationRecord } from '../../types'
import { Badge } from '../common/UIPrimitives'

export const DiffViewer: React.FC<{
  record: RemediationRecord
  onApprove: (id: string, approved: boolean) => Promise<void>
  onVerify: (id: string) => Promise<void>
}> = ({ record, onApprove, onVerify }) => (
  <div className="border border-slate-800 rounded-xl p-5 bg-[#0c1322] space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div>
        <div className="text-sm font-semibold text-slate-100">Patch Proposal • {record.file_path || 'Snippet'}</div>
        <div className="text-xs text-slate-400 mt-0.5">{record.rationale}</div>
      </div>
      <Badge
        label={record.status.toUpperCase()}
        className={
          record.status === 'approved_applied'
            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40'
            : record.status === 'rejected'
            ? 'bg-red-500/15 text-red-300 border-red-500/40'
            : 'bg-amber-500/15 text-amber-300 border-amber-500/40'
        }
      />
    </div>

    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
      <div>
        <div className="text-xs font-medium text-red-400 mb-1">Original Code</div>
        <pre className="bg-[#060a13] border border-red-900/40 rounded-lg p-3 text-xs text-slate-300 overflow-x-auto max-h-60">
          {record.original_code}
        </pre>
      </div>
      <div>
        <div className="text-xs font-medium text-emerald-400 mb-1">Proposed Secure Code</div>
        <pre className="bg-[#060a13] border border-emerald-900/40 rounded-lg p-3 text-xs text-slate-200 overflow-x-auto max-h-60">
          {record.proposed_code}
        </pre>
      </div>
    </div>

    {record.backup_path && (
      <div className="text-xs text-slate-400 font-mono">Backup saved: {record.backup_path}</div>
    )}

    <div className="flex flex-wrap gap-3">
      {record.status === 'pending_approval' && (
        <>
          <button
            onClick={() => onApprove(record.id, true)}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold"
          >
            Approve & Apply Patch (With Backup)
          </button>
          <button
            onClick={() => onApprove(record.id, false)}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-red-900/60 text-slate-200 text-xs font-semibold"
          >
            Reject
          </button>
        </>
      )}
      {record.status === 'approved_applied' && (
        <button
          onClick={() => onVerify(record.id)}
          className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
        >
          Re-Scan & Verify Fix
        </button>
      )}
    </div>
  </div>
)
