import React from 'react'
import { RefreshCw } from 'lucide-react'
import type { SyncLog } from '../../types'
import { formatDate } from '../../utils/formatters'
import { Badge, Card } from '../common/UIPrimitives'

export const SyncStatusPanel: React.FC<{
  lastSync: string | null
  logs: SyncLog[]
  onTriggerSync: () => void
  syncing: boolean
}> = ({ lastSync, logs, onTriggerSync, syncing }) => (
  <Card
    title="Intelligence Feed Synchronization"
    subtitle={`Last successful sync: ${formatDate(lastSync)}`}
    action={
      <button
        onClick={onTriggerSync}
        disabled={syncing}
        className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold disabled:opacity-50"
      >
        <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
        {syncing ? 'Syncing Feeds...' : 'Sync Now'}
      </button>
    }
  >
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead className="text-slate-400 border-b border-slate-800">
          <tr>
            <th className="py-2 pr-3">Source</th>
            <th className="py-2 pr-3">Status</th>
            <th className="py-2 pr-3">Fetched</th>
            <th className="py-2 pr-3">Created</th>
            <th className="py-2 pr-3">Updated</th>
            <th className="py-2 pr-3">Duplicates</th>
            <th className="py-2">Completed</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/70">
          {logs.length === 0 ? (
            <tr>
              <td colSpan={7} className="py-4 text-center text-slate-500">
                No intelligence sync runs recorded yet. Click "Sync Now" to pull live NVD, CISA KEV & GitHub feeds.
              </td>
            </tr>
          ) : (
            logs.map((log) => (
              <tr key={log.id} className="text-slate-300">
                <td className="py-2.5 pr-3 font-medium uppercase">{log.source}</td>
                <td className="py-2.5 pr-3">
                  <Badge
                    label={log.status}
                    className={
                      log.status === 'completed'
                        ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                        : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                    }
                  />
                </td>
                <td className="py-2.5 pr-3">{log.records_fetched}</td>
                <td className="py-2.5 pr-3">{log.records_created}</td>
                <td className="py-2.5 pr-3">{log.records_updated}</td>
                <td className="py-2.5 pr-3">{log.duplicates_skipped}</td>
                <td className="py-2.5 text-slate-400">{formatDate(log.completed_at)}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  </Card>
)
