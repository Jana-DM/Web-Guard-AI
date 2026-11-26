import React, { useEffect, useState } from 'react'
import { Search } from 'lucide-react'
import { Badge, Card, ErrorBanner, LoadingState } from '../../components/common/UIPrimitives'
import { intelligenceApi } from '../../services/intelligence/intelligenceApi'
import type { CVERecord } from '../../types'
import { severityStyle } from '../../utils/formatters'

export const CVEDatabasePage: React.FC = () => {
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('')
  const [kevOnly, setKevOnly] = useState(false)
  const [cves, setCves] = useState<CVERecord[]>([])
  const [selected, setSelected] = useState<{ record: CVERecord; ai_explanation: string } | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const search = async () => {
    setLoading(true)
    try {
      const res = await intelligenceApi.searchCves({ q: query || undefined, severity: severity || undefined, kev_only: kevOnly })
      setCves(res.items)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load CVEs')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    search()
  }, [])

  const inspectCve = async (cveId: string) => {
    try {
      setSelected(await intelligenceApi.getCveDetail(cveId))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load CVE details')
    }
  }

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onClose={() => setError(null)} />}

      <Card title="CVE Intelligence Explorer" subtitle="Search synchronized CVEs with CISA KEV and patch metadata">
        <div className="flex flex-wrap gap-3">
          <div className="flex-1 min-w-[240px] relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search CVE-2024-... or product/keyword"
              className="w-full bg-[#060a13] border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100"
            />
          </div>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <label className="inline-flex items-center gap-2 text-xs text-slate-300 px-3 py-2 border border-slate-700 rounded-lg bg-[#060a13]">
            <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} />
            CISA KEV Only
          </label>
          <button onClick={search} className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold">
            Filter
          </button>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <Card title={`CVE Records (${cves.length})`}>
            {loading ? (
              <LoadingState />
            ) : cves.length === 0 ? (
              <div className="text-sm text-slate-500 py-6">No matching CVEs stored. Sync feeds from Threat Intelligence first.</div>
            ) : (
              <div className="space-y-3">
                {cves.map((cve) => (
                  <div
                    key={cve.id}
                    onClick={() => inspectCve(cve.cve_id)}
                    className="border border-slate-800 hover:border-cyan-500/50 rounded-lg p-3.5 bg-[#060a13]/70 cursor-pointer transition-colors"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-mono font-semibold text-cyan-300 text-sm">{cve.cve_id}</span>
                      <div className="flex items-center gap-2">
                        {cve.is_kev && <Badge label="CISA KEV" className="bg-red-500/15 text-red-400 border-red-500/40" />}
                        <Badge label={cve.severity.toUpperCase()} className={severityStyle(cve.severity)} />
                      </div>
                    </div>
                    <div className="text-xs text-slate-300 mt-1 line-clamp-2">{cve.description}</div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>

        <div>
          <Card title="Grounded CVE Analysis">
            {selected ? (
              <div className="space-y-3 text-xs">
                <div className="font-mono text-base font-bold text-cyan-300">{selected.record.cve_id}</div>
                <div className="text-slate-300 whitespace-pre-wrap">{selected.ai_explanation}</div>
                {selected.record.references.length > 0 && (
                  <div>
                    <div className="font-semibold text-slate-400 mb-1">References</div>
                    <ul className="space-y-1 text-cyan-400 break-all">
                      {selected.record.references.slice(0, 4).map((ref) => (
                        <li key={ref}>{ref}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-sm text-slate-500">Select any CVE record to inspect CVSS, affected versions, and AI explanation.</div>
            )}
          </Card>
        </div>
      </div>
    </div>
  )
}
