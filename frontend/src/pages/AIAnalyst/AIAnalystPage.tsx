import React, { useState } from 'react'
import { Bot, Send } from 'lucide-react'
import { Card, ErrorBanner } from '../../components/common/UIPrimitives'
import { scannerApi } from '../../services/scanner/scannerApi'

export const AIAnalystPage: React.FC = () => {
  const [question, setQuestion] = useState('')
  const [cveId, setCveId] = useState('')
  const [messages, setMessages] = useState<Array<{ role: 'user' | 'assistant'; text: string; citations?: Array<{ type: string; id: string; label: string }> }>>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const ask = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!question.trim()) return
    const q = question.trim()
    setMessages((prev) => [...prev, { role: 'user', text: q }])
    setQuestion('')
    setLoading(true)
    setError(null)
    try {
      const res = await scannerApi.askAiAnalyst({
        question: q,
        cve_id: cveId.trim() || undefined,
      })
      setMessages((prev) => [...prev, { role: 'assistant', text: res.answer, citations: res.citations }])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI analyst request failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onClose={() => setError(null)} />}

      <Card
        title="Grounded AI Security Assistant"
        subtitle="Responses are constrained strictly to verified database findings, evidence records, and synced CVE intelligence."
      >
        <div className="space-y-4 min-h-[340px] max-h-[520px] overflow-y-auto mb-4 p-4 rounded-xl bg-[#060a13] border border-slate-800">
          {messages.length === 0 ? (
            <div className="text-center py-12 text-slate-500 text-sm">
              <Bot className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
              Ask about confirmed findings, CISA KEV CVEs, or remediation priorities.
            </div>
          ) : (
            messages.map((m, idx) => (
              <div key={idx} className={`p-3.5 rounded-xl text-sm ${m.role === 'user' ? 'bg-cyan-950/40 border border-cyan-500/30 ml-10' : 'bg-[#0c1322] border border-slate-800 mr-10'}`}>
                <div className="text-[11px] font-semibold uppercase text-slate-400 mb-1">{m.role}</div>
                <div className="whitespace-pre-wrap text-slate-200">{m.text}</div>
                {m.citations && m.citations.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-slate-800 flex flex-wrap gap-2">
                    {m.citations.map((c) => (
                      <span key={c.id} className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-cyan-300">
                        {c.type}: {c.label}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        <form onSubmit={ask} className="flex flex-wrap gap-3">
          <input
            type="text"
            value={cveId}
            onChange={(e) => setCveId(e.target.value)}
            placeholder="Optional CVE ID (e.g. CVE-2024-1234)"
            className="w-56 bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
          />
          <input
            type="text"
            required
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask Web Guard AI Analyst..."
            className="flex-1 min-w-[260px] bg-[#060a13] border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100"
          />
          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold disabled:opacity-50"
          >
            <Send className="w-4 h-4" />
            {loading ? 'Analyzing...' : 'Ask'}
          </button>
        </form>
      </Card>
    </div>
  )
}
