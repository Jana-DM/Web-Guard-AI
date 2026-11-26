import React from 'react'
import { ArrowRight } from 'lucide-react'

const STAGES = [
  'Detection',
  'Context Analysis',
  'Cross Validation',
  'Evidence Collection',
  'Confidence Assessment',
  'Final Classification',
]

export const ValidationPipelineView: React.FC<{ stages?: Record<string, unknown> }> = ({ stages }) => (
  <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-4">
    <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
      Multi-Stage Evidence Validation Pipeline
    </div>
    <div className="flex flex-wrap items-center gap-2">
      {STAGES.map((stage, idx) => (
        <React.Fragment key={stage}>
          <div className="px-3 py-1.5 rounded-lg bg-[#111a2e] border border-cyan-500/30 text-xs font-medium text-cyan-200">
            {idx + 1}. {stage}
          </div>
          {idx < STAGES.length - 1 && <ArrowRight className="w-3.5 h-3.5 text-slate-600" />}
        </React.Fragment>
      ))}
    </div>
    {stages && Object.keys(stages).length > 0 && (
      <pre className="mt-3 bg-[#060a13] border border-slate-800 rounded-lg p-3 text-xs text-slate-300 overflow-x-auto">
        {JSON.stringify(stages, null, 2)}
      </pre>
    )}
  </div>
)
