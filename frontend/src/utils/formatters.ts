export function formatDate(value?: string | null): string {
  if (!value) return 'Never'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

export function severityStyle(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-red-500/15 text-red-400 border-red-500/40'
    case 'high':
      return 'bg-orange-500/15 text-orange-400 border-orange-500/40'
    case 'medium':
      return 'bg-amber-500/15 text-amber-300 border-amber-500/40'
    case 'low':
      return 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40'
    default:
      return 'bg-slate-500/15 text-slate-300 border-slate-500/40'
  }
}

export function classificationStyle(classification: string): string {
  switch (classification) {
    case 'CONFIRMED':
      return 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40'
    case 'POTENTIAL':
      return 'bg-amber-500/15 text-amber-300 border-amber-500/40'
    case 'NEEDS REVIEW':
      return 'bg-violet-500/15 text-violet-300 border-violet-500/40'
    default:
      return 'bg-slate-600/20 text-slate-400 border-slate-600/40'
  }
}
