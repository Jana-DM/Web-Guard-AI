export function startPeriodicRefresh(callback: () => void, intervalMs = 15000): () => void {
  const timer = window.setInterval(callback, intervalMs)
  return () => window.clearInterval(timer)
}
