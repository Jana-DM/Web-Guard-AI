import { useCallback, useState } from 'react'

export function useAsyncAction<TArgs extends unknown[], TResult>(
  fn: (...args: TArgs) => Promise<TResult>
) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const execute = useCallback(
    async (...args: TArgs): Promise<TResult | null> => {
      setLoading(true)
      setError(null)
      try {
        return await fn(...args)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unexpected error')
        return null
      } finally {
        setLoading(false)
      }
    },
    [fn]
  )

  return { execute, loading, error, setError }
}
