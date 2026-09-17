import { useState, useEffect, useCallback, useRef } from 'react'
import { extractApiError } from './api'

interface UseQueryResult<T> {
  data: T | null
  loading: boolean
  error: string | null
  refresh: () => void
}

export function useQuery<T>(fetcher: () => Promise<T>, deps: any[] = []): UseQueryResult<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [counter, setCounter] = useState(0)

  const refresh = useCallback(() => setCounter(c => c + 1), [])

  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    fetcherRef.current()
      .then(d => { if (!cancelled) { setData(d); setLoading(false) } })
      .catch(err => { if (!cancelled) { setError(extractApiError(err)); setLoading(false) } })
    return () => { cancelled = true }
  }, [counter, ...deps])

  return { data, loading, error, refresh }
}

interface UseMutationResult<T, V> {
  execute: (variables: V) => Promise<T>
  loading: boolean
  error: string | null
}

export function useMutation<T, V = void>(mutationFn: (variables: V) => Promise<T>): UseMutationResult<T, V> {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const execute = useCallback(async (variables: V): Promise<T> => {
    setLoading(true)
    setError(null)
    try {
      return await mutationFn(variables)
    } catch (err) {
      const msg = extractApiError(err)
      setError(msg)
      throw err
    } finally {
      setLoading(false)
    }
  }, [mutationFn])

  return { execute, loading, error }
}
