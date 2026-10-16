import { useState, useEffect, useCallback } from 'react'
import api from '../services/api.js'
import toast from 'react-hot-toast'

/**
 * useApi — Generic fetch hook
 * Handles loading, error, and data state for any API call.
 *
 * Usage:
 *   const { data, loading, error, refetch } = useApi('/threats/analytics/summary')
 */
export function useApi(endpoint, options = {}) {
  const { immediate = true, params = {} } = options

  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(immediate)
  const [error,   setError]   = useState(null)

  const fetch = useCallback(async (overrideParams = {}) => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.get(endpoint, { params: { ...params, ...overrideParams } })
      setData(res.data.data)
      return res.data.data
    } catch (err) {
      const msg = err.response?.data?.error || 'Failed to load data'
      setError(msg)
      // Only toast on non-auth errors (auth redirected by interceptor)
      if (err.response?.status !== 401) toast.error(msg)
      return null
    } finally {
      setLoading(false)
    }
  }, [endpoint])

  useEffect(() => {
    if (immediate) fetch()
  }, [immediate])

  return { data, loading, error, refetch: fetch }
}

/**
 * useApiMutation — For POST/PUT/DELETE calls
 *
 * Usage:
 *   const { mutate, loading } = useApiMutation()
 *   await mutate('post', '/threats', body)
 */
export function useApiMutation() {
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState(null)

  const mutate = useCallback(async (method, endpoint, body = {}) => {
    setLoading(true)
    setError(null)
    try {
      const res = await api[method](endpoint, body)
      return res.data
    } catch (err) {
      const msg = err.response?.data?.error || 'Operation failed'
      setError(msg)
      toast.error(msg)
      return null
    } finally {
      setLoading(false)
    }
  }, [])

  return { mutate, loading, error }
}
