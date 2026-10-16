/**
 * useRealTimeThreats
 * ===================
 * Maintains a live-updating list of recent threats.
 * Combines initial API fetch with Socket.IO push updates.
 */
import { useState, useEffect, useCallback } from 'react'
import { useSocket }  from './useSocket.js'
import { threatAPI }  from '../services/api.js'

export function useRealTimeThreats(initialLimit = 8) {
  const [threats,      setThreats]      = useState([])
  const [criticalCount,setCriticalCount]= useState(0)
  const [totalToday,   setTotalToday]   = useState(0)
  const [loading,      setLoading]      = useState(true)
  const { connected, on } = useSocket()

  // ── Initial load from API ──
  const loadThreats = useCallback(async () => {
    try {
      const [threatsRes, analyticsRes] = await Promise.all([
        threatAPI.list({ limit: initialLimit, sortBy:'createdAt', sortOrder:'desc' }),
        threatAPI.analytics(),
      ])
      setThreats(threatsRes.data.data || [])
      const kpis = analyticsRes.data.data?.kpis || {}
      setTotalToday(kpis.totalToday || 0)
      // Count critical from today's breakdown
      const sevToday = analyticsRes.data.data?.charts?.bySeverityToday || []
      const crit = sevToday.find(s => s._id === 'CRITICAL')?.count || 0
      setCriticalCount(crit)
    } catch (err) {
      console.warn('[useRealTimeThreats] Load failed:', err.message)
    } finally {
      setLoading(false)
    }
  }, [initialLimit])

  useEffect(() => { loadThreats() }, [loadThreats])

  // ── Socket.IO: prepend new threats ──
  useEffect(() => {
    if (!connected) return

    const unsub = on('new_threat', (threat) => {
      setThreats(prev => [threat, ...prev].slice(0, initialLimit))
      setTotalToday(n => n + 1)
      if (threat.severity === 'CRITICAL') setCriticalCount(n => n + 1)
    })

    const unsubUpdate = on('threat_updated', (updated) => {
      setThreats(prev => prev.map(t =>
        t._id === updated.id ? { ...t, status: updated.status } : t
      ))
    })

    const unsubIntel = on('threat_intel_updated', (updated) => {
      setThreats(prev => prev.map(t =>
        t._id === updated.threatId ? { ...t, threatIntel: updated.threatIntel } : t
      ))
    })

    return () => { unsub?.(); unsubUpdate?.(); unsubIntel?.() }
  }, [connected, on, initialLimit])

  return { threats, criticalCount, totalToday, loading, refetch: loadThreats }
}
