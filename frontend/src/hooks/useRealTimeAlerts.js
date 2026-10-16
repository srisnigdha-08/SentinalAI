/**
 * useRealTimeAlerts
 * ==================
 * Tracks unread alert count and latest alerts in real time.
 * Badge in sidebar updates automatically via Socket.IO.
 */
import { useState, useEffect, useCallback } from 'react'
import { useSocket }  from './useSocket.js'
import { alertAPI }   from '../services/api.js'
import toast          from 'react-hot-toast'

export function useRealTimeAlerts() {
  const [alerts,      setAlerts]      = useState([])
  const [unreadCount, setUnreadCount] = useState(0)
  const [loading,     setLoading]     = useState(true)
  const { connected, on } = useSocket()

  const loadAlerts = useCallback(async () => {
    try {
      const [alertsRes, countRes] = await Promise.all([
        alertAPI.list({ limit: 10, isRead: false }),
        alertAPI.unreadCount(),
      ])
      setAlerts(alertsRes.data.data || [])
      setUnreadCount(countRes.data.data?.count || 0)
    } catch {
      // Silently fail — alerts are non-critical UI
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadAlerts() }, [loadAlerts])

  // ── Socket.IO: new alerts pushed from backend ──
  useEffect(() => {
    if (!connected) return

    const unsub = on('new_alert', (alert) => {
      // Prepend to local list
      setAlerts(prev => [alert, ...prev].slice(0, 10))
      setUnreadCount(n => n + 1)

      // Show toast for critical/high alerts
      if (alert.severity === 'CRITICAL') {
        toast.error(`⚠ CRITICAL: ${alert.title}`, { duration: 6000 })
      } else if (alert.severity === 'HIGH') {
        toast(`⚡ ${alert.title}`, { duration: 4000 })
      }
    })

    const unsubIP = on('ip_blocked', (data) => {
      toast.error(`🚫 IP Blocked: ${data.ip}`, { duration: 4000 })
    })

    return () => { unsub?.(); unsubIP?.() }
  }, [connected, on])

  const markRead = useCallback(async (id) => {
    try {
      await alertAPI.markRead(id)
      setAlerts(prev => prev.filter(a => a._id !== id && a.id !== id))
      setUnreadCount(n => Math.max(0, n - 1))
    } catch { /* silent */ }
  }, [])

  const markAllRead = useCallback(async () => {
    try {
      await alertAPI.markAllRead()
      setAlerts([])
      setUnreadCount(0)
    } catch { /* silent */ }
  }, [])

  return { alerts, unreadCount, loading, markRead, markAllRead, refetch: loadAlerts }
}
