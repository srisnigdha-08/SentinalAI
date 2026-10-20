import { REPORT_TIME_ZONE } from '../utils/reportingTime.js'
/**
 * useRealTimeFeed
 * ================
 * Replaces the Phase 1 mock useLiveFeed hook.
 * Listens strictly to real Socket.IO events from the SentinelAI pipeline.
 */
import { useState, useEffect, useRef, useCallback } from 'react'
import { useSocket } from './useSocket.js'

export function useRealTimeFeed(maxItems = 30) {
  const [feed, setFeed]   = useState([])
  const { connected, on } = useSocket()

  const recentKeysRef = useRef(new Set())
  const seqRef = useRef(1)

  const addItem = useCallback((item) => {
    if (!item || !item.ip) return
    const key = `${item.ip}::${item.msg}`
    if (recentKeysRef.current.has(key)) return
    recentKeysRef.current.add(key)
    setTimeout(() => {
      recentKeysRef.current.delete(key)
    }, 2000)

    setFeed(prev => [
      { id: `${Date.now()}-${seqRef.current++}`, ts: new Date().toLocaleTimeString('en-IN', { timeZone: REPORT_TIME_ZONE, hour12:false }), ...item },
      ...prev,
    ].slice(0, maxItems))
  }, [maxItems])

  // ── Real Socket.IO events from live pipeline ──
  useEffect(() => {
    if (!connected) return

    const unsubFeed  = on('live_feed_event', (data) => addItem({ ip:data.ip, msg:data.msg, sev:data.sev }))
    const unsubThreat= on('new_threat', (data) => addItem({
      ip:  data.sourceIP,
      msg: `${data.attackType} detected — score ${((data.aiScore||0)*100).toFixed(0)}%`,
      sev: data.severity,
    }))
    const unsubHP    = on('honeypot_session_opened', (data) => addItem({
      ip:  data.sourceIP,
      msg: `Honeypot session on ${data.honeypotNode}`,
      sev: 'HIGH',
    }))
    const unsubCmd   = on('honeypot_command', (data) => addItem({
      ip:  data.sourceIP,
      msg: `Command: ${data.command?.slice(0,60)}`,
      sev: 'MEDIUM',
    }))
    const unsubAI    = on('ai_prediction', (data) => {
      if (data.threatScore >= 0.7) addItem({
        ip:  data.sourceIP,
        msg: `AI: ${data.predictedClass} (${((data.threatScore||0)*100).toFixed(0)}%) → ${data.action}`,
        sev: data.severity || 'HIGH',
      })
    })

    return () => { unsubFeed?.(); unsubThreat?.(); unsubHP?.(); unsubCmd?.(); unsubAI?.() }
  }, [connected, on, addItem])

  // ── Initial load: fetch real recent threats from API on mount ──
  useEffect(() => {
    let isMounted = true
    import('../services/api.js').then(({ threatAPI }) => {
      threatAPI.recent(10).then(res => {
        if (!isMounted) return
        const recents = res.data?.data?.threats || []
        if (recents.length > 0) {
          setFeed(prev => {
            const existingIps = new Set(prev.map(x => x.ip))
            const newRecents = recents
              .filter(t => !existingIps.has(t.sourceIP))
              .map(t => ({
                id: t._id || `${Date.now()}-${seqRef.current++}`,
                ts: new Date(t.createdAt).toLocaleTimeString('en-IN', { timeZone: REPORT_TIME_ZONE, hour12: false }),
                ip: t.sourceIP,
                msg: `${t.attackType} detected — score ${((t.aiScore || 0) * 100).toFixed(0)}%`,
                sev: t.severity,
              }))
            return [...prev, ...newRecents].slice(0, maxItems)
          })
        }
      }).catch(() => {
        // Feed remains empty if no recent threats
      })
    })
    return () => { isMounted = false }
  }, [maxItems])

  return { feed, connected }
}
