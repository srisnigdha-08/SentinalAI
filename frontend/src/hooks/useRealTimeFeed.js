import { REPORT_TIME_ZONE } from '../utils/reportingTime.js'
/**
 * useRealTimeFeed
 * ================
 * Replaces the Phase 1 mock useLiveFeed hook.
 * Listens strictly to real Socket.IO events from the SentinelAI pipeline.
 *
 * WS-002: one source per event kind, so nothing is shown twice: threats come from 'new_threat' (it carries the threat
 * id); blocks, unblocks and honeypot activity from the server-formatted 'live_feed_event' (already redacted per role
 * room), whose 'threat' copy is ignored. Threats emitted while the socket was down are recovered from the
 * role-redacted REST list once the server confirms the rooms are rejoined after a reconnect.
 */
import { useState, useEffect, useRef, useCallback } from 'react'
import { useSocket } from './useSocket.js'
import { threatAPI } from '../services/api.js'
import { feedThreatsToRecover, insertByTime } from '../utils/liveFeedSync.js'
import { isAlertScore, liveSeverity } from '../utils/scoreBands.js'
import { useScoreLines } from './useScoreLines.js'

const CATCH_UP_LIMIT = 20

// A threat (REST list or new_threat event) as a feed row, keyed by its id and ordered by its server time
const threatItem = (t) => ({
  id: t._id || t.id,
  at: Date.parse(t.createdAt) || Date.now(),
  ts: new Date(t.createdAt || Date.now()).toLocaleTimeString('en-IN', { timeZone: REPORT_TIME_ZONE, hour12: false }),
  ip: t.sourceIP,
  msg: `${t.attackType} detected — score ${((t.aiScore || 0) * 100).toFixed(0)}%`,
  sev: t.severity,
})

export function useRealTimeFeed(maxItems = 30) {
  // THR-003: the socket handlers below subscribe once, so they read the current lines through a ref
  const scoreLines = useScoreLines()
  const scoreLinesRef = useRef(scoreLines)
  scoreLinesRef.current = scoreLines
  const [feed, setFeed]   = useState([])
  const { connected, on, socket } = useSocket()

  const recentKeysRef = useRef(new Set())
  const seqRef = useRef(1)
  const seenThreatIdsRef = useRef(new Set())
  const newestThreatAtRef = useRef(null)

  const addItem = useCallback((item) => {
    if (!item || !item.ip) return
    const key = `${item.ip}::${item.msg}`
    if (recentKeysRef.current.has(key)) return
    recentKeysRef.current.add(key)
    setTimeout(() => {
      recentKeysRef.current.delete(key)
    }, 2000)

    setFeed(prev => insertByTime(prev, [
      { id: `${Date.now()}-${seqRef.current++}`, at: Date.now(), ts: new Date().toLocaleTimeString('en-IN', { timeZone: REPORT_TIME_ZONE, hour12:false }), ...item },
    ], maxItems))
  }, [maxItems])

  const noteThreat = useCallback((t) => {
    const id = t?._id || t?.id
    if (!id) return true
    if (seenThreatIdsRef.current.has(id)) return false
    seenThreatIdsRef.current.add(id)
    if (seenThreatIdsRef.current.size > 500) seenThreatIdsRef.current.delete(seenThreatIdsRef.current.values().next().value)
    const at = Date.parse(t.createdAt)
    if (Number.isFinite(at) && (newestThreatAtRef.current === null || at > newestThreatAtRef.current)) newestThreatAtRef.current = at
    return true
  }, [])

  // ── Real Socket.IO events from live pipeline ──
  useEffect(() => {
    if (!connected) return

    const unsubFeed  = on('live_feed_event', (data) => {
      if (data?.type === 'threat') return // the same threat also arrives as new_threat
      addItem({ ip:data.ip, msg:data.msg, sev:data.sev })
    })
    // Threats are de-duplicated by id only: two detections from the same address are two rows
    const unsubThreat= on('new_threat', (data) => {
      if (!data?.sourceIP || !noteThreat(data)) return
      setFeed(prev => insertByTime(prev, [threatItem(data)], maxItems))
    })
    const unsubAI    = on('ai_prediction', (data) => {
      if (isAlertScore(data.threatScore, scoreLinesRef.current)) addItem({
        ip:  data.sourceIP,
        msg: `AI: ${data.predictedClass} (${((data.threatScore||0)*100).toFixed(0)}%) → ${data.action}`,
        sev: liveSeverity(data, scoreLinesRef.current),
      })
    })

    return () => { unsubFeed?.(); unsubThreat?.(); unsubAI?.() }
  }, [connected, on, addItem, noteThreat, maxItems])

  // The server answers every room join with 'connected'. After a disconnect, the first such acknowledgement means the
  // rooms are rejoined: recover the threats emitted while the socket was down (bounded, role-redacted REST list).
  // Registered on the socket itself, which survives reconnects, so no acknowledgement is missed between renders.
  // The cut-off is the newest threat seen when the connection dropped, not when the response arrives: a live threat
  // delivered after the rejoin must not hide older ones the feed missed. Rapid reconnects keep the earliest cut-off.
  useEffect(() => {
    if (!socket) return
    let missedSince = null // { newestAt } while threats may have been missed
    let active = true
    const onDisconnect = () => { if (!missedSince) missedSince = { newestAt: newestThreatAtRef.current } }
    const onJoined = () => {
      if (!missedSince) return
      const { newestAt } = missedSince
      missedSince = null
      threatAPI.recent(CATCH_UP_LIMIT).then(res => {
        if (!active) return
        const missed = feedThreatsToRecover(res.data?.data?.threats, seenThreatIdsRef.current, newestAt)
          .filter(noteThreat)
        if (missed.length) setFeed(prev => insertByTime(prev, missed.map(threatItem), maxItems))
      }).catch(() => {
        // The next live event or page load fills the feed; a refused session is handled by the auth layer
      })
    }
    socket.on('disconnect', onDisconnect)
    socket.on('connected', onJoined)
    return () => { active = false; socket.off('disconnect', onDisconnect); socket.off('connected', onJoined) }
  }, [socket, noteThreat, maxItems])

  // ── Initial load: fetch real recent threats from API on mount ──
  useEffect(() => {
    let isMounted = true
    threatAPI.recent(10).then(res => {
      if (!isMounted) return
      const recents = (res.data?.data?.threats || []).filter(noteThreat)
      if (recents.length > 0) setFeed(prev => insertByTime(prev, recents.map(threatItem), maxItems))
    }).catch(() => {
      // Feed remains empty if no recent threats
    })
    return () => { isMounted = false }
  }, [maxItems, noteThreat])

  return { feed, connected }
}
