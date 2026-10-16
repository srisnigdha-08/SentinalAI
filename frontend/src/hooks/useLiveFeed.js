import { REPORT_TIME_ZONE } from '../utils/reportingTime.js'
/**
 * ============================================================================
 * SIMULATION ATTACK FEED HOOK (INTENTIONALLY PRESERVED)
 * ============================================================================
 * This hook generates synthetic attack events for offline testing, demos,
 * and UI benchmarking.
 *
 * In SentinelAI default REAL DATA MODE, this hook is NOT used by the dashboard.
 * The production dashboard uses `useRealTimeFeed.js` which connects to the
 * genuine Socket.IO pipeline events.
 *
 * To re-enable this simulated feed in the future:
 * Import and call this hook in `LiveFeed.jsx` or your test harness.
 * ============================================================================
 */
import { useState, useEffect, useRef } from 'react'

const FEED_POOL = [
  { ip: '185.220.101.47', msg: 'SSH login attempt — invalid credentials (attempt 47)', sev: 'CRITICAL' },
  { ip: '194.165.16.78',  msg: 'SQL injection payload detected in POST /api/users',    sev: 'HIGH' },
  { ip: '45.95.147.22',   msg: 'Honeypot SSH session opened — capturing commands',      sev: 'HIGH' },
  { ip: '212.102.39.212', msg: 'SYN flood detected — 12,400 packets/sec',              sev: 'CRITICAL' },
  { ip: '77.247.110.50',  msg: 'Port scan: 65535 ports in 4.2 seconds',               sev: 'MEDIUM' },
  { ip: '91.92.252.10',   msg: 'Credential stuffing — 200 accounts attempted',         sev: 'HIGH' },
  { ip: '103.75.190.51',  msg: 'XSS payload in search parameter — blocked',            sev: 'MEDIUM' },
  { ip: '5.188.210.3',    msg: 'Malware C2 beacon — heartbeat interval 30s',           sev: 'LOW' },
  { ip: '198.51.100.14',  msg: 'RDP brute force — 340 attempts from single source',    sev: 'HIGH' },
  { ip: '203.0.113.77',   msg: 'Anomaly: unusual data exfiltration volume detected',   sev: 'CRITICAL' },
]

export function useLiveFeed(maxItems = 30, intervalMs = 2200) {
  const [feed, setFeed] = useState([])
  const idxRef = useRef(0)

  const addEvent = () => {
    const e = FEED_POOL[idxRef.current % FEED_POOL.length]
    idxRef.current++
    const item = {
      id: Date.now() + Math.random(),
      ts: new Date().toLocaleTimeString('en-IN', { timeZone: REPORT_TIME_ZONE, hour12: false }),
      ...e,
    }
    setFeed(prev => [item, ...prev].slice(0, maxItems))
  }

  useEffect(() => {
    addEvent(); addEvent(); addEvent()
    const t = setInterval(addEvent, intervalMs)
    return () => clearInterval(t)
  }, [])

  return feed
}
