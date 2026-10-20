'use strict'

const reportTime = require('../utils/reportingTime')
const logger = require('../utils/logger')
const ThreatLog = require('../models/ThreatLog')
const {
  redactThreat,
  redactIP,
  redactHoneypotSession,
  redactAIPrediction,
  redactTextWithIPs,
} = require('../utils/redact')

const clients = new Map()
let _io = null

const REQUEST_STATS_MIN_INTERVAL_MS = 5000

const init = (io) => {
  _io = io
  io.on('connection', (socket) => {
    const verifiedRole = socket.role || socket.user?.role || 'viewer'
    const verifiedUserId = socket.user?._id?.toString() || socket.user?.id || null
    logger.info(`[WS] Connected: ${socket.id} (User: ${socket.user?.email || 'authenticated'}, Role: ${verifiedRole})`)

    socket.on('join_room', ({ role: claimedRole, userId, room: customRoom } = {}) => {
      // Security: Bind strictly to the server-verified role from the JWT, ignore client claim
      socket.join(verifiedRole)
      socket.join(`threat_subscribers_${verifiedRole}`)
      socket.join('all')
      socket.join('threat_subscribers')

      // Do NOT allow viewer to join privileged rooms
      if (verifiedRole === 'admin' || verifiedRole === 'analyst') {
        socket.join('threat_subscribers_privileged')
        if (customRoom && (customRoom === 'admin' || customRoom === 'analyst')) {
          socket.join(customRoom)
        }
      }

      clients.set(socket.id, {
        userId: verifiedUserId || userId,
        role: verifiedRole,
        rooms: [verifiedRole, `threat_subscribers_${verifiedRole}`, 'all', 'threat_subscribers'],
        connectedAt: new Date(),
      })

      if (claimedRole && claimedRole !== verifiedRole) {
        logger.warn(
          `[WS] ${socket.id} claimed role '${claimedRole}' but was overridden to verified role '${verifiedRole}'`
        )
      }
      logger.info(`[WS] ${socket.id} joined: ${verifiedRole}`)
      socket.emit('connected', { socketId: socket.id, room: verifiedRole, timestamp: new Date().toISOString() })
    })

    socket.on('subscribe_threats', () => {
      socket.join(`threat_subscribers_${verifiedRole}`)
      socket.join('threat_subscribers')
      if (verifiedRole === 'admin' || verifiedRole === 'analyst') {
        socket.join('threat_subscribers_privileged')
      }
      socket.emit('subscribed', { channel: 'threats' })
    })

    // Each request costs three countDocuments; answer bursts from the last snapshot instead (M4).
    let lastStats = null
    let lastStatsAt = 0
    socket.on('request_stats', async () => {
      if (lastStats && Date.now() - lastStatsAt < REQUEST_STATS_MIN_INTERVAL_MS) {
        socket.emit('stats_snapshot', lastStats)
        return
      }
      lastStatsAt = Date.now()
      try {
        const now = new Date()
        const today = reportTime.filter(1, now)
        const [total, critical, blocked] = await Promise.all([
          ThreatLog.countDocuments({ createdAt: today }),
          ThreatLog.countDocuments({ severity: 'CRITICAL', createdAt: today }),
          ThreatLog.countDocuments({ status: 'BLOCKED' }),
        ])
        lastStats = {
          totalToday: total,
          critical,
          blocked,
          reporting: reportTime.metadata(1, now),
          timestamp: new Date().toISOString(),
        }
        socket.emit('stats_snapshot', lastStats)
      } catch (e) {
        logger.debug('[WS] stats err: ' + e.message)
      }
    })

    socket.on('ping_sentinel', () => socket.emit('pong_sentinel', { timestamp: new Date().toISOString() }))

    socket.on('disconnect', (reason) => {
      clients.delete(socket.id)
      logger.info('[WS] Disconnected: ' + socket.id + ' (' + reason + ')')
    })

    socket.on('error', (e) => logger.error('[WS] Error ' + socket.id + ': ' + e.message))
  })

  startHealthBroadcast(io)
  logger.info('[WS] Socket.IO initialized')
}

const emitNewThreat = (threat) => {
  if (!_io) return
  const rawPayload = {
    _id: threat._id?.toString(),
    id: threat._id?.toString(),
    severity: threat.severity,
    sourceIP: threat.sourceIP,
    attackType: threat.attackType,
    aiScore: threat.aiScore,
    status: threat.status,
    targetService: threat.targetService || 'INTERNAL',
    payload: threat.payload,
    payloadHash: threat.payloadHash,
    createdAt: threat.createdAt || new Date(),
    timestamp: threat.createdAt || new Date(),
  }

  const redactedPayload = redactThreat(rawPayload, 'viewer')

  // Privileged operators (Admin & Analyst) receive unredacted threat data
  _io.to(['admin', 'analyst', 'threat_subscribers_privileged']).emit('new_threat', rawPayload)

  // Viewers receive redacted telemetry
  _io.to(['viewer', 'threat_subscribers_viewer']).emit('new_threat', redactedPayload)

  // Live feed event per role
  _io.to(['admin', 'analyst']).emit('live_feed_event', {
    type: 'threat',
    sev: threat.severity,
    ip: threat.sourceIP,
    msg: threat.attackType + ' detected - score ' + Math.round((threat.aiScore || 0) * 100) + '%',
    timestamp: new Date().toISOString(),
  })
  _io.to('viewer').emit('live_feed_event', {
    type: 'threat',
    sev: threat.severity,
    ip: redactIP(threat.sourceIP),
    msg: threat.attackType + ' detected - score ' + Math.round((threat.aiScore || 0) * 100) + '%',
    timestamp: new Date().toISOString(),
  })

  if (threat.severity === 'CRITICAL') {
    _io.to('admin').emit('critical_alert', { ...rawPayload, urgency: 'IMMEDIATE' })
  }
}

const emitThreatUpdated = (threat) => {
  if (!_io) return
  _io.to(['admin', 'analyst', 'threat_subscribers_privileged']).emit('threat_updated', {
    id: threat._id?.toString(),
    status: threat.status,
    sourceIP: threat.sourceIP,
    timestamp: new Date().toISOString(),
  })
  _io.to(['viewer', 'threat_subscribers_viewer']).emit('threat_updated', {
    id: threat._id?.toString(),
    status: threat.status,
    sourceIP: redactIP(threat.sourceIP),
    timestamp: new Date().toISOString(),
  })
}

const emitThreatIntelUpdated = ({ threatId, sourceIP, threatIntel }) => {
  if (!_io) return
  _io.to(['admin', 'analyst']).emit('threat_intel_updated', {
    threatId: threatId?.toString(),
    sourceIP,
    threatIntel,
    timestamp: new Date().toISOString(),
  })
  _io.to('viewer').emit('threat_intel_updated', {
    threatId: threatId?.toString(),
    sourceIP: redactIP(sourceIP),
    threatIntel,
    timestamp: new Date().toISOString(),
  })
}

const emitIPBlocked = (ip, by, threatId) => {
  if (!_io) return
  _io.to(['admin', 'analyst']).emit('ip_blocked', { ip, blockedBy: by, threatId, timestamp: new Date().toISOString() })
  _io.to(['admin', 'analyst']).emit('live_feed_event', {
    type: 'block',
    sev: 'HIGH',
    ip,
    msg: 'IP ' + ip + ' blocked',
    timestamp: new Date().toISOString(),
  })

  const safeIP = redactIP(ip)
  _io.to('viewer').emit('ip_blocked', { ip: safeIP, blockedBy: by, threatId, timestamp: new Date().toISOString() })
  _io.to('viewer').emit('live_feed_event', {
    type: 'block',
    sev: 'HIGH',
    ip: safeIP,
    msg: 'IP ' + safeIP + ' blocked',
    timestamp: new Date().toISOString(),
  })
}

const emitIPUnblocked = (ip, by) => {
  if (!_io) return
  _io.to(['admin', 'analyst']).emit('ip_unblocked', { ip, unblockedBy: by, timestamp: new Date().toISOString() })
  _io.to(['admin', 'analyst']).emit('live_feed_event', {
    type: 'unblock',
    sev: 'INFO',
    ip,
    msg: 'IP ' + ip + ' unblocked',
    timestamp: new Date().toISOString(),
  })

  const safeIP = redactIP(ip)
  _io.to('viewer').emit('ip_unblocked', { ip: safeIP, unblockedBy: by, timestamp: new Date().toISOString() })
  _io.to('viewer').emit('live_feed_event', {
    type: 'unblock',
    sev: 'INFO',
    ip: safeIP,
    msg: 'IP ' + safeIP + ' unblocked',
    timestamp: new Date().toISOString(),
  })
}

const emitNewAlert = (alert) => {
  if (!_io) return
  const p = {
    id: alert._id?.toString(),
    title: alert.title,
    message: alert.message,
    severity: alert.severity,
    type: alert.type,
    timestamp: alert.createdAt || new Date(),
  }
  const targetRoles =
    Array.isArray(alert.targetRoles) && alert.targetRoles.length > 0 ? alert.targetRoles : ['admin', 'analyst']

  targetRoles.forEach((role) => {
    if (role === 'viewer') {
      _io.to('viewer').emit('new_alert', {
        ...p,
        title: redactTextWithIPs(p.title),
        message: redactTextWithIPs(p.message),
      })
    } else {
      _io.to(role).emit('new_alert', p)
    }
  })
}

const emitAIPrediction = (p) => {
  if (!_io) return
  const rawPred = {
    _id: p._id?.toString(),
    id: p._id?.toString(),
    sourceIP: p.sourceIP,
    predictedClass: p.predictedClass,
    threatScore: p.threatScore,
    severity:
      p.severity ||
      (p.threatScore >= 0.85 ? 'CRITICAL' : p.threatScore >= 0.7 ? 'HIGH' : p.threatScore >= 0.4 ? 'MEDIUM' : 'LOW'),
    action: p.action || (p.threatScore >= 0.92 ? 'BLOCK' : p.threatScore >= 0.7 ? 'MONITOR' : 'ALLOW'),
    modelType: p.modelType || 'random_forest',
    modelVersion: p.modelVersion || 'v2.1',
    isAnomaly: p.isAnomaly || false,
    anomalyScore: p.anomalyScore || 0,
    inferenceTimeMs: p.inferenceTimeMs ?? null,
    createdAt: (p.createdAt || new Date()).toISOString(),
    timestamp: (p.createdAt || new Date()).toISOString(),
  }

  _io.to(['admin', 'analyst']).emit('ai_prediction', rawPred)
  _io.to(['viewer', 'threat_subscribers_viewer']).emit('ai_prediction', redactAIPrediction(rawPred, 'viewer'))
}

const emitHoneypotEvent = (eventType, data) => {
  if (!_io) return
  _io.to(['admin', 'analyst']).emit(eventType, { ...data, timestamp: new Date().toISOString() })
  _io.to('viewer').emit(eventType, { ...redactHoneypotSession(data, 'viewer'), timestamp: new Date().toISOString() })

  const msgs = {
    honeypot_session_opened: 'Honeypot session from ' + data.sourceIP + ' on ' + data.honeypotNode,
    honeypot_command: 'Command: ' + (data.command || '').slice(0, 60),
    honeypot_session_closed: 'Session closed: ' + data.sourceIP + ' (' + data.durationSeconds + 's)',
    malware_download: 'Malware: ' + data.sourceIP + ' -> ' + data.url,
  }
  if (msgs[eventType]) {
    _io.to(['admin', 'analyst']).emit('live_feed_event', {
      type: 'honeypot',
      sev: eventType === 'malware_download' ? 'CRITICAL' : 'HIGH',
      ip: data.sourceIP,
      msg: msgs[eventType],
      timestamp: new Date().toISOString(),
    })

    const safeIP = redactIP(data.sourceIP)
    _io.to('viewer').emit('live_feed_event', {
      type: 'honeypot',
      sev: eventType === 'malware_download' ? 'CRITICAL' : 'HIGH',
      ip: safeIP,
      msg: eventType === 'honeypot_command' ? 'Command: [REDACTED_COMMAND]' : redactTextWithIPs(msgs[eventType]),
      timestamp: new Date().toISOString(),
    })
  }
}

const emitToRoom = (room, event, data) => {
  if (_io) _io.to(room).emit(event, { ...data, timestamp: new Date().toISOString() })
}

let healthTimer = null
const startHealthBroadcast = (io) => {
  if (healthTimer) clearInterval(healthTimer)
  healthTimer = setInterval(async () => {
    if (io.engine.clientsCount === 0) return
    try {
      const mem = process.memoryUsage()
      const now = new Date()
      const today = reportTime.filter(1, now)
      const [td] = await Promise.all([ThreatLog.countDocuments({ createdAt: today })])

      // Full system telemetry for operators
      io.to(['admin', 'analyst']).emit('system_health', {
        memory: {
          heapUsed: Math.round(mem.heapUsed / 1024 / 1024),
          heapTotal: Math.round(mem.heapTotal / 1024 / 1024),
          rss: Math.round(mem.rss / 1024 / 1024),
          heapPercent: Math.round((mem.heapUsed / mem.heapTotal) * 100),
        },
        uptime: Math.floor(process.uptime()),
        connectedClients: io.engine.clientsCount,
        threatsToday: td,
        reporting: reportTime.metadata(1, now),
        timestamp: new Date().toISOString(),
      })

      // Minimal safe telemetry for viewers
      io.to('viewer').emit('system_health', {
        status: 'ok',
        mode: 'REAL_MODE',
        threatsToday: td,
        timestamp: new Date().toISOString(),
      })
    } catch (e) {
      logger.debug('[WS] health err: ' + e.message)
    }
  }, 15000)
  healthTimer.unref?.()
}

const stopHealthBroadcast = () => {
  if (healthTimer) {
    clearInterval(healthTimer)
    healthTimer = null
  }
}

const disconnectUser = (userId) => {
  if (!_io || !userId) return
  const idStr = String(userId)
  for (const [socketId, client] of clients.entries()) {
    if (String(client.userId) === idStr) {
      const s = _io.sockets.sockets?.get?.(socketId)
      s?.disconnect(true)
      clients.delete(socketId)
      logger.info(`[WS] Disconnected socket ${socketId} for user ${idStr}`)
    }
  }
}

const getStats = () => ({
  connectedClients: clients.size,
  clients: Array.from(clients.entries()).map(([id, m]) => ({ socketId: id, role: m.role, connectedAt: m.connectedAt })),
})

module.exports = {
  init,
  emitNewThreat,
  emitThreatUpdated,
  emitThreatIntelUpdated,
  emitIPBlocked,
  emitIPUnblocked,
  emitNewAlert,
  emitAIPrediction,
  emitHoneypotEvent,
  emitToRoom,
  startHealthBroadcast,
  stopHealthBroadcast,
  disconnectUser,
  getStats,
}
