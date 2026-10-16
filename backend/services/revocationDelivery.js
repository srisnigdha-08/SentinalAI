const { performance } = require('node:perf_hooks')
const SESSION_FIELDS = ['revokedAt', 'authVersion', 'expiresAt', 'user']
const USER_FIELDS = ['authVersion', 'role', 'status', 'password', 'passwordChangedAt']
const affects = (change, fields) => {
  const description = change.updateDescription || {}
  const changed = [...Object.keys(description.updatedFields || {}), ...(description.removedFields || [])]
  return changed.some((name) => fields.includes(name.split('.')[0]))
}
// One shared database subscription per process; no polling approximation of revocation events.
function createRevocationDelivery({
  mode,
  connection,
  disconnectSession,
  disconnectUser,
  disconnectAll,
  logger,
  now = () => performance.now(),
  staleMs = 2000,
  retryMs = 500,
}) {
  let stream = null
  let stopping = false
  let ready = mode === 'single'
  let lastRead = -Infinity
  let watchdog
  let running
  const delay = (ms) =>
    new Promise((resolve) => {
      const timer = setTimeout(resolve, ms)
      timer.unref?.()
    })
  const available = () =>
    !stopping &&
    (mode === 'single' ||
      (ready && (connection.readyState === undefined || connection.readyState === 1) && now() - lastRead < staleMs))
  const unavailable = () => {
    if (ready) disconnectAll()
    ready = false
  }
  function handle(change) {
    const collection = change.ns?.coll
    if (!['users', 'authsessions'].includes(collection)) return
    if (['drop', 'rename', 'invalidate'].includes(change.operationType)) {
      unavailable()
      throw new Error('Security collection invalidated')
    }
    const id = String(change.documentKey?._id || '')
    if (!id) return
    const all = ['delete', 'replace'].includes(change.operationType)
    if (collection === 'authsessions' && (all || affects(change, SESSION_FIELDS))) disconnectSession(id)
    if (collection === 'users' && (all || affects(change, USER_FIELDS))) disconnectUser(id)
  }
  async function open() {
    const hello = await connection.db.admin().command({ hello: 1 })
    if (stopping) throw new Error('Revocation delivery stopped')
    if (!hello.setName && hello.msg !== 'isdbgrid')
      throw new Error('mongo-stream revocation requires a replica set or sharded MongoDB')
    stream = connection.db.watch(
      [
        {
          $match: {
            'ns.coll': { $in: ['users', 'authsessions'] },
            operationType: { $in: ['update', 'replace', 'delete', 'drop', 'rename', 'invalidate'] },
          },
        },
      ],
      { maxAwaitTimeMS: 500 }
    )
    await read() // Actual aggregate/getMore round trip, not merely constructing a lazy cursor.
  }
  async function read() {
    const change = await stream.tryNext()
    if (stopping) return
    if (connection.readyState !== undefined && connection.readyState !== 1)
      throw new Error('Revocation store disconnected')
    if (stream.closed) throw new Error('Revocation stream closed')
    if (change) handle(change)
    lastRead = now()
    ready = true
  }
  async function closeStream() {
    const previous = stream
    stream = null
    if (previous) await previous.close().catch(() => {})
  }
  async function pump() {
    while (!stopping) {
      try {
        if (!stream) await open()
        else await read()
      } catch (error) {
        unavailable()
        // Never log the event, URI, query, credentials or an untrusted error message.
        logger.warn('Shared revocation delivery unavailable (' + error.name + ')')
        await closeStream()
        if (!stopping) await delay(retryMs)
      }
    }
  }
  async function start() {
    if (mode === 'single') return
    if (running || stopping) throw new Error('Revocation delivery cannot be started twice')
    connection.on('disconnected', unavailable)
    try {
      await open()
    } catch (error) {
      unavailable()
      await closeStream()
      connection.off('disconnected', unavailable)
      throw error // Startup must not fall back to local-only revocation.
    }
    watchdog = setInterval(
      () => {
        if (!available()) unavailable()
      },
      Math.max(50, Math.floor(staleMs / 4))
    )
    watchdog.unref?.()
    running = pump()
  }
  async function stop() {
    stopping = true
    unavailable()
    clearInterval(watchdog)
    connection.off?.('disconnected', unavailable)
    await closeStream()
    await running
  }
  return { start, stop, available, handle, status: () => ({ mode, ready: available() }) }
}
module.exports = { createRevocationDelivery }
