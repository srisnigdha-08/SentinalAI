const auth = require('../services/authSessionService')
const PACKET_AUTH_CACHE_MS = 5000

function install(io) {
  auth.attachSocketServer(io)
  io.use(async (socket, next) => {
    try {
      const header = socket.handshake.headers.authorization
      const token = socket.handshake.auth?.token || (header?.startsWith('Bearer ') ? header.slice(7) : null)
      const state = await auth.authorize(token)
      if (state.user.mustChangePassword) {
        return next(new Error('Password change required'))
      }
      socket.authToken = token
      socket.user = state.user
      socket.role = state.user.role
      socket.authClaims = state.claims
      next()
    } catch (error) {
      if (error.message === 'Password change required') {
        return next(error)
      }
      next(new Error(error.statusCode === 503 ? 'Authentication service unavailable' : 'Authentication rejected'))
    }
  })
  io.on('connection', async (socket) => {
    // Join before re-reading: either revocation disconnects this room or the re-read rejects it.
    let expiry
    let recheck
    socket.on('disconnect', () => {
      clearTimeout(expiry)
      clearInterval(recheck)
    })
    // Re-authorising every packet cost one session read per message (M4). A successful check is reused for
    // PACKET_AUTH_CACHE_MS; revocation still disconnects at once via the session/user rooms, and the
    // 15 s recheck below still runs.
    let packetAuthAt = 0
    socket.use(async (_packet, next) => {
      try {
        await ready
        if (Date.now() - packetAuthAt >= PACKET_AUTH_CACHE_MS) {
          const state = await auth.authorize(socket.authToken)
          if (state.user.role !== socket.role || state.user.mustChangePassword) throw new auth.AuthError()
          packetAuthAt = Date.now()
        }
        next()
      } catch {
        socket.disconnect(true)
      }
    })
    const ready = (async () => {
      await socket.join(auth.sessionRoom(socket.authClaims.sid))
      await socket.join(auth.userRoom(socket.authClaims.id))
      const state = await auth.authorize(socket.authToken)
      if (!socket.connected || state.user.role !== socket.role || state.user.mustChangePassword)
        return socket.disconnect(true)
      expiry = setTimeout(() => socket.disconnect(true), Math.max(0, socket.authClaims.exp * 1000 - Date.now()))
      recheck = setInterval(async () => {
        try {
          const state = await auth.authorize(socket.authToken)
          if (state.user.role !== socket.role || state.user.mustChangePassword) socket.disconnect(true)
        } catch {
          socket.disconnect(true)
        }
      }, 15000)
      expiry.unref?.()
      recheck.unref?.()
    })()
    ready.catch(() => socket.disconnect(true))
  })
}
module.exports = { install }
