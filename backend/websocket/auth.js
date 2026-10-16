const auth = require('../services/authSessionService')
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
    socket.use(async (_packet, next) => {
      try {
        await ready
        const state = await auth.authorize(socket.authToken)
        if (state.user.role !== socket.role || state.user.mustChangePassword) throw new auth.AuthError()
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
