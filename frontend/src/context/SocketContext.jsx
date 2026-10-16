import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import { io } from 'socket.io-client'
import { useAuth } from '../hooks/useAuth.js'
import { authSession } from '../services/authSession.js'

export const SocketContext = createContext(null)

// One connection owner, independent of page widgets.
export function SocketProvider({ children }) {
  const { user, token } = useAuth()
  const [socket, setSocket] = useState(null)
  const [connected, setConnected] = useState(false)
  const [reconnecting, setReconnecting] = useState(false)
  const [error, setError] = useState(null)
  const userId = user?._id || user?.id
  const role = user?.role
  useEffect(() => {
    if (!userId || !token) return
    const connection = io(import.meta.env.VITE_SOCKET_URL || window.location.origin, {
      auth: { token }, reconnectionAttempts: 10, reconnectionDelay: 1000, reconnectionDelayMax: 5000,
    })
    setSocket(connection)
    connection.on('connect', () => {
      setConnected(true)
      setReconnecting(false)
      setError(null)
      connection.emit('join_room', { role, userId })
      connection.emit('subscribe_threats')
    })
    connection.on('disconnect', () => setConnected(false))
    connection.on('connect_error', error => {
      setConnected(false); setError('Live connection unavailable')
      if (error.message === 'Authentication rejected') authSession.refresh().catch(() => {})
    })
    connection.io.on('reconnect_attempt', () => setReconnecting(true))
    connection.io.on('reconnect_failed', () => setReconnecting(false))
    return () => {
      connection.removeAllListeners()
      connection.io.removeAllListeners()
      connection.disconnect()
      setSocket(null)
      setConnected(false)
      setReconnecting(false)
    }
  }, [token, userId, role])
  const value = useMemo(() => ({
    socket, connected, reconnecting, error,
    on(event, handler) { socket?.on(event, handler); return () => socket?.off(event, handler) },
    off(event, handler) { socket?.off(event, handler) },
    emit(event, data) { socket?.emit(event, data) },
  }), [socket, connected, reconnecting, error])
  return <SocketContext.Provider value={value}>{children}</SocketContext.Provider>
}
export const useSocketContext = () => useContext(SocketContext)
