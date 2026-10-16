import { useSocketContext } from '../context/SocketContext.jsx'
export function useSocket() {
  const context = useSocketContext()
  if (!context) throw new Error('useSocket requires SocketProvider')
  return context
}
