import { createContext, useEffect, useState } from 'react'
import { aiAPI } from '../services/api.js'
import { useAuth } from '../hooks/useAuth.js'
import { useSocket } from '../hooks/useSocket.js'
import { DEFAULT_LINES, linesFromResponse } from '../utils/scoreBands.js'

const DEFAULTS = Object.freeze({ ...DEFAULT_LINES, source: 'default' })

// THR-003/THR-004: the alert/block lines the backend scores with, plus their source ('engine', 'engine-cached',
// 'default'). Loaded per signed-in user and again whenever the live connection comes back (an engine restarted with
// other lines is picked up); reset to the defaults on sign-out. Colours never wait on the request.
export const ScoreLinesContext = createContext(DEFAULTS)

export function ScoreLinesProvider({ children }) {
  const { user } = useAuth()
  const { connected } = useSocket()
  const [lines, setLines] = useState(DEFAULTS)
  const userId = user?._id || user?.id || null

  useEffect(() => {
    if (!userId) {
      setLines(DEFAULTS)
      return undefined
    }
    // Not gated on the socket: if it never connects the lines still load; a reconnect simply loads them again
    let current = true
    aiAPI.scoreLines()
      .then(res => { if (current) setLines(linesFromResponse(res.data?.data)) })
      .catch(() => { if (current) setLines(DEFAULTS) })
    return () => { current = false }
  }, [userId, connected])

  return <ScoreLinesContext.Provider value={lines}>{children}</ScoreLinesContext.Provider>
}
