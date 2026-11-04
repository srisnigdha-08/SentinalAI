import { createContext, useEffect, useState } from 'react'
import { aiAPI } from '../services/api.js'
import { useAuth } from '../hooks/useAuth.js'
import { DEFAULT_LINES, normalizeLines } from '../utils/scoreBands.js'

// THR-003: the alert/block lines the backend scores with, loaded once per signed-in user. Defaults until the answer
// arrives or when it fails, so colours never block on the request.
export const ScoreLinesContext = createContext(DEFAULT_LINES)

export function ScoreLinesProvider({ children }) {
  const { user } = useAuth()
  const [lines, setLines] = useState(DEFAULT_LINES)
  const userId = user?._id || user?.id || null

  useEffect(() => {
    if (!userId) return undefined
    let current = true
    aiAPI.scoreLines()
      .then(res => { if (current) setLines(normalizeLines(res.data?.data)) })
      .catch(() => { if (current) setLines(DEFAULT_LINES) })
    return () => { current = false }
  }, [userId])

  return <ScoreLinesContext.Provider value={lines}>{children}</ScoreLinesContext.Provider>
}
