import { useContext } from 'react'
import { ScoreLinesContext } from '../context/ScoreLinesContext.jsx'

/** { alert, block } the backend scores with (THR-003); the engine defaults outside the provider or before loading. */
export function useScoreLines() {
  return useContext(ScoreLinesContext)
}
