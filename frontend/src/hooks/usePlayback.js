import { useEffect, useState, useSyncExternalStore } from 'react'
import { createPlaybackEngine } from '../utils/playbackEngine.js'

/**
 * One playback engine per mounted replay (the page keys the replay by session, so switching sessions mounts a fresh
 * engine). New events for the same session keep the position; unmount cancels any pending timer.
 */
export function usePlayback(events) {
  const [engine] = useState(() => createPlaybackEngine(events))
  useEffect(() => {
    engine.setEvents(events)
  }, [engine, events])
  useEffect(() => () => engine.dispose(), [engine])
  const state = useSyncExternalStore(engine.subscribe, engine.getState, engine.getState)
  return [state, engine]
}
