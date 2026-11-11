// Attack Time Machine playback: a framework-free, deterministic stepper over already-ordered timeline events.
// It only moves an index on a timer. It never issues requests or runs anything recorded in the events.

export const SPEEDS = Object.freeze([0.5, 1, 2, 4])
export const MIN_STEP_MS = 300
export const MAX_STEP_MS = 3000
const DEFAULT_GAP_MS = 1000

/** Delay before advancing from `index`: the recorded gap scaled by speed, clamped (long idle gaps compressed). */
export function stepDelay(events, index, speed = 1) {
  const a = events?.[index]?.time
  const b = events?.[index + 1]?.time
  const gap = Number.isFinite(a) && Number.isFinite(b) ? Math.max(0, b - a) : DEFAULT_GAP_MS
  const raw = gap / (SPEEDS.includes(speed) ? speed : 1)
  return { delay: Math.min(MAX_STEP_MS, Math.max(MIN_STEP_MS, raw)), compressed: raw > MAX_STEP_MS }
}

export function createPlaybackEngine(initialEvents = [], { setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
  let events = Array.isArray(initialEvents) ? initialEvents : []
  let state = { index: events.length ? 0 : -1, playing: false, speed: 1, total: events.length }
  let timer = null
  const listeners = new Set()

  const emit = () => listeners.forEach((l) => l())
  const set = (patch) => {
    state = { ...state, ...patch }
    emit()
  }
  const cancel = () => {
    if (timer !== null) {
      clearTimer(timer)
      timer = null
    }
  }
  const atEnd = () => state.index >= state.total - 1
  const arm = () => {
    cancel()
    if (!state.playing) return
    if (atEnd()) return set({ playing: false })
    timer = setTimer(() => {
      timer = null
      if (!state.playing) return
      const index = Math.min(state.index + 1, state.total - 1)
      set({ index, playing: index < state.total - 1 })
      arm()
    }, stepDelay(events, state.index, state.speed).delay)
  }
  const clampIndex = (i) => (state.total ? Math.max(0, Math.min(state.total - 1, Math.trunc(Number(i) || 0))) : -1)

  return {
    getState: () => state,
    subscribe(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    play() {
      if (!state.total) return
      set({ playing: true, index: atEnd() ? 0 : state.index })
      arm()
    },
    pause() {
      cancel()
      if (state.playing) set({ playing: false })
    },
    toggle() {
      state.playing ? this.pause() : this.play()
    },
    next() {
      if (!state.total) return
      set({ index: clampIndex(state.index + 1) })
      arm()
    },
    prev() {
      if (!state.total) return
      set({ index: clampIndex(state.index - 1) })
      arm()
    },
    seek(i) {
      if (!state.total) return
      set({ index: clampIndex(i) })
      arm()
    },
    restart() {
      if (!state.total) return
      set({ index: 0 })
      arm()
    },
    setSpeed(speed) {
      if (!SPEEDS.includes(speed)) return
      set({ speed })
      arm()
    },
    /** New events for the same session (live append): keeps the position, clamps it into range. */
    setEvents(nextEvents) {
      events = Array.isArray(nextEvents) ? nextEvents : []
      const total = events.length
      const index = total ? Math.min(Math.max(state.index, 0), total - 1) : -1
      set({ total, index, playing: state.playing && total > 0 })
      arm()
    },
    /** Stops playback and cancels any pending timer. The engine can be used again afterwards. */
    dispose() {
      cancel()
      if (state.playing) state = { ...state, playing: false }
    },
    hasPendingTimer: () => timer !== null,
  }
}
