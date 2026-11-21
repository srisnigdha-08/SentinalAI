// Rank 7: how a served persona is shown. windows_srv is an experimental Windows-like shell SIMULATION over Cowrie
// SSH, never a Windows host, so every place that names it says so. Mirrors backend utils/deceptionProfiles.js.
export const EXPERIMENTAL_PERSONAS = Object.freeze({
  windows_srv: 'simulated Windows shell, experimental',
})

/** Display text for a persona id; unknown or missing values are returned as given (or the fallback). */
export function personaLabel(id, fallback = 'Not recorded') {
  if (!id) return fallback
  const note = EXPERIMENTAL_PERSONAS[id]
  return note ? `${id} (${note})` : String(id)
}

export function isSimulatedWindows(id) {
  return id === 'windows_srv'
}
