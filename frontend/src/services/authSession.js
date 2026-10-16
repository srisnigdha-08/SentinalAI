import { createAuthClient } from './authClient.js'
let storage
try { storage = window.localStorage } catch {}
export const authSession = createAuthClient({ fetch: (...args) => window.fetch(...args),
  locks: navigator.locks, channel: typeof BroadcastChannel === 'function' ? new BroadcastChannel('sentinel-auth-v2') : null,
  storage, base: (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '') })
