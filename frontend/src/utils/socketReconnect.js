// WS-001: Socket.IO does not retry by itself when the *server* ends or refuses the connection:
// - 'io server disconnect': the backend closed the socket because a session re-check failed (revocation, token
//   expiry, or an auth store that is unreachable during a MongoDB outage);
// - 'Authentication service unavailable': the handshake itself could not be checked (503, e.g. MongoDB still down).
// Retrying both is safe because every handshake is re-authorised from scratch. A rejected token ('Authentication
// rejected', 'Password change required') is never retried here; the connect_error path refreshes or signs out.
const RETRIED = new Set(['io server disconnect', 'Authentication service unavailable'])

/** Milliseconds to wait before reconnecting after `reason`, or null when Socket.IO (or nobody) should handle it. */
export function serverDisconnectRetryDelay(reason, attempt, random = Math.random) {
  if (!RETRIED.has(reason)) return null // transport drops are retried by Socket.IO; client closes are intended
  const base = Math.min(30000, 2000 * 2 ** Math.min(Math.max(0, attempt), 4)) // 2, 4, 8, 16, 30 s
  return Math.round(Math.min(30000, base * (0.75 + random() * 0.5)))
}
