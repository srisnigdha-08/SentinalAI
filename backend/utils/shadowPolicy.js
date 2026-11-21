'use strict'
/**
 * Persona policy v2 shadow evidence (docs/PERSONA_POLICY_V2.md section 9). The engine reports v2's pick for every
 * scored session as `policyV2`; this keeps a validated, minimal record on the session (HoneypotSession.shadowPolicy),
 * separate from the persona actually served (servedProfile) and from v1's recommendation (recommendedProfile).
 *
 *   status OK                      a servable persona was recommended
 *   status INVALID_RECOMMENDATION  the pick was missing, unknown or unsupported (windows_srv): stored as null, never
 *                                  replaced by another persona
 *   status ERROR                   v2 failed for this session; errorCode names the exception type only
 * No IP address, command, credential or session content is stored. Nothing here can change what is served.
 */
const { SERVABLE_DECEPTION_PROFILES } = require('./deceptionProfiles')

const SCHEMA_VERSION = 'shadow-v2/1'
const CODE = /^[A-Za-z][A-Za-z0-9_]{0,63}$/

const str = (v, max) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null)

/** The record to store for one engine `policyV2` block, or null when the engine reported none (v2 off). */
function shadowPolicyRecord(v2) {
  if (!v2 || typeof v2 !== 'object' || Array.isArray(v2)) return null
  const base = {
    schemaVersion: SCHEMA_VERSION,
    version: str(v2.policyVersion, 64),
    mode: str(v2.mode, 16),
    learned: typeof v2.learned === 'boolean' ? v2.learned : null,
  }
  if (v2.error || v2.status === 'ERROR') {
    const code = typeof v2.error === 'string' && CODE.test(v2.error) ? v2.error : 'UNKNOWN_ERROR'
    return { ...base, recommendation: null, status: 'ERROR', errorCode: code }
  }
  const ok = SERVABLE_DECEPTION_PROFILES.includes(v2.recommendation)
  return {
    ...base,
    recommendation: ok ? v2.recommendation : null,
    status: ok ? 'OK' : 'INVALID_RECOMMENDATION',
    errorCode: null,
  }
}

module.exports = { SCHEMA_VERSION, shadowPolicyRecord }
