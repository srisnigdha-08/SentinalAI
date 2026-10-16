'use strict'

/**
 * Authoritative canonical prediction classes for SentinelAI ML classification.
 * Exactly aligns with CICIDS2017 multiclass labels and Random Forest production model:
 * rf_classifier_cicids_v2.pkl (LABEL_MAP / classes in metadata).
 */
const CANONICAL_CLASSES = Object.freeze([
  'BENIGN',
  'SSH Brute Force',
  'SQL Injection',
  'Port Scan',
  'DDoS',
  'RCE Attempt',
  'XSS Attempt',
  'Malware Beacon',
  'Credential Stuffing',
  'Lateral Movement',
  'Data Exfiltration',
])

/**
 * Validates whether a provided class string exactly matches one of the canonical classes.
 * Rejects leading/trailing whitespace variations if untrimmed, case mismatches, typos, and empty strings.
 */
const isValidCanonicalClass = (cls) => {
  if (typeof cls !== 'string') return false
  return CANONICAL_CLASSES.includes(cls.trim())
}

module.exports = {
  CANONICAL_CLASSES,
  isValidCanonicalClass,
}
