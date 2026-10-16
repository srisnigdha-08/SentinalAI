/**
 * MITRE ATT&CK Mapping Utility
 * Maps command intents and threat classifications to MITRE technique IDs and names.
 */
const logger = require('./logger')

const MITRE_ATTACK_MAP = {
  CREDENTIAL_HARVEST: [{ id: 'T1003', name: 'OS Credential Dumping' }],
  MALWARE_DOWNLOAD: [{ id: 'T1105', name: 'Ingress Tool Transfer' }],
  REVERSE_SHELL: [
    { id: 'T1059', name: 'Command and Scripting Interpreter' },
    { id: 'T1071', name: 'Application Layer Protocol' },
  ],
  PERSISTENCE: [
    { id: 'T1543', name: 'Create or Modify System Process' },
    { id: 'T1053', name: 'Scheduled Task/Job' },
  ],
  PRIVILEGE_ESCALATION: [{ id: 'T1548', name: 'Abuse Elevation Control Mechanism' }],
  RECONNAISSANCE: [{ id: 'T1595', name: 'Active Scanning' }],
  DESTRUCTION: [{ id: 'T1485', name: 'Data Destruction' }],
}

const THREAT_MITRE_MAP = {
  'SSH Brute Force': [{ id: 'T1110', name: 'Brute Force' }],
  'SSH Intrusion Attempt': [
    { id: 'T1110', name: 'Brute Force' },
    { id: 'T1021', name: 'Remote Services' },
  ],
  'SQL Injection': [{ id: 'T1190', name: 'Exploit Public-Facing Application' }],
  DDoS: [{ id: 'T1498', name: 'Network Denial of Service' }],
  'Port Scan': [{ id: 'T1046', name: 'Network Service Discovery' }],
  'RCE Attempt': [{ id: 'T1190', name: 'Exploit Public-Facing Application' }],
  'XSS Attempt': [{ id: 'T1190', name: 'Exploit Public-Facing Application' }],
  'Malware Beacon': [{ id: 'T1071', name: 'Application Layer Protocol' }],
  'Credential Stuffing': [{ id: 'T1110', name: 'Brute Force' }],
  Ransomware: [{ id: 'T1486', name: 'Data Encrypted for Impact' }],
  'Lateral Movement': [{ id: 'T1021', name: 'Remote Services' }],
  'Data Exfiltration': [{ id: 'T1048', name: 'Exfiltration Over Alternative Protocol' }],
  'Zero-Day Exploit': [{ id: 'T1190', name: 'Exploit Public-Facing Application' }],
}

function getMitreTechniquesForIntents(intents) {
  const techniques = []
  const seen = new Set()

  for (const intent of intents) {
    if (!intent || intent === 'UNKNOWN') continue
    const mappings = MITRE_ATTACK_MAP[intent]
    if (mappings) {
      for (const tech of mappings) {
        if (!seen.has(tech.id)) {
          seen.add(tech.id)
          techniques.push(tech)
        }
      }
    } else {
      logger.warn(`[MITRE Mapping] No MITRE technique mapping found for intent: "${intent}"`)
    }
  }
  return techniques
}

function getMitreTechniquesForThreat(attackType) {
  if (!attackType || attackType === 'Unknown') return []
  const mappings = THREAT_MITRE_MAP[attackType]
  if (!mappings) {
    logger.warn(`[MITRE Mapping] No MITRE technique mapping found for threat attackType: "${attackType}"`)
    return []
  }
  return mappings
}

module.exports = {
  MITRE_ATTACK_MAP,
  THREAT_MITRE_MAP,
  getMitreTechniquesForIntents,
  getMitreTechniquesForThreat,
}
