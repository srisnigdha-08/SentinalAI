const mitreMapping = require('../utils/mitreMapping')
const logger = require('../utils/logger')

jest.mock('../utils/logger', () => ({
  warn: jest.fn(),
  info: jest.fn(),
  error: jest.fn(),
}))

describe('MITRE ATT&CK Mapping Utility', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  test('should map every intent in MITRE_ATTACK_MAP to valid technique details', () => {
    const intents = Object.keys(mitreMapping.MITRE_ATTACK_MAP)
    expect(intents.length).toBeGreaterThan(0)

    intents.forEach((intent) => {
      const techniques = mitreMapping.getMitreTechniquesForIntents([intent])
      expect(techniques).toBeInstanceOf(Array)
      expect(techniques.length).toBeGreaterThan(0)

      techniques.forEach((tech) => {
        expect(tech).toHaveProperty('id')
        expect(tech).toHaveProperty('name')
        expect(tech.id).toMatch(/^T\d{4}$/)
      })
    })
  })

  test('should map every attackType in THREAT_MITRE_MAP to valid technique details', () => {
    const threats = Object.keys(mitreMapping.THREAT_MITRE_MAP)
    expect(threats.length).toBeGreaterThan(0)

    threats.forEach((threat) => {
      const techniques = mitreMapping.getMitreTechniquesForThreat(threat)
      expect(techniques).toBeInstanceOf(Array)
      expect(techniques.length).toBeGreaterThan(0)

      techniques.forEach((tech) => {
        expect(tech).toHaveProperty('id')
        expect(tech).toHaveProperty('name')
        expect(tech.id).toMatch(/^T\d{4}$/)
      })
    })
  })

  test('should return empty list and log a warning for an unmapped intent', () => {
    const techniques = mitreMapping.getMitreTechniquesForIntents(['UNMAPPED_INTENT_XYZ'])
    expect(techniques).toEqual([])
    expect(logger.warn).toHaveBeenCalledTimes(1)
    expect(logger.warn.mock.calls[0][0]).toContain('No MITRE technique mapping found for intent: "UNMAPPED_INTENT_XYZ"')
  })

  test('should return empty list and log a warning for an unmapped threat attackType', () => {
    const techniques = mitreMapping.getMitreTechniquesForThreat('Unmapped Attack Type ABC')
    expect(techniques).toEqual([])
    expect(logger.warn).toHaveBeenCalledTimes(1)
    expect(logger.warn.mock.calls[0][0]).toContain(
      'No MITRE technique mapping found for threat attackType: "Unmapped Attack Type ABC"'
    )
  })

  test('should ignore UNKNOWN or empty intent values without warning', () => {
    const techniques = mitreMapping.getMitreTechniquesForIntents(['UNKNOWN', '', null, undefined])
    expect(techniques).toEqual([])
    expect(logger.warn).not.toHaveBeenCalled()
  })

  test('should return empty list and not log warning for "Unknown" threat type', () => {
    const techniques = mitreMapping.getMitreTechniquesForThreat('Unknown')
    expect(techniques).toEqual([])
    expect(logger.warn).not.toHaveBeenCalled()
  })
})
