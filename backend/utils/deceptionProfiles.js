'use strict'

// The six Cowrie personas. Must match PROFILES in ai-engine/rl_engine/deception_scorer.py,
// honeypot/switch_profile.py and PERSONAS in honeypot/parsers/log_parser.py. Kept complete so historical records
// that name any of them still validate.
const DECEPTION_PROFILES = ['ubuntu_22', 'debian_11', 'centos_7', 'windows_srv', 'aws_ec2', 'raspberry_pi']

// Unsupported personas (docs/PERSONAS.md): Cowrie emulates a Linux shell only, so a Windows banner would
// misrepresent the host. They can never be selected, recorded as served from now on, or recommended.
const UNSUPPORTED_PROFILES = ['windows_srv']
const SERVABLE_DECEPTION_PROFILES = DECEPTION_PROFILES.filter((p) => !UNSUPPORTED_PROFILES.includes(p))

// Rank 7: windows_srv now has an implemented, tested Windows-like shell *simulation* (honeypot/windows_persona), but
// it stays out of production: it remains in UNSUPPORTED_PROFILES, so nothing above changes. Support and production
// eligibility are separate facts.
const EXPERIMENTAL_PROFILES = ['windows_srv']
const PERSONA_STATUS = Object.freeze(
  Object.fromEntries(
    DECEPTION_PROFILES.map((p) => [
      p,
      Object.freeze(
        EXPERIMENTAL_PROFILES.includes(p)
          ? {
              supported: true,
              experimental: true,
              productionEligible: false,
              servingEnabled: false,
              simulation: 'windows-like shell simulation over Cowrie SSH; not a Windows host',
            }
          : { supported: true, experimental: false, productionEligible: true, servingEnabled: true, simulation: null }
      ),
    ])
  )
)

module.exports = {
  DECEPTION_PROFILES,
  UNSUPPORTED_PROFILES,
  SERVABLE_DECEPTION_PROFILES,
  EXPERIMENTAL_PROFILES,
  PERSONA_STATUS,
}
