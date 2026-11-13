'use strict'

// The six Cowrie personas. Must match PROFILES in ai-engine/rl_engine/deception_scorer.py,
// honeypot/switch_profile.py and PERSONAS in honeypot/parsers/log_parser.py. Kept complete so historical records
// that name any of them still validate.
const DECEPTION_PROFILES = ['ubuntu_22', 'debian_11', 'centos_7', 'windows_srv', 'aws_ec2', 'raspberry_pi']

// Unsupported personas (docs/PERSONAS.md): Cowrie emulates a Linux shell only, so a Windows banner would
// misrepresent the host. They can never be selected, recorded as served from now on, or recommended.
const UNSUPPORTED_PROFILES = ['windows_srv']
const SERVABLE_DECEPTION_PROFILES = DECEPTION_PROFILES.filter((p) => !UNSUPPORTED_PROFILES.includes(p))

module.exports = { DECEPTION_PROFILES, UNSUPPORTED_PROFILES, SERVABLE_DECEPTION_PROFILES }
