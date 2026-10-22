'use strict'

// The six Cowrie personas. Must match PROFILES in ai-engine/rl_engine/deception_scorer.py,
// honeypot/switch_profile.py and PERSONAS in honeypot/parsers/log_parser.py.
const DECEPTION_PROFILES = ['ubuntu_22', 'debian_11', 'centos_7', 'windows_srv', 'aws_ec2', 'raspberry_pi']

module.exports = { DECEPTION_PROFILES }
