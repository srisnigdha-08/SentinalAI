'use strict'
/**
 * What SentinelAI can actually do right now, for the dashboard's Capability Status page (docs/CAPABILITIES.md).
 * Every entry carries one label and the facts it rests on. Runtime facts (capture heartbeat, active containment
 * adapter, learner provenance, policy mode) are read live; evaluation results are fixed references to committed
 * evidence. A label is never upgraded beyond what that evidence supports.
 *
 * Labels: implemented_and_tested | implemented_not_enabled | simulated | shadow_only | experimental |
 *         blocked | not_implemented
 */
const LABELS = {
  implemented_and_tested: 'Implemented and tested',
  implemented_not_enabled: 'Implemented, not enabled',
  simulated: 'Simulated',
  shadow_only: 'Shadow only',
  experimental: 'Experimental',
  blocked: 'Blocked by missing infrastructure or evidence',
  not_implemented: 'Not implemented',
}

async function getCapabilities() {
  const capture = require('./captureStatusService').getStatus()
  const enforcement = require('./containment/adapterFactory').describeEnforcement()
  const correlation = require('./containmentCorrelationService').config()
  let engine = null
  try {
    const fn = require('./aiEngineService').getDeceptionStats
    engine = typeof fn === 'function' ? await fn() : null
  } catch {
    engine = null
  }
  const prov = engine?.provenance || null
  const v2Mode = engine?.v2Mode || 'unknown'

  const items = [
    {
      id: 'ml_generalization',
      title: 'Network-flow ML generalisation',
      label: 'experimental',
      summary:
        'Deployed model xgb_cicids_v1 is unchanged. Protocol v4 candidates (domain-balanced) were evaluated on unseen capture days and none met the pre-registered rule; no model was promoted.',
      facts: {
        deployedModel: 'xgb_cicids_v1',
        promoted: false,
        evidence: 'ai-engine/experiments/candidate_v4_20261113/results.json',
        needs: 'Independently labelled traffic from new networks, and the one-shot protected-day test (owner approval)',
      },
    },
    {
      id: 'network_capture',
      title: 'Network traffic source',
      label: capture.mode === 'unavailable' ? 'implemented_not_enabled' : 'implemented_and_tested',
      summary:
        capture.mode === 'live_passive'
          ? `Live passive capture running on ${capture.last?.interface || 'one interface'}.`
          : capture.mode === 'pcap_replay'
            ? `Recorded PCAP replay (${capture.state || 'running'}). Not live traffic.`
            : `Capture unavailable: ${capture.reason}`,
      facts: { mode: capture.mode, fresh: capture.fresh, counters: capture.last?.counters || null },
    },
    {
      id: 'host_firewall',
      title: 'Host-firewall containment',
      label: enforcement.hostFirewall === 'host_firewall' ? 'implemented_and_tested' : 'implemented_not_enabled',
      summary:
        enforcement.hostFirewall === 'host_firewall'
          ? `Real ${enforcement.backend} enforcement is active; every rule is verified after it is applied.`
          : 'Containment is SIMULATED (mock adapter). Windows Firewall and Linux iptables adapters exist and are tested with mocked commands, but are not enabled. Cowrie deny-list refusal is real for the honeypot.',
      facts: enforcement,
    },
    {
      id: 'cowrie_denylist',
      title: 'Honeypot deny-list enforcement',
      label: 'implemented_and_tested',
      summary: 'Cowrie refuses connections from deny-listed addresses (the honeypot only, not the host).',
      facts: {},
    },
    {
      id: 'auto_block_correlation',
      title: 'Automatic containment decisions',
      label: 'implemented_and_tested',
      summary:
        correlation.policy === 'correlated'
          ? `Correlated: at least ${correlation.minFlows} suspicious flows from one source in ${correlation.windowSeconds} s, ${correlation.minBlockLineFlows} at the block line. A single flow is held for analyst approval. Single-host only.`
          : 'Legacy single-flow policy (simulated enforcement only).',
      facts: { ...correlation, trusted: correlation.trusted.length, scope: 'single host (no multi-node correlation)' },
    },
    {
      id: 'qlearning_evidence',
      title: 'Q-learning evidence',
      label: 'experimental',
      summary: prov
        ? `Seed: ${prov.seedEpisodes ?? '?'} synthetic episodes. Sessions: ${prov.sessionEpisodes ?? '?'} (operator ${prov.bySource?.operator ?? 0}, external ${prov.bySource?.external ?? 0}, simulated ${prov.bySource?.simulated ?? 0}, unknown ${prov.bySource?.unknown ?? 0}, untracked ${prov.untrackedSessionEpisodes ?? '?'}). No independent external evidence yet.`
        : 'Learner statistics unavailable (AI engine not reachable).',
      facts: prov,
    },
    {
      id: 'windows_persona',
      title: 'Windows honeypot persona',
      label: 'not_implemented',
      summary:
        'windows_srv is unsupported and cannot be selected, served or recommended: Cowrie emulates a Linux shell only. A genuine Windows target would need an isolated Windows VM (not available).',
      facts: { servablePersonas: engine?.servablePersonas || null, unsupported: ['windows_srv'] },
    },
    {
      id: 'persona_policy_v2',
      title: 'Persona policy v2',
      label: v2Mode === 'active' ? 'experimental' : 'shadow_only',
      summary: `Mode: ${v2Mode}. Readiness: NOT READY (no external sessions; live rollback rehearsal not done). Never applied while in shadow.`,
      facts: { mode: v2Mode, evidence: 'docs/PERSONA_POLICY_V2.md' },
    },
    {
      id: 'deception_arena',
      title: 'Deception Arena',
      label: 'simulated',
      summary: 'Simulated attackers only. Results describe the simulator, not real attackers.',
      facts: { evidence: 'ai-engine/experiments/arena_profiles_20261113/results.json' },
    },
    {
      id: 'session_ml',
      title: 'Honeypot-session ML classifier',
      label: 'blocked',
      summary:
        'Session features, provenance and labelling pipeline exist. No classifier is trained: there are too few independently labelled sessions. Sessions are classified by MITRE rules.',
      facts: { classifier: 'rule-based (honeypot_rules)', evidence: 'docs/SESSION_ML.md' },
    },
  ]
  return { generatedAt: new Date().toISOString(), labels: LABELS, items }
}

module.exports = { getCapabilities, LABELS }
