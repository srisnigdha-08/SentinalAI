'use strict'
/**
 * What SentinelAI can actually do right now, for the dashboard's Capability Status page (docs/CAPABILITIES.md).
 * Every entry carries one label and the facts it rests on. Runtime facts (capture heartbeat, active containment
 * adapter, learner provenance, policy mode) are read live; evaluation results are fixed references to committed
 * evidence. A label is never upgraded beyond what that evidence supports.
 *
 * Labels: implemented_and_verified | implemented_and_tested | implemented_and_tested_simulated |
 *         implemented_not_enabled | simulated | shadow_only | experimental | blocked | not_implemented
 * implemented_and_tested_simulated: working and tested, but it simulates the effect (no real system is changed).
 * implemented_and_verified is used only where a named, automated end-to-end test suite exercises the whole workflow
 * (see facts.evidence); it is not a runtime claim that the workflow is running now.
 */
const fs = require('fs')
const path = require('path')

const LABELS = {
  implemented_and_verified: 'Implemented and verified',
  implemented_and_tested: 'Implemented and tested',
  implemented_and_tested_simulated: 'Implemented and tested (simulated)',
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
  let sessionMl = null
  try {
    const fn = require('./aiEngineService').getSessionMlStatus
    sessionMl = typeof fn === 'function' ? await fn() : null
  } catch {
    sessionMl = null
  }
  const v2Mode = engine?.v2Mode || 'unknown'

  const items = [
    // Network-flow generalisation is two facts: the Rank 5 evaluation tooling (ready or not) and what the evidence
    // shows about the frozen model. A working evaluator never upgrades the generalisation entry.
    ...mlGeneralisationItems(latestRank5Status()),
    // Two separate entries: a verified offline PCAP replay must never make live capture look available.
    pcapReplayItem(capture),
    liveCaptureItem(capture),
    // Host-firewall containment is three separate facts: adapter code verified with mocked commands, real
    // enforcement (not enabled), and the simulated default. Mocked tests never upgrade real enforcement.
    ...firewallContainmentItems(enforcement),
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
    // Q-learning is two separate facts: the evidence system (verified by tests) and whether the policy works
    // (not shown: the evidence is synthetic and operator-generated). Passing evidence tests never upgrades the second.
    ...qlearningItems(prov),
    // Rank 7: the Windows persona is two facts. The simulation (implemented, tested) and production serving
    // (disabled: experimental, not eligible). A tested simulation never makes the persona servable.
    ...windowsPersonaItems(engine, latestRank7Status()),
    // Persona policy v2 is two facts: its shadow machinery (verified by tests and a read-only evaluation) and its
    // readiness to decide (evidence-gated). A verified shadow pipeline never upgrades readiness.
    ...personaPolicyV2Items(v2Mode, latestRank6Status(), engine?.v2Activation || null),
    {
      id: 'deception_arena',
      title: 'Deception Arena',
      label: 'simulated',
      summary: 'Simulated attackers only. Results describe the simulator, not real attackers.',
      facts: { evidence: 'ai-engine/experiments/arena_profiles_20261113/results.json' },
    },
    // Honeypot-session ML is three facts: the pipeline (verified by tests), the model (none: no independent labels)
    // and effectiveness (unevaluated). Infrastructure tests never upgrade the model or its effectiveness.
    ...sessionMlItems(sessionMl),
  ]
  return { generatedAt: new Date().toISOString(), labels: LABELS, items }
}

// Rank 7 (docs/PERSONAS.md, "Simulated Windows persona"): the newest rank7 run's rank7_status.json. Missing or
// unreadable evidence is reported as such, never as a pass.
const RANK7_DIR = path.join(__dirname, '..', '..', 'audit', 'rank7_windows_persona')
const RANK7_TESTS = [
  'ai-engine/tests/test_windows_persona.py',
  'backend/tests/rank7WindowsPersona.test.js',
  'frontend/tests/personaLabels.test.mjs',
]

function latestRank7Status(dir = RANK7_DIR) {
  try {
    const runs = fs
      .readdirSync(dir, { withFileTypes: true })
      .filter((d) => d.isDirectory() && d.name.startsWith('run_'))
      .map((d) => d.name)
      .sort()
      .reverse()
    if (!runs.length) return null
    // only the newest run counts; an older passing run never stands in for a newer broken one
    const data = JSON.parse(fs.readFileSync(path.join(dir, runs[0], 'rank7_status.json'), 'utf8'))
    if (data && typeof data === 'object' && data.tests)
      return { ...data, evidence: `audit/rank7_windows_persona/${runs[0]}/` }
  } catch {
    // fall through: no readable evidence
  }
  return null
}

function windowsPersonaItems(engine, r7) {
  const { PERSONA_STATUS } = require('../utils/deceptionProfiles')
  const status = PERSONA_STATUS.windows_srv
  const tested = Boolean(r7 && r7.tests && r7.tests.passed === true && r7.tests.failed === 0)
  return [
    {
      id: 'windows_persona_simulation',
      title: 'Windows persona: simulated Windows-style shell',
      label: tested ? 'implemented_and_tested_simulated' : 'implemented_not_enabled',
      summary: tested
        ? 'A Windows Server-style shell SIMULATION over Cowrie SSH: allowlisted cmd/PowerShell-style commands with fictional output and an isolated in-memory filesystem. Nothing is executed on the host. Unit, security and adapter tests pass; not deployed, no live sessions. It is not a Windows host, and RDP, SMB and WinRM are not simulated.'
        : 'The Windows-style shell simulation is present but no passing Rank 7 test evidence was found on this machine.',
      facts: {
        implementation: 'implemented',
        testVerification: tested ? 'passed' : r7 ? 'failed' : 'not_verified',
        simulated: true,
        live: false,
        cowrieVersionChecked: r7?.cowrieVersion || null,
        supportedCommands: r7?.supportedCommandCount || null,
        evidence: r7?.evidence || null,
        tests: RANK7_TESTS,
      },
    },
    {
      id: 'windows_persona',
      title: 'Windows honeypot persona (production serving)',
      label: 'implemented_not_enabled',
      summary:
        'windows_srv is EXPERIMENTAL and not production-eligible: it cannot be selected, served or recommended by the learner, persona policy v2, the rotator, the profile switcher or the backend. Sessions served by it would be scored but never learned. A genuine Windows target would need an isolated Windows VM (not available).',
      facts: {
        servablePersonas: engine?.servablePersonas || null,
        unsupported: ['windows_srv'],
        supported: status.supported,
        experimental: status.experimental,
        productionEligible: status.productionEligible,
        servingEnabled: status.servingEnabled,
      },
    },
  ]
}

// Rank 6 (docs/PERSONA_POLICY_V2.md section 9): the newest rank6 run's readiness_status.json. Missing or unreadable
// evidence is reported as such, never as a pass.
const RANK6_DIR = path.join(__dirname, '..', '..', 'audit', 'rank6_persona_policy_v2')
const RANK6_TESTS = [
  'ai-engine/tests/test_rank6_v2_shadow.py',
  'ai-engine/tests/test_persona_policy_v2.py',
  'backend/tests/rank6PersonaPolicyV2.test.js',
]

function latestRank6Status(dir = RANK6_DIR) {
  try {
    const runs = fs
      .readdirSync(dir, { withFileTypes: true })
      .filter((d) => d.isDirectory() && d.name.startsWith('run_'))
      .map((d) => d.name)
      .sort()
      .reverse()
    for (const run of runs) {
      const file = path.join(dir, run, 'readiness_status.json')
      if (!fs.existsSync(file)) continue
      const data = JSON.parse(fs.readFileSync(file, 'utf8'))
      // newest: false marks a fallback to an older run; such a run is shown but can never count as READY.
      if (data && data.gates && data.overall)
        return { ...data, evidence: `audit/rank6_persona_policy_v2/${run}/`, newest: run === runs[0] }
    }
  } catch {
    // fall through: no readable evidence
  }
  return null
}

// The ten mandatory gates (ai-engine/rl_engine/v2_activation.py MANDATORY_GATES).
const RANK6_GATES = [
  '1_shadow_isolation',
  '2_persona_compatibility',
  '3_invalid_action_handling',
  '4_failure_isolation',
  '5_evidence_schema_and_provenance',
  '6_reproducible_evaluation',
  '7_adequate_session_evidence',
  '8_independent_evidence',
  '9_decision_stability',
  '10_documented_acceptance_criteria',
]

// Rank 6 corrections: whether v2 may serve. The engine's own fail-closed decision (GET /deception/stats
// v2Activation) when reachable; otherwise derived the same way from the evidence: blocked unless READY.
function v2ActivationStatus(v2Mode, readiness, engineActivation) {
  if (engineActivation && typeof engineActivation === 'object' && typeof engineActivation.allowed === 'boolean') {
    return {
      requested: Boolean(engineActivation.requested),
      allowed: engineActivation.allowed === true,
      reason: String(engineActivation.reason || 'UNKNOWN'),
      source: 'engine',
    }
  }
  if (v2Mode !== 'active') return { requested: false, allowed: false, reason: 'NOT_REQUESTED', source: 'evidence' }
  // Without the engine's decision, never claim v2 is serving.
  return {
    requested: true,
    allowed: false,
    reason: readiness === 'READY' ? 'ENGINE_UNREACHABLE' : `READINESS_${readiness}`,
    source: 'evidence',
  }
}

function personaPolicyV2Items(v2Mode, r6, engineActivation = null) {
  const gates = r6?.gates || {}
  const status = (k) => gates[k]?.status || 'NOT_VERIFIED'
  const shadowOk = r6?.shadow_engineering === 'PASS'
  // READY is only ever shown when the newest evidence file says READY and every mandatory gate passed; nothing
  // here can promote v2.
  const allGatesPass = RANK6_GATES.every((g) => status(g) === 'PASS')
  const readiness = r6
    ? r6.overall === 'READY' && allGatesPass && r6.newest !== false
      ? 'READY'
      : r6.overall === 'FAILED'
        ? 'FAILED'
        : 'NOT_READY'
    : 'NOT_VERIFIED'
  const activation = v2ActivationStatus(v2Mode, readiness, engineActivation)
  const prov = r6?.session_provenance || null
  const activationText = activation.allowed
    ? 'Activation: v2 is serving (owner switch on and readiness evidence READY).'
    : activation.requested
      ? `Activation requested (DECEPTION_V2=active) but blocked (${activation.reason}); v1 serves.`
      : 'Activation: blocked unless the owner switch is on AND the newest readiness evidence is READY (fail-closed).'
  return [
    {
      id: 'persona_policy_v2_shadow',
      title: 'Persona policy v2: shadow pipeline and isolation',
      label: shadowOk ? 'implemented_and_verified' : r6 ? 'blocked' : 'implemented_not_enabled',
      summary: shadowOk
        ? 'v2 computes a separate, validated recommendation for every scored session and records it as shadow evidence. Isolation is verified: with v2 healthy, failing, timing out or returning an unsupported persona, v1 makes the same decisions and learns the same Q-table; v2 cannot share the v1 table. This verifies the shadow pipeline, not that v2 is better.'
        : r6
          ? 'The last Rank 6 run did not pass its shadow engineering checks.'
          : 'No Rank 6 evaluation run is present on this machine.',
      facts: {
        isolation: status('1_shadow_isolation'),
        personaCompatibility: status('2_persona_compatibility'),
        invalidActionHandling: status('3_invalid_action_handling'),
        failureIsolation: status('4_failure_isolation'),
        evidenceSchema: status('5_evidence_schema_and_provenance'),
        reproducibleComparison: status('6_reproducible_evaluation'),
        evidence: r6?.evidence || null,
        tests: RANK6_TESTS,
      },
    },
    {
      id: 'persona_policy_v2',
      title: 'Persona policy v2',
      label: activation.allowed ? 'experimental' : 'shadow_only',
      summary: `Mode: ${v2Mode}. Production policy: ${activation.allowed ? 'v2' : 'v1 (Q-learning)'}. Readiness: ${readiness === 'READY' ? 'READY (owner activation still required)' : readiness.replace('_', ' ')}${
        r6
          ? ` (session evidence ${status('7_adequate_session_evidence')}, independent evidence ${status('8_independent_evidence')}, decision stability ${status('9_decision_stability')} in simulation, acceptance criteria ${status('10_documented_acceptance_criteria')})`
          : ' (no external sessions; live rollback rehearsal not done)'
      }. v1 decides; v2 is never applied while in shadow and is never activated automatically. ${activationText}${
        prov
          ? ` Session provenance: ${prov.total_sessions_evaluated} replayed sessions, labelled operator ${prov.labelled_operator_in_replay} (inferred from source address), verified provenance ${prov.with_recorded_and_verified_provenance}, untracked ${prov.with_untracked_or_unverifiable_provenance}, independently verified external ${prov.independently_verified_external}.`
          : ''
      }`,
      facts: {
        mode: v2Mode,
        productionPolicy: activation.allowed ? 'persona_policy_v2' : 'v1_q_learning',
        readiness,
        activation,
        mandatoryGates: r6 ? Object.fromEntries(RANK6_GATES.map((g) => [g, status(g)])) : null,
        sessionProvenance: prov,
        independentExternalSessions: prov ? prov.independently_verified_external : 0,
        evidenceGates: r6
          ? {
              sessionEvidence: status('7_adequate_session_evidence'),
              independentEvidence: status('8_independent_evidence'),
              decisionStability: status('9_decision_stability'),
              acceptanceCriteria: status('10_documented_acceptance_criteria'),
            }
          : null,
        rank6Evidence: r6?.evidence || null,
        evidence: 'docs/PERSONA_POLICY_V2.md',
      },
    },
  ]
}

// Rank 5 (docs/ML_GENERALISATION.md): the newest non-smoke run's rank5_status.json, read from disk. Missing or
// unreadable evidence is reported as such, never as a pass.
const RANK5_DIR = path.join(__dirname, '..', '..', 'audit', 'rank5_network_flow_generalisation')
const RANK5_TESTS = ['ai-engine/tests/test_rank5_generalisation.py', 'backend/tests/rank5Capability.test.js']

function latestRank5Status(dir = RANK5_DIR) {
  try {
    const runs = fs
      .readdirSync(dir, { withFileTypes: true })
      .filter((d) => d.isDirectory() && d.name.startsWith('run_') && !d.name.includes('smoke'))
      .map((d) => d.name)
      .sort()
      .reverse()
    for (const run of runs) {
      const file = path.join(dir, run, 'rank5_status.json')
      if (!fs.existsSync(file)) continue
      const data = JSON.parse(fs.readFileSync(file, 'utf8'))
      if (data && data.smoke_run_not_evidence !== true && data.status) {
        return { ...data, evidence: `audit/rank5_network_flow_generalisation/${run}/` }
      }
    }
  } catch {
    // fall through: no readable evidence
  }
  return null
}

const pct = (v) => (typeof v === 'number' && Number.isFinite(v) ? `${(v * 100).toFixed(1)} %` : 'n/a')

function mlGeneralisationItems(r5) {
  const st = r5?.status || {}
  const h = r5?.headline || {}
  const toolingReady = st.evaluation_tooling === 'READY' && st.model_integrity === 'READY'
  return [
    {
      id: 'ml_evaluation_tooling',
      title: 'Network-flow evaluation tooling (frozen model, Rank 5)',
      label: toolingReady ? 'implemented_and_verified' : r5 ? 'blocked' : 'implemented_not_enabled',
      summary: toolingReady
        ? 'A read-only evaluator scores the frozen xgb_cicids_v1 through the served code path (artifact hashes checked before and after, production-path parity on samples), on three separate sets with leakage checks, per-class and per-day metrics and drift diagnostics. Evaluation tooling is ready; that is not evidence that the model generalises.'
        : r5
          ? `The last Rank 5 run did not complete its checks (tooling ${st.evaluation_tooling || 'unknown'}, integrity ${st.model_integrity || 'unknown'}).`
          : 'No Rank 5 evaluation run is present on this machine (ai-engine/evaluation/rank5_generalisation.py has not been run here).',
      facts: { status: r5 ? st : null, evidence: r5?.evidence || null, tests: RANK5_TESTS },
    },
    {
      id: 'ml_generalization',
      title: 'Network-flow ML generalisation',
      label: 'experimental',
      summary: r5
        ? `Independent generalisation: ${st.independent_generalisation || 'NOT_VERIFIED'}. Random split (in-distribution, not independent): accuracy ${pct(h.e1_accuracy)}, macro F1 ${pct(h.e1_f1_macro)}. Later traffic from another network (CSE-CIC-IDS2018 development days, used earlier in development): accuracy ${pct(h.e3_accuracy)}, balanced accuracy ${pct(h.e3_balanced_accuracy)}, macro F1 ${pct(h.e3_f1_macro)}, attack recall at the alert line ${pct(h.e3_attack_recall_alert_line)}, benign false-positive rate ${pct(h.e3_benign_fpr_alert_line)}. Deployed model xgb_cicids_v1 is unchanged; no model was promoted.`
        : 'Deployed model xgb_cicids_v1 is unchanged. Protocol v4 candidates (domain-balanced) were evaluated on unseen capture days and none met the pre-registered rule; no model was promoted. No Rank 5 evaluation of the frozen model is present here.',
      facts: {
        deployedModel: 'xgb_cicids_v1',
        promoted: false,
        independentGeneralisation: st.independent_generalisation || 'NOT_VERIFIED',
        chronologicalEvaluation: st.chronological_evaluation || 'INSUFFICIENT_DATA',
        leakageChecks: st.leakage_checks || 'NOT_VERIFIED',
        driftDiagnostics: st.drift_diagnostics || 'INSUFFICIENT_DATA',
        finding: st.generalisation_finding || null,
        rank5Evidence: r5?.evidence || null,
        evidence: 'ai-engine/experiments/candidate_v4_20261113/results.json',
        needs: 'Independently labelled traffic from new networks, and the one-shot protected-day test (owner approval)',
      },
    },
  ]
}

// Honeypot-session ML: tests of the feature contract, artifact safety, shadow inference and integration.
const SESSION_ML_TESTS = [
  'ai-engine/tests/test_session_ml_classifier.py',
  'ai-engine/tests/test_session_ml.py',
  'backend/tests/sessionMlIntegration.test.js',
  'frontend/tests/sessionMl.test.mjs',
]
// The read-only label audit behind the "no model" decision.
const SESSION_ML_AUDIT = 'ai-engine/experiments/session_ml_data_audit_20261113/audit.json'

function sessionMlItems(status) {
  // A model can only ever be reported as loaded in SHADOW; nothing in the engine has an active mode.
  const loaded = status?.modelStatus === 'OK'
  const engine = status
    ? `Engine: mode ${status.mode}, schema ${status.featureSchemaVersion}, model ${status.modelStatus}${status.reason ? ` (${status.reason})` : ''}.`
    : 'Engine status unavailable (AI engine not reachable).'
  return [
    {
      id: 'session_ml_pipeline',
      title: 'Honeypot-session ML pipeline (features, inference, shadow integration)',
      label: 'implemented_and_verified',
      summary: `Versioned session feature schema (session_v2), safe JSON model loading with hash and schema checks, shadow-only inference returned beside the rule-based result, backend storage and dashboard display are verified by automated tests. It never changes the rule result, alerts or containment. ${engine}`,
      facts: {
        featureSchemaVersion: status?.featureSchemaVersion || 'session_v2',
        separateFrom: 'xgb_cicids_v1 (network flows, 53 features)',
        evidence: SESSION_ML_TESTS,
        engine: status,
      },
    },
    {
      id: 'session_ml',
      title: 'Honeypot-session ML model',
      label: loaded ? 'shadow_only' : 'blocked',
      summary: loaded
        ? `A session model (${status.modelVersion}) is loaded in SHADOW: its predictions are shown beside the rules and never acted on.`
        : 'SHADOW ONLY — INSUFFICIENT LABELLED DATA. No model is trained: the read-only audit of 119 honeypot sessions found 0 independently labelled sessions (every class label comes from the rule-based classifier, which a model would only imitate). Sessions are classified by the MITRE rules.',
      facts: {
        classifier: 'rule-based (honeypot_rules)',
        modelLoaded: loaded,
        audit: SESSION_ML_AUDIT,
        readinessGate: '>= 30 independent labels in >= 2 classes, spanning >= 14 days',
        evidence: 'docs/SESSION_ML.md',
      },
    },
    {
      id: 'session_ml_effectiveness',
      title: 'Honeypot-session classifier effectiveness',
      label: 'experimental',
      summary:
        'Not evaluated: there is no model and no independent test set. No accuracy claim is made for session classification by ML.',
      facts: { independentlyEvaluated: false, audit: SESSION_ML_AUDIT },
    },
  ]
}

// Q-learning evidence management: tests that exercise provenance, dedupe, the bounded log and the read-only report
// on isolated copies (the deployed tables are never written).
const QLEARNING_EVIDENCE_TESTS = [
  'ai-engine/tests/test_qlearning_evidence_management.py',
  'ai-engine/tests/test_qlearning_provenance.py',
  'backend/tests/qlearningEvidenceCapability.test.js',
  'backend/tests/limitationRemediation.test.js',
]
// The committed, read-only measurement of the operator demo table (evaluation/qlearning_evidence_report.py).
const QLEARNING_EVIDENCE_REPORT = 'ai-engine/experiments/qlearning_evidence_v2_20261113/report.json'

function qlearningItems(prov) {
  const live = prov
    ? `Engine now: ${prov.seedEpisodes ?? '?'} synthetic seed episodes; session updates ${prov.sessionEpisodes ?? '?'} (operator ${prov.bySource?.operator ?? 0}, external ${prov.bySource?.external ?? 0}, simulated ${prov.bySource?.simulated ?? 0}, unknown ${prov.bySource?.unknown ?? 0}, untracked ${prov.untrackedSessionEpisodes ?? '?'}); duplicates rejected ${prov.duplicatesRejected ?? 0}.`
    : 'Live learner statistics unavailable (AI engine not reachable).'
  return [
    {
      id: 'qlearning_evidence',
      title: 'Q-learning evidence management',
      label: 'implemented_and_verified',
      summary: `Evidence provenance (operator / external / simulated / unknown, missing and invalid labels counted), duplicate-session protection (replays, concurrent writers, failed saves), a bounded update log and a reproducible read-only report are verified by automated tests on isolated copies. This says nothing about whether the policy works. ${live}`,
      facts: {
        scope: [
          'evidence-source provenance',
          'duplicate-session protection',
          'bounded update log',
          'source-specific counts',
          'read-only reporting',
        ],
        sources: ['operator', 'external', 'simulated', 'unknown'],
        independentSource: 'external (only under authorised collection)',
        evidence: QLEARNING_EVIDENCE_TESTS,
        report: QLEARNING_EVIDENCE_REPORT,
        live: prov,
      },
    },
    {
      id: 'qlearning_effectiveness',
      title: 'Q-learning policy effectiveness',
      label: 'experimental',
      summary:
        'INSUFFICIENT INDEPENDENT EVIDENCE. The measured table holds 12,106 episodes: 12,087 (99.84 %) from the synthetic warm start and 19 session-driven updates, recorded before provenance tracking (operator-generated according to the session records; the table itself does not record their source). 0 independent external sessions. The 19 updates changed none of the 6 greedy decisions, and debian_11, aws_ec2 and raspberry_pi have no real session. Independent evidence is needed before any claim about real-world effectiveness.',
      facts: {
        report: QLEARNING_EVIDENCE_REPORT,
        totalEpisodes: 12106,
        syntheticSeedEpisodes: 12087,
        sessionDrivenUpdates: 19,
        sessionDrivenProvenance: 'untracked in the table (operator-generated per the session records)',
        independentExternalSessions: 0,
        decisionsChangedByRealData: '0 of 6',
        personasWithoutRealSessions: ['debian_11', 'aws_ec2', 'raspberry_pi'],
        needs: 'Independent external sessions collected under authorisation (docs/QLEARNING_EVIDENCE.md)',
      },
    },
  ]
}

// Test evidence for the firewall adapters: every command runs through a test double (child_process is replaced).
const FIREWALL_ADAPTER_EVIDENCE = [
  'backend/tests/firewallContainmentVerification.test.js',
  'backend/tests/realFirewallAdapters.test.js',
  'backend/tests/firewallExecFile.test.js',
  'backend/tests/windowsFirewallSafety.test.js',
]

function firewallContainmentItems(enforcement) {
  const real = enforcement.hostFirewall === 'host_firewall'
  return [
    {
      id: 'firewall_adapters',
      title: 'Host-firewall adapters (Windows Firewall, Linux iptables)',
      label: 'implemented_and_verified',
      summary:
        'Adapter code and safety logic verified with MOCKED command execution only: command construction, allowlisted executables, input validation, the enable and host-bound confirmation gates, post-apply verification, cleanup of failed applications, release and audit. No real firewall rule has been created by these tests.',
      facts: {
        scope: 'mocked command execution (test doubles); no netsh, iptables, ip6tables or nft was run',
        adapters: ['WindowsFirewallAdapter (netsh advfirewall)', 'LinuxIptablesAdapter (iptables / ip6tables)'],
        lifecycle: 'REQUESTED -> VALIDATING -> APPROVED -> APPLYING -> ACTIVE -> ROLLING_BACK -> ROLLED_BACK',
        evidence: FIREWALL_ADAPTER_EVIDENCE,
        realRulesTested: false,
      },
    },
    {
      id: 'host_firewall',
      title: 'Real host-firewall enforcement',
      // A real adapter in use has still never been verified against a real firewall by this project.
      label: real ? 'experimental' : 'implemented_not_enabled',
      summary: real
        ? `Real ${enforcement.backend} enforcement is ACTIVE on this host. Rules are verified after they are applied, but real enforcement has not been verified by this project's tests; treat it as experimental.`
        : 'Not enabled: no real firewall rule is created. Containment is SIMULATED (mock adapter). Enabling it needs CONTAINMENT_BACKEND, the backend enable flag and the host-bound confirmation phrase, outside tests. Actual host-firewall rules have not been created or tested.',
      facts: {
        active: real,
        backend: enforcement.backend,
        requestedBackend: enforcement.requestedBackend,
        refusedReasons: enforcement.refusedReasons,
        verifiedAfterApply: enforcement.verifiedAfterApply,
        realRulesTested: false,
      },
    },
    {
      id: 'mock_containment',
      title: 'Default containment (mock adapter)',
      label: 'implemented_and_tested_simulated',
      summary: real
        ? 'The mock adapter is the default but is not in use right now (a real adapter is active).'
        : 'In use: the mock adapter is the default containment mechanism. It records each containment through the full lifecycle and audit trail, but changes no host firewall. Cowrie deny-list refusal is a separate capability.',
      facts: { inUse: !real, backend: real ? null : enforcement.backend, hostFirewallChanged: false },
    },
  ]
}

// Test evidence for the offline PCAP replay workflow (docs/CAPTURE.md, "How it is verified").
const PCAP_REPLAY_EVIDENCE = [
  'ai-engine/tests/test_capture.py',
  'ai-engine/tests/test_pcap_replay_e2e.py',
  'backend/tests/pcapReplayIngest.test.js',
  'frontend/tests/capabilities.test.mjs',
]

function lastReplay(capture) {
  const last = capture.last
  if (!last || last.mode !== 'pcap_replay') return null
  return {
    state: capture.mode === 'pcap_replay' ? capture.state : 'stale',
    reportedAt: last.receivedAt,
    counters: last.counters,
    note: last.lastError || null,
  }
}

function pcapReplayItem(capture) {
  const last = lastReplay(capture)
  const lastText = !last
    ? 'No replay has reported since the backend started.'
    : last.state === 'failed'
      ? `Last replay failed: ${last.note}`
      : `Last replay: ${last.state} (${last.counters?.packets ?? 0} packets, ${last.counters?.flows ?? 0} flows, ${last.counters?.posted ?? 0} posted).${last.note ? ` Note: ${last.note}` : ''}`
  return {
    id: 'pcap_replay',
    title: 'Network traffic source: offline PCAP replay',
    label: 'implemented_and_verified',
    summary: `A recorded classic .pcap file is replayed through the header-only flow extractor, the deployed model (xgb_cicids_v1) and backend storage; every prediction is stored and pushed as "pcap_replay". Recorded traffic, not live. ${lastText}`,
    facts: {
      workflow:
        'python -m capture.service --pcap <file> [--dry-run] -> POST /api/honeypot/ingest/flow -> AI engine -> AIPrediction + ai_prediction event',
      input:
        'classic libpcap (.pcap; pcapng refused); link types Ethernet, raw IP, Linux SLL, BSD loopback; TCP and UDP over IPv4/IPv6',
      extraction:
        'packet headers only (no payload bytes kept); 50 flow features + 3 derived by the engine = the 53-feature xgb_cicids_v1 contract',
      provenance:
        'AIPrediction.captureSource = "pcap_replay", also on the ai_prediction socket event and the Trust Meter',
      liveTraffic: false,
      lastReplay: last,
      evidence: PCAP_REPLAY_EVIDENCE,
    },
  }
}

function liveCaptureItem(capture) {
  const running = capture.mode === 'live_passive'
  return {
    id: 'live_capture',
    title: 'Network traffic source: live network capture',
    // A running live capture is reported as experimental: it has not been verified by this project.
    label: running ? 'experimental' : 'implemented_not_enabled',
    summary: running
      ? `A live passive capture is reporting from ${capture.last?.interface || 'one interface'}. Live capture has not been verified; treat it as experimental.`
      : `Not enabled: no live capture service is running${capture.mode === 'unavailable' ? ` (${String(capture.reason || '').replace(/\.$/, '')})` : ' (the last capture-service report was an offline PCAP replay)'}. It needs SENTINEL_LIVE_CAPTURE=1, --i-understand-live-capture, one named interface and a capture driver (Npcap or CAP_NET_RAW). Offline PCAP replay working does not mean live capture works.`,
    facts: {
      running,
      verified: false,
      interface: running ? capture.last?.interface || null : null,
      fresh: running ? capture.fresh : false,
      counters: running ? capture.last?.counters || null : null,
      guards: [
        'SENTINEL_LIVE_CAPTURE=1',
        '--i-understand-live-capture',
        'exactly one named interface',
        'Npcap / CAP_NET_RAW',
      ],
    },
  }
}

module.exports = {
  getCapabilities,
  LABELS,
  latestRank5Status,
  mlGeneralisationItems,
  latestRank6Status,
  personaPolicyV2Items,
  v2ActivationStatus,
  latestRank7Status,
  windowsPersonaItems,
}
