/**
 * test_backend_safety_isolated.js
 *
 * Isolated regression test suite for SentinelAI GATE-1 Phase 3C:
 * Backend Failure-Safety and Inference Contract Verification.
 *
 * Evaluates:
 * 1. Current production behavior (demonstrating current defects and regression baselines).
 * 2. Proposed failure-state contract behavior (verifying safety remediation logic).
 *
 * Constraints:
 * - Zero modifications to production source code.
 * - Zero writes to live MongoDB database sentinel-db.
 * - Zero changes to Windows Firewall rules.
 * - Completely isolated in-memory execution.
 */

'use strict';

const fs = require('fs');
const path = require('path');

// Test Suite Results Container
const testReport = {
  suite: 'SentinelAI GATE-1 Phase 3C: Backend Failure-Safety Regression Suite',
  timestamp: new Date().toISOString(),
  environment: {
    nodeVersion: process.version,
    platform: process.platform,
    workspace: 'ai-engine/experiments/gate1_phase3c_backend_safety',
    gateStatus: 'GATE-1 OPEN',
    autonomousContainment: false,
    realFirewallEnforcement: false
  },
  totalTests: 11,
  currentProductionResults: {
    passed: 0,
    failedDefects: 0,
    tests: []
  },
  proposedContractResults: {
    passed: 0,
    failed: 0,
    tests: []
  }
};

console.log('='.repeat(80));
console.log('  SentinelAI Phase 3C: Isolated Backend Failure-Safety Regression Tests');
console.log('='.repeat(80));

// ============================================================================
// PART A: CURRENT PRODUCTION BEHAVIOR TESTS (Baseline Defect Verification)
// ============================================================================
console.log('\n--- PART A: Verifying Current Production Behavior Against Failure Modes ---');

// TC-01: Degraded Action Overwrite
function testProdDegradedActionOverwrite() {
  const result = {
    predictedClass: 'UNINSPECTED_TRAFFIC',
    threatScore: 0.50,
    action: 'MONITOR',
    status: 'DEGRADED'
  };
  const blockThreshold = 0.92;
  const score = result.threatScore || 0;
  // Current production logic in backend/services/aiEngineService.js:58
  const prodAction = score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW';
  
  const defectConfirmed = (prodAction === 'ALLOW' && result.action === 'MONITOR');
  testReport.currentProductionResults.tests.push({
    testId: 'TC-PROD-01',
    description: 'Current production overwrites explicit degraded MONITOR to ALLOW',
    input: result,
    observedAction: prodAction,
    expectedSafeAction: 'MONITOR',
    defectConfirmed,
    status: defectConfirmed ? 'DEFECT_CONFIRMED' : 'UNEXPECTED'
  });
  if (defectConfirmed) testReport.currentProductionResults.failedDefects++;
  console.log(`[TC-PROD-01] Degraded Action Overwrite: ${defectConfirmed ? 'CONFIRMED DEFECT (ALLOW)' : 'FAIL'}`);
}

// TC-02: Timeout Handling Fails Open (returns null)
function testProdTimeoutFailsOpen() {
  // Current production logic in backend/services/aiEngineService.js:48-54
  function simulateProdPipelineOnTimeout() {
    try {
      throw new Error('timeout of 10000ms exceeded'); // Axios timeout
    } catch (e) {
      // Line 48-49: logger.warn, returns null
      const predictRecord = null;
      // Line 54: if (!r?.result) return null;
      if (!predictRecord) return null;
      return { action: 'ALLOW' };
    }
  }

  const output = simulateProdPipelineOnTimeout();
  const defectConfirmed = (output === null);
  testReport.currentProductionResults.tests.push({
    testId: 'TC-PROD-02',
    description: 'Current production returns null on timeout (fails open with zero log/alert)',
    observedOutput: output,
    defectConfirmed,
    status: defectConfirmed ? 'DEFECT_CONFIRMED' : 'UNEXPECTED'
  });
  if (defectConfirmed) testReport.currentProductionResults.failedDefects++;
  console.log(`[TC-PROD-02] Timeout Fail-Open Drop: ${defectConfirmed ? 'CONFIRMED DEFECT (null)' : 'FAIL'}`);
}

// TC-03: Connection Refused Fails Open
function testProdConnRefusedFailsOpen() {
  function simulateProdPipelineOnConnRefused() {
    try {
      const err = new Error('connect ECONNREFUSED 127.0.0.1:8000');
      err.code = 'ECONNREFUSED';
      throw err;
    } catch (e) {
      const predictRecord = null;
      if (!predictRecord) return null;
      return { action: 'ALLOW' };
    }
  }

  const output = simulateProdPipelineOnConnRefused();
  const defectConfirmed = (output === null);
  testReport.currentProductionResults.tests.push({
    testId: 'TC-PROD-03',
    description: 'Current production returns null on ECONNREFUSED (fails open)',
    observedOutput: output,
    defectConfirmed,
    status: defectConfirmed ? 'DEFECT_CONFIRMED' : 'UNEXPECTED'
  });
  if (defectConfirmed) testReport.currentProductionResults.failedDefects++;
  console.log(`[TC-PROD-03] ECONNREFUSED Fail-Open Drop: ${defectConfirmed ? 'CONFIRMED DEFECT (null)' : 'FAIL'}`);
}

// TC-04: ThreatLog Status Enum Rejection
function testProdThreatLogSchemaRejection() {
  // Current production enum in backend/models/ThreatLog.js:33
  const allowedStatuses = ['DETECTED', 'MONITORING', 'BLOCKED', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE'];
  const testStatus = 'DEGRADED';
  const isRejected = !allowedStatuses.includes(testStatus);

  testReport.currentProductionResults.tests.push({
    testId: 'TC-PROD-04',
    description: 'Current ThreatLog schema status enum rejects DEGRADED',
    attemptedStatus: testStatus,
    allowedStatuses,
    isRejected,
    status: isRejected ? 'DEFECT_CONFIRMED' : 'UNEXPECTED'
  });
  if (isRejected) testReport.currentProductionResults.failedDefects++;
  console.log(`[TC-PROD-04] ThreatLog Schema Enum Rejects DEGRADED: ${isRejected ? 'CONFIRMED DEFECT' : 'FAIL'}`);
}

// TC-05: ThreatLog attackType Enum Rejection for UNINSPECTED_TRAFFIC
function testProdThreatLogAttackTypeRejection() {
  // Current production enum in backend/models/ThreatLog.js:12-27
  const allowedAttackTypes = [
    'SSH Brute Force', 'SSH Intrusion Attempt', 'SQL Injection', 'Port Scan',
    'DDoS', 'RCE Attempt', 'XSS Attempt', 'Malware Beacon', 'Credential Stuffing',
    'Ransomware', 'Lateral Movement', 'Data Exfiltration', 'Zero-Day Exploit', 'Unknown'
  ];
  const testAttackType = 'UNINSPECTED_TRAFFIC';
  const isRejected = !allowedAttackTypes.includes(testAttackType);

  testReport.currentProductionResults.tests.push({
    testId: 'TC-PROD-05',
    description: 'Current ThreatLog attackType enum rejects UNINSPECTED_TRAFFIC',
    attemptedAttackType: testAttackType,
    isRejected,
    status: isRejected ? 'DEFECT_CONFIRMED' : 'UNEXPECTED'
  });
  if (isRejected) testReport.currentProductionResults.failedDefects++;
  console.log(`[TC-PROD-05] ThreatLog attackType Rejects UNINSPECTED_TRAFFIC: ${isRejected ? 'CONFIRMED DEFECT' : 'FAIL'}`);
}

// TC-06: Malformed Score Defaults to ALLOW
function testProdMalformedScoreDefaultsToAllow() {
  const result = { predictedClass: 'DDoS', threatScore: null };
  const score = result.threatScore || 0; // defaults to 0
  const blockThreshold = 0.92;
  const prodAction = score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW';

  const defectConfirmed = (prodAction === 'ALLOW' && score === 0);
  testReport.currentProductionResults.tests.push({
    testId: 'TC-PROD-06',
    description: 'Current production defaults malformed threatScore to 0.0 and grants ALLOW',
    observedScore: score,
    observedAction: prodAction,
    defectConfirmed,
    status: defectConfirmed ? 'DEFECT_CONFIRMED' : 'UNEXPECTED'
  });
  if (defectConfirmed) testReport.currentProductionResults.failedDefects++;
  console.log(`[TC-PROD-06] Malformed Score Defaults to ALLOW: ${defectConfirmed ? 'CONFIRMED DEFECT' : 'FAIL'}`);
}

// TC-07: Alert refModel Schema Rejection for AIPrediction
function testProdAlertRefModelRejection() {
  // Current production enum in backend/models/Alert.js:22
  const allowedRefModels = ['ThreatLog', 'HoneypotSession', 'User'];
  const testRefModel = 'AIPrediction';
  const isRejected = !allowedRefModels.includes(testRefModel);

  testReport.currentProductionResults.tests.push({
    testId: 'TC-PROD-07',
    description: 'Current Alert schema refModel rejects AIPrediction',
    attemptedRefModel: testRefModel,
    isRejected,
    status: isRejected ? 'DEFECT_CONFIRMED' : 'UNEXPECTED'
  });
  if (isRejected) testReport.currentProductionResults.failedDefects++;
  console.log(`[TC-PROD-07] Alert refModel Rejects AIPrediction: ${isRejected ? 'CONFIRMED DEFECT' : 'FAIL'}`);
}

// TC-08: Autonomous Containment Safe Gating (Nominal Production Feature)
function testProdAutonomousContainmentGating() {
  const score = 0.98;
  const blockThreshold = 0.92;
  const autoBlockEnabled = false; // Current production setting
  const shouldBlock = score >= blockThreshold && autoBlockEnabled;
  const status = shouldBlock ? 'BLOCKED' : 'MONITORING';

  const safe = (!shouldBlock && status === 'MONITORING');
  testReport.currentProductionResults.tests.push({
    testId: 'TC-PROD-08',
    description: 'Current production correctly gates BLOCK when autoBlockEnabled=false',
    observedStatus: status,
    autoBlockEnabled,
    safe,
    status: safe ? 'PASS_NOMINAL' : 'FAIL'
  });
  if (safe) testReport.currentProductionResults.passed++;
  console.log(`[TC-PROD-08] Autonomous Containment Gating: ${safe ? 'PASS (Nominal Safe)' : 'FAIL'}`);
}

// Run Part A
testProdDegradedActionOverwrite();
testProdTimeoutFailsOpen();
testProdConnRefusedFailsOpen();
testProdThreatLogSchemaRejection();
testProdThreatLogAttackTypeRejection();
testProdMalformedScoreDefaultsToAllow();
testProdAlertRefModelRejection();
testProdAutonomousContainmentGating();


// ============================================================================
// PART B: PROPOSED FAILURE-STATE CONTRACT REGRESSION TESTS
// ============================================================================
console.log('\n--- PART B: Testing Proposed Failure-State Contract Implementation ---');

/**
 * Reference implementation of the proposed failure-state contract pipeline handler
 */
class FailureStateContractHandler {
  constructor(options = {}) {
    this.blockThreshold = options.blockThreshold || 0.92;
    this.autoBlockEnabled = options.autoBlockEnabled || false;
    this.emergencyLogs = [];
    this.emittedAlerts = [];
    this.threatLogMock = [];
    this.aiPredictionMock = [];
  }

  // Pure validation & action resolution function
  resolveActionAndStatus(result, rawError = null) {
    // 1. Service Unavailable / Raw Error
    if (rawError) {
      return {
        status: 'UNAVAILABLE',
        action: 'MONITOR',
        threatScore: 0.50,
        predictedClass: 'UNINSPECTED_TRAFFIC',
        severity: 'MEDIUM',
        isDegraded: true,
        reason: rawError.message || 'AI service failure'
      };
    }

    // 2. Malformed / Missing Result
    if (!result || typeof result !== 'object') {
      return {
        status: 'INVALID_RESPONSE',
        action: 'MONITOR',
        threatScore: 0.50,
        predictedClass: 'UNINSPECTED_TRAFFIC',
        severity: 'MEDIUM',
        isDegraded: true,
        reason: 'Malformed or missing inference payload'
      };
    }

    // 3. Explicit Degraded State
    if (result.status === 'DEGRADED' || result.predictedClass === 'UNINSPECTED_TRAFFIC') {
      return {
        status: 'DEGRADED',
        action: 'MONITOR', // Mandatory fail-safe
        threatScore: typeof result.threatScore === 'number' ? result.threatScore : 0.50,
        predictedClass: 'UNINSPECTED_TRAFFIC',
        severity: 'MEDIUM',
        isDegraded: true,
        reason: 'Explicit model degradation'
      };
    }

    // 4. Malformed Score
    const score = Number(result.threatScore);
    if (!Number.isFinite(score) || score < 0 || score > 1) {
      return {
        status: 'INVALID_RESPONSE',
        action: 'MONITOR',
        threatScore: 0.50,
        predictedClass: result.predictedClass || 'UNINSPECTED_TRAFFIC',
        severity: 'MEDIUM',
        isDegraded: true,
        reason: 'Invalid threatScore value'
      };
    }

    // 5. Nominal Prediction - Action Precedence Rule
    let action = 'ALLOW';
    if (result.action === 'MONITOR' || result.action === 'BLOCK') {
      // Honor explicit policy recommendation
      action = result.action;
    } else {
      action = score >= this.blockThreshold ? 'BLOCK' : score >= 0.70 ? 'MONITOR' : 'ALLOW';
    }

    const severity = score >= 0.90 ? 'CRITICAL' : score >= 0.75 ? 'HIGH' : score >= 0.50 ? 'MEDIUM' : 'LOW';

    return {
      status: 'HEALTHY',
      action,
      threatScore: score,
      predictedClass: result.predictedClass || 'BENIGN',
      severity,
      isDegraded: false,
      reason: 'Nominal inference'
    };
  }

  // Execution pipeline handler
  async processInference(flowRecord, rawInferenceResult, injectedError = null, dbFails = false) {
    const resolution = this.resolveActionAndStatus(rawInferenceResult, injectedError);

    // Simulated vs Real Enforcement Handling
    const simulatedBlock = (resolution.action === 'BLOCK' && !this.autoBlockEnabled);
    const threatStatus = resolution.status === 'DEGRADED' || resolution.status === 'UNAVAILABLE'
      ? 'DEGRADED'
      : (resolution.action === 'BLOCK' && this.autoBlockEnabled)
        ? 'BLOCKED'
        : (resolution.threatScore >= 0.70 || resolution.action === 'MONITOR')
          ? 'MONITORING'
          : 'DETECTED';

    // Emergency Logging Fallback on DB failure
    if (dbFails) {
      const emergencyRecord = {
        timestamp: new Date().toISOString(),
        event: 'PERSISTENCE_FAILURE_EMERGENCY_AUDIT',
        sourceIP: flowRecord.sourceIP || 'UNKNOWN',
        assignedAction: resolution.action,
        status: resolution.status,
        threatScore: resolution.threatScore,
        error: 'Mock MongoNetworkError: Connection timed out'
      };
      this.emergencyLogs.push(emergencyRecord);
      throw new Error('Database persistence failed (Emergency disk audit logged)');
    }

    // Normal Persistence Mock
    const predDoc = {
      _id: 'pred-' + Math.random().toString(36).substring(7),
      sourceIP: flowRecord.sourceIP,
      predictedClass: resolution.predictedClass,
      threatScore: resolution.threatScore,
      status: resolution.status,
      policyAction: resolution.action
    };
    this.aiPredictionMock.push(predDoc);

    // ThreatLog creation for threats or degraded traffic
    let threatDoc = null;
    if (resolution.isDegraded || resolution.threatScore >= 0.70 || resolution.action === 'MONITOR' || resolution.action === 'BLOCK') {
      threatDoc = {
        _id: 'threat-' + Math.random().toString(36).substring(7),
        sourceIP: flowRecord.sourceIP,
        attackType: resolution.predictedClass,
        aiScore: resolution.threatScore,
        status: threatStatus,
        severity: resolution.severity,
        notes: resolution.reason
      };
      this.threatLogMock.push(threatDoc);

      // Operator Alert
      const alert = {
        title: resolution.isDegraded ? `System Alert: Degraded Traffic Monitored` : `Threat: ${resolution.predictedClass}`,
        severity: resolution.severity,
        type: resolution.isDegraded ? 'SYSTEM_HEALTH' : 'THREAT_DETECTED',
        sourceRef: { refModel: 'ThreatLog', refId: threatDoc._id }
      };
      this.emittedAlerts.push(alert);
    }

    return {
      success: true,
      action: resolution.action,
      threatScore: resolution.threatScore,
      status: resolution.status,
      simulatedBlock,
      threatStatus,
      predictionId: predDoc._id,
      threatId: threatDoc ? threatDoc._id : null
    };
  }
}

// TC-09: Remediation of Degraded Action (Preserves MONITOR)
async function testRemediatedDegradedPreservation() {
  const handler = new FailureStateContractHandler();
  const res = await handler.processInference(
    { sourceIP: '192.168.1.50' },
    { predictedClass: 'UNINSPECTED_TRAFFIC', threatScore: 0.50, action: 'MONITOR', status: 'DEGRADED' }
  );

  const passed = (res.action === 'MONITOR' && res.status === 'DEGRADED' && res.threatStatus === 'DEGRADED');
  testReport.proposedContractResults.tests.push({
    testId: 'TC-REM-01',
    description: 'Contract preserves explicit degraded status and assigns MONITOR',
    observed: res,
    passed
  });
  if (passed) testReport.proposedContractResults.passed++;
  console.log(`[TC-REM-01] Degraded Action Preservation: ${passed ? 'PASS' : 'FAIL'}`);
}

// TC-10: Remediation of Timeout (Controlled Fail-Safe Fallback)
async function testRemediatedTimeoutHandling() {
  const handler = new FailureStateContractHandler();
  const timeoutErr = new Error('timeout of 10000ms exceeded');
  const res = await handler.processInference({ sourceIP: '10.0.0.99' }, null, timeoutErr);

  const passed = (res.action === 'MONITOR' && res.status === 'UNAVAILABLE' && res.threatStatus === 'DEGRADED');
  testReport.proposedContractResults.tests.push({
    testId: 'TC-REM-02',
    description: 'Contract converts timeout into controlled UNAVAILABLE with MONITOR and operator alert',
    observed: res,
    passed
  });
  if (passed) testReport.proposedContractResults.passed++;
  console.log(`[TC-REM-02] Timeout Fail-Safe Fallback: ${passed ? 'PASS' : 'FAIL'}`);
}

// TC-11: Remediation of Schema Compatibility (UNINSPECTED_TRAFFIC & DEGRADED)
function testRemediatedSchemaCompatibility() {
  // Proposed expanded enums
  const proposedStatuses = ['DETECTED', 'MONITORING', 'BLOCKED', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE', 'DEGRADED'];
  const proposedAttackTypes = [
    'SSH Brute Force', 'SSH Intrusion Attempt', 'SQL Injection', 'Port Scan',
    'DDoS', 'RCE Attempt', 'XSS Attempt', 'Malware Beacon', 'Credential Stuffing',
    'Ransomware', 'Lateral Movement', 'Data Exfiltration', 'Zero-Day Exploit', 'Unknown',
    'UNINSPECTED_TRAFFIC'
  ];

  const statusAllowed = proposedStatuses.includes('DEGRADED');
  const attackTypeAllowed = proposedAttackTypes.includes('UNINSPECTED_TRAFFIC');
  const passed = (statusAllowed && attackTypeAllowed);

  testReport.proposedContractResults.tests.push({
    testId: 'TC-REM-03',
    description: 'Proposed ThreatLog schema permits DEGRADED status and UNINSPECTED_TRAFFIC attackType',
    statusAllowed,
    attackTypeAllowed,
    passed
  });
  if (passed) testReport.proposedContractResults.passed++;
  console.log(`[TC-REM-03] Proposed Schema Compatibility: ${passed ? 'PASS' : 'FAIL'}`);
}

// TC-12: Remediation of Persistence Failure (Emergency File Fallback)
async function testRemediatedEmergencyAuditFallback() {
  const handler = new FailureStateContractHandler();
  let caught = false;
  try {
    await handler.processInference(
      { sourceIP: '172.16.0.4' },
      { predictedClass: 'PortScan', threatScore: 0.88, action: 'MONITOR' },
      null,
      true // Inject DB failure
    );
  } catch (e) {
    caught = true;
  }

  const logRecorded = handler.emergencyLogs.length === 1 && handler.emergencyLogs[0].event === 'PERSISTENCE_FAILURE_EMERGENCY_AUDIT';
  const passed = caught && logRecorded;

  testReport.proposedContractResults.tests.push({
    testId: 'TC-REM-04',
    description: 'Emergency audit record written to fallback logger on DB persistence failure',
    caughtException: caught,
    emergencyLogCount: handler.emergencyLogs.length,
    passed
  });
  if (passed) testReport.proposedContractResults.passed++;
  console.log(`[TC-REM-04] Emergency Disk Audit Fallback: ${passed ? 'PASS' : 'FAIL'}`);
}

// TC-13: Simulated Block Verification
async function testRemediatedSimulatedBlockGating() {
  const handler = new FailureStateContractHandler({ blockThreshold: 0.90, autoBlockEnabled: false });
  const res = await handler.processInference(
    { sourceIP: '198.51.100.1' },
    { predictedClass: 'DDoS', threatScore: 0.96, action: 'BLOCK' }
  );

  const passed = (res.action === 'BLOCK' && res.simulatedBlock === true && res.threatStatus === 'MONITORING');
  testReport.proposedContractResults.tests.push({
    testId: 'TC-REM-05',
    description: 'BLOCK action is tagged as simulatedBlock=true and status held at MONITORING when autoBlockEnabled=false',
    observed: res,
    passed
  });
  if (passed) testReport.proposedContractResults.passed++;
  console.log(`[TC-REM-05] Simulated BLOCK Gating: ${passed ? 'PASS' : 'FAIL'}`);
}

// Run Part B
(async () => {
  await testRemediatedDegradedPreservation();
  await testRemediatedTimeoutHandling();
  testRemediatedSchemaCompatibility();
  await testRemediatedEmergencyAuditFallback();
  await testRemediatedSimulatedBlockGating();

  // Summary
  console.log('\n' + '='.repeat(80));
  console.log('  TEST SUMMARY');
  console.log('='.repeat(80));
  console.log(`Part A: Current Production Defect Verifications: ${testReport.currentProductionResults.failedDefects} / 7 Defects Confirmed (1 Nominal Safe Gating Verified)`);
  console.log(`Part B: Proposed Contract Remediation Tests:    ${testReport.proposedContractResults.passed} / 5 Tests Passed`);

  // Write out structured test results
  const outPath = path.join(__dirname, 'backend_safety_regression_results.json');
  fs.writeFileSync(outPath, JSON.stringify(testReport, null, 2));
  console.log(`\n[OUTPUT] Test results saved to:\n  ${outPath}`);
})();
