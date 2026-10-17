'use strict';

/**
 * test_schemas_and_compatibility.js
 *
 * Verifies Mongoose schema validation, rejection of invalid states, and query parsing
 * for SentinelAI GATE-1 Phase 3E.
 */

const path = require('path');
const fs = require('fs');
const assert = require('assert');
const backendDir = path.join(__dirname, '..', '..', '..', 'backend');
const mongoose = require(path.join(backendDir, 'node_modules', 'mongoose'));
const ThreatLog = require(path.join(backendDir, 'models', 'ThreatLog'));
const Alert = require(path.join(backendDir, 'models', 'Alert'));
const AIPrediction = require(path.join(backendDir, 'models', 'AIPrediction'));
const threatService = require(path.join(backendDir, 'services', 'threatService'));

const results = [];

function check(title, fn) {
  try {
    fn();
    results.push({ title, status: 'VERIFIED' });
    console.log(`[PASS] ${title}`);
  } catch (err) {
    results.push({ title, status: 'FAILED', error: err.message });
    console.error(`[FAIL] ${title}: ${err.message}`);
  }
}

async function asyncCheck(title, fn) {
  try {
    await fn();
    results.push({ title, status: 'VERIFIED' });
    console.log(`[PASS] ${title}`);
  } catch (err) {
    results.push({ title, status: 'FAILED', error: err.message });
    console.error(`[FAIL] ${title}: ${err.message}`);
  }
}

async function main() {
  console.log('================================================================');
  console.log('SentinelAI GATE-1 Phase 3E: Schema & Query Compatibility Check');
  console.log('================================================================\n');

  // 1. ThreatLog accepts DEGRADED status and UNINSPECTED_TRAFFIC
  check('ThreatLog accepts DEGRADED status and UNINSPECTED_TRAFFIC attackType', () => {
    const doc = new ThreatLog({
      severity: 'MEDIUM',
      sourceIP: '10.0.0.1',
      attackType: 'UNINSPECTED_TRAFFIC',
      status: 'DEGRADED',
      preBlockStatus: 'DEGRADED',
      aiScore: 0.5,
      confidence: 0.5
    });
    const err = doc.validateSync();
    assert.strictEqual(err, undefined);
  });

  // 2. ThreatLog rejects invalid status
  check('ThreatLog rejects invalid status enum value', () => {
    const doc = new ThreatLog({
      severity: 'MEDIUM',
      sourceIP: '10.0.0.1',
      attackType: 'DDoS',
      status: 'INVALID_STATE_XYZ'
    });
    const err = doc.validateSync();
    assert.ok(err !== undefined, 'Validation error expected');
    assert.ok(err.errors.status, 'Error on status expected');
  });

  // 3. ThreatLog rejects invalid attackType
  check('ThreatLog rejects invalid attackType enum value', () => {
    const doc = new ThreatLog({
      severity: 'MEDIUM',
      sourceIP: '10.0.0.1',
      attackType: 'INVALID_ATTACK_TYPE_123',
      status: 'ACTIVE'
    });
    const err = doc.validateSync();
    assert.ok(err !== undefined, 'Validation error expected');
    assert.ok(err.errors.attackType, 'Error on attackType expected');
  });

  // 4. Alert accepts AIPrediction refModel
  check('Alert accepts AIPrediction refModel in sourceRef', () => {
    const doc = new Alert({
      title: 'AI Anomaly',
      message: 'Degraded AI state',
      severity: 'MEDIUM',
      type: 'SYSTEM_HEALTH',
      sourceRef: {
        refModel: 'AIPrediction',
        refId: new mongoose.Types.ObjectId()
      }
    });
    const err = doc.validateSync();
    assert.strictEqual(err, undefined);
  });

  // 5. Alert rejects invalid refModel
  check('Alert rejects invalid refModel in sourceRef', () => {
    const doc = new Alert({
      title: 'Invalid Alert',
      message: 'Invalid refModel',
      severity: 'LOW',
      type: 'INFO',
      sourceRef: {
        refModel: 'NonExistentModel',
        refId: new mongoose.Types.ObjectId()
      }
    });
    const err = doc.validateSync();
    assert.ok(err !== undefined, 'Validation error expected');
    assert.ok(err.errors['sourceRef.refModel'], 'Error on sourceRef.refModel expected');
  });

  // 6. threatService query accepts status=DEGRADED
  await asyncCheck('threatService.findThreats parses status=DEGRADED without error', async () => {
    const origFind = ThreatLog.find;
    const origCount = ThreatLog.countDocuments;
    let queryPassed = null;

    try {
      ThreatLog.countDocuments = async () => 3;
      ThreatLog.find = (q) => {
        queryPassed = q;
        return {
          sort: () => ({
            skip: () => ({
              limit: () => ({
                populate: () => ({
                  lean: async () => [{ _id: 't1', status: 'DEGRADED' }]
                })
              })
            })
          })
        };
      };

      const result = await threatService.findThreats({ status: 'DEGRADED', page: 1, limit: 10 });
      assert.strictEqual(result.total, 3);
      assert.strictEqual(queryPassed.status, 'DEGRADED');
    } finally {
      ThreatLog.find = origFind;
      ThreatLog.countDocuments = origCount;
    }
  });

  console.log('\n================================================================');
  const allPassed = results.every(r => r.status === 'VERIFIED');
  console.log(`Schema Compatibility Result: ${allPassed ? 'ALL VERIFIED (6/6)' : 'FAILURES'}`);
  console.log('================================================================');

  const outputPath = path.join(__dirname, 'schema_and_compatibility_output.json');
  fs.writeFileSync(outputPath, JSON.stringify(results, null, 2), 'utf8');
}

main().catch(console.error);
