import test from 'node:test';
import assert from 'node:assert/strict';
import { validateTestDatabaseName } from '../e2e/dbGuard.js';

test('validateTestDatabaseName: accepts valid test databases', () => {
  assert.equal(validateTestDatabaseName('mongodb://localhost:27017/sentinelai_test'), 'sentinelai_test');
  assert.equal(validateTestDatabaseName('mongodb://127.0.0.1:27017/sentinel_test_ci?replicaSet=rs0'), 'sentinel_test_ci');
  assert.equal(validateTestDatabaseName('sentinelai_testing'), 'sentinelai_testing');
});

test('validateTestDatabaseName: strictly rejects non-test and production database names', () => {
  const rejectedDatabases = [
    'mongodb://localhost:27017/sentinelai',
    'mongodb://localhost:27017/sentinelai_prod',
    'mongodb://127.0.0.1:27017/production',
    'mongodb://localhost:27017/development',
    'mongodb://localhost:27017/',
    '',
    null,
    undefined,
  ];

  for (const uri of rejectedDatabases) {
    assert.throws(
      () => validateTestDatabaseName(uri),
      /CRITICAL SAFETY ERROR: Test database ".*" must contain "test"/,
      `Failed to reject non-test URI: ${uri}`
    );
  }
});
