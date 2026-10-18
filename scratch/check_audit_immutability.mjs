import mongoose from '../backend/node_modules/mongoose/index.js';

async function auditIntegrityAndHooks() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const db = mongoose.connection.db;

  console.log('=== CHECK 9: AUDIT LOG INTEGRITY & IMMUTABILITY HOOKS ===');

  // A. Audit log entries check in live DB (Read-Only)
  const auditLogs = await db.collection('auditlogs').find({}).sort({ createdAt: 1 }).toArray();
  console.log('Total AuditLog entries:', auditLogs.length);

  let missingActorCount = 0;
  let outOfOrderCount = 0;
  let lastTimestamp = 0;

  for (let i = 0; i < auditLogs.length; i++) {
    const entry = auditLogs[i];
    const curTime = new Date(entry.createdAt).getTime();
    if (curTime < lastTimestamp) {
      outOfOrderCount++;
    }
    lastTimestamp = curTime;

    // Check actions that imply authentication but have no actor
    const authenticatedActions = [
      'TRIAGE_NOTE_UPDATE',
      'CONTAINMENT_BLOCK',
      'USER_ROLE_CHANGE',
      'USER_STATUS_CHANGE',
      'SETTINGS_UPDATE',
      'ALERT_DISMISSED',
      'AUTO_BLOCK_TOGGLE',
      'MANUAL_REDRIVE'
    ];
    if (authenticatedActions.includes(entry.action)) {
      if (!entry.actor || (!entry.actor.id && !entry.actor.email)) {
        missingActorCount++;
        console.log('  Missing actor on authenticated action:', entry._id, entry.action);
      }
    }
  }
  console.log('Audit entries with missing actor on authenticated actions:', missingActorCount);
  console.log('Audit entries out of sequential createdAt order:', outOfOrderCount);

  // Inspect the 12 target orphans found earlier
  console.log('\n--- Inspecting Audit Log Target Orphans ---');
  let targetOrphansFound = 0;
  for (const a of auditLogs) {
    if (a.target && a.target.id) {
      let targetColl = null;
      if (a.target.type === 'User') targetColl = 'users';
      else if (a.target.type === 'Threat' || a.target.type === 'ThreatLog') targetColl = 'threatlogs';
      else if (a.target.type === 'ContainmentAction') targetColl = 'containmentactions';
      if (targetColl) {
        try {
          const found = await db.collection(targetColl).findOne({ _id: new mongoose.Types.ObjectId(a.target.id) });
          if (!found) {
            targetOrphansFound++;
            console.log(`  Orphan Target: Action=${a.action}, TargetType=${a.target.type}, TargetId=${a.target.id}, TargetIdent=${a.target.identifier}`);
          }
        } catch {
          targetOrphansFound++;
          console.log(`  Invalid ObjectId Target: Action=${a.action}, TargetType=${a.target.type}, TargetId=${a.target.id}`);
        }
      }
    }
  }
  console.log('Total Target Orphans in AuditLogs:', targetOrphansFound);

  await mongoose.disconnect();

  // B. Testing immutability hooks against an IN-MEMORY test schema (NOT live DB)
  console.log('\n--- Testing Immutability Hooks Against Mock / In-Memory Schema ---');
  const AuditLog = (await import('../backend/models/AuditLog.js')).default || (await import('../backend/models/AuditLog.js'));

  // Create isolated in-memory mongo connection for testing hooks safely
  const testConn = await mongoose.createConnection('mongodb://127.0.0.1:27017/sentinelai_mock_audit_test_transient');
  const TestAuditLog = testConn.model('TestAuditLog', AuditLog.schema);

  // 1. Create a test entry
  const entry = await TestAuditLog.create({
    action: 'TEST_IMMUTABILITY_PROBE',
    eventType: 'SECURITY_AUDIT',
    status: 'SUCCESS'
  });
  console.log('Test audit record created in transient test DB with ID:', entry._id);

  // Probe 1: doc.save() when modified
  let docSaveBlocked = false;
  try {
    entry.action = 'MODIFIED_ACTION';
    await entry.save();
  } catch (err) {
    docSaveBlocked = true;
    console.log('  [PASS] doc.save() modification blocked:', err.message);
  }
  if (!docSaveBlocked) console.log('  [FAIL] doc.save() modification was NOT blocked!');

  // Probe 2: Model.updateOne()
  let updateOneBlocked = false;
  try {
    await TestAuditLog.updateOne({ _id: entry._id }, { action: 'MODIFIED' });
  } catch (err) {
    updateOneBlocked = true;
    console.log('  [PASS] Model.updateOne blocked:', err.message);
  }
  if (!updateOneBlocked) console.log('  [FAIL] Model.updateOne was NOT blocked!');

  // Probe 3: Model.updateMany()
  let updateManyBlocked = false;
  try {
    await TestAuditLog.updateMany({}, { action: 'MODIFIED' });
  } catch (err) {
    updateManyBlocked = true;
    console.log('  [PASS] Model.updateMany blocked:', err.message);
  }
  if (!updateManyBlocked) console.log('  [FAIL] Model.updateMany was NOT blocked!');

  // Probe 4: Model.findOneAndUpdate()
  let findOneAndUpdateBlocked = false;
  try {
    await TestAuditLog.findOneAndUpdate({ _id: entry._id }, { action: 'MODIFIED' });
  } catch (err) {
    findOneAndUpdateBlocked = true;
    console.log('  [PASS] Model.findOneAndUpdate blocked:', err.message);
  }
  if (!findOneAndUpdateBlocked) console.log('  [FAIL] Model.findOneAndUpdate was NOT blocked!');

  // Probe 5: Model.deleteOne()
  let deleteOneQueryBlocked = false;
  try {
    await TestAuditLog.deleteOne({ _id: entry._id });
  } catch (err) {
    deleteOneQueryBlocked = true;
    console.log('  [PASS] Model.deleteOne (query) blocked:', err.message);
  }
  if (!deleteOneQueryBlocked) console.log('  [FAIL] Model.deleteOne (query) was NOT blocked!');

  // Probe 6: Model.deleteMany()
  let deleteManyBlocked = false;
  try {
    await TestAuditLog.deleteMany({});
  } catch (err) {
    deleteManyBlocked = true;
    console.log('  [PASS] Model.deleteMany blocked:', err.message);
  }
  if (!deleteManyBlocked) console.log('  [FAIL] Model.deleteMany was NOT blocked!');

  // Probe 7: Model.findOneAndDelete()
  let findOneAndDeleteBlocked = false;
  try {
    await TestAuditLog.findOneAndDelete({ _id: entry._id });
  } catch (err) {
    findOneAndDeleteBlocked = true;
    console.log('  [PASS] Model.findOneAndDelete blocked:', err.message);
  }
  if (!findOneAndDeleteBlocked) console.log('  [FAIL] Model.findOneAndDelete was NOT blocked!');

  // Probe 8: Model.findOneAndRemove()
  console.log('  Checking Model.findOneAndRemove existence in Mongoose ' + mongoose.version + ':');
  if (typeof TestAuditLog.findOneAndRemove === 'function') {
    try {
      await TestAuditLog.findOneAndRemove({ _id: entry._id });
      console.log('  [FAIL] Model.findOneAndRemove was NOT blocked!');
    } catch (err) {
      console.log('  [PASS] Model.findOneAndRemove blocked:', err.message);
    }
  } else {
    console.log('  [OBSERVATION] Model.findOneAndRemove is undefined (removed in Mongoose 8.x). The hook pre("findOneAndRemove") never fires because the method no longer exists in Mongoose 8!');
  }

  // Probe 9: Model.bulkWrite()
  console.log('  Checking Model.bulkWrite hook behavior in Mongoose ' + mongoose.version + ':');
  let bulkWriteBlocked = false;
  try {
    await TestAuditLog.bulkWrite([
      { deleteOne: { filter: { _id: entry._id } } }
    ]);
  } catch (err) {
    bulkWriteBlocked = true;
    console.log('  Result of bulkWrite:', err.message);
  }
  if (bulkWriteBlocked) {
    console.log('  [PASS] bulkWrite blocked by hook.');
  } else {
    console.log('  [CRITICAL FINDING] bulkWrite was NOT blocked! In Mongoose 8, pre("bulkWrite") does NOT intercept Model.bulkWrite() unless supported, or it bypassed the hook completely!');
  }

  // Probe 10: Document-level deleteOne: doc.deleteOne()
  console.log('  Checking Document-level doc.deleteOne():');
  const freshDoc = await TestAuditLog.findOne({ _id: entry._id });
  if (freshDoc) {
    let docDeleteBlocked = false;
    try {
      await freshDoc.deleteOne();
    } catch (err) {
      docDeleteBlocked = true;
      console.log('  Result of doc.deleteOne():', err.message);
    }
    if (docDeleteBlocked) {
      console.log('  [PASS] doc.deleteOne() blocked.');
    } else {
      console.log('  [CRITICAL FINDING] doc.deleteOne() was NOT blocked! In Mongoose, AuditLog.js defined pre("deleteOne") without { document: true, query: true }, so pre("deleteOne") only attached to Query middleware! A caller doing `const doc = await AuditLog.findById(id); await doc.deleteOne();` DELETES THE AUDIT LOG!');
    }
  }

  // Cleanup transient test database
  await testConn.dropDatabase();
  await testConn.close();
}

auditIntegrityAndHooks().catch(console.error);
