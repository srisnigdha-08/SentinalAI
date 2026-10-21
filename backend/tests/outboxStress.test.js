'use strict'

const fs = require('fs')
const path = require('path')
const { SecurityEventBus, FileOutboxStore, InMemoryOutboxStore } = require('../utils/securityEventBus')

describe('Phase 7 — Outbox Architecture Stress & Reliability Suite', () => {
  const tmpDir = path.join(__dirname, '..', 'logs', `stress_test_${Date.now()}`)

  beforeAll(() => {
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true })
  })

  afterAll(() => {
    try {
      if (fs.existsSync(tmpDir)) fs.rmSync(tmpDir, { recursive: true, force: true })
    } catch (_) {}
  })

  test('1. Crash/Restart Recovery: pending event survives simulated crash and is delivered on restart', async () => {
    const outboxFile = path.join(tmpDir, 'recovery_outbox.json')
    const store1 = new FileOutboxStore(outboxFile)

    // Bus 1: Crashes right after persisting and before delivery
    const bus1 = new SecurityEventBus({ outboxStore: store1 })
    bus1.subscribe('ALERT_CREATED', () => {
      throw new Error('Subscriber fatal crash')
    })

    await bus1.publishDurable(
      { eventType: 'ALERT_CREATED', payload: { alertId: 'ALT-101', severity: 'CRITICAL' } },
      async () => {} // state persisted
    )

    // Verification: Event is pending on disk
    const pendingOnDisk = await store1.getPendingEvents()
    expect(pendingOnDisk.length).toBe(1)
    expect(pendingOnDisk[0].payload.alertId).toBe('ALT-101')

    // Bus 2: New process instance starts, connects to same file
    const store2 = new FileOutboxStore(outboxFile)
    const bus2 = new SecurityEventBus({ outboxStore: store2 })
    const delivered = []
    bus2.subscribe('ALERT_CREATED', (env) => {
      delivered.push(env)
    })

    const replayRes = await bus2.replayPendingOutbox()
    expect(replayRes.replayed).toBe(1)
    expect(delivered.length).toBe(1)
    expect(delivered[0].payload.alertId).toBe('ALT-101')

    // Verification: Now empty in store2
    const pendingAfter = await store2.getPendingEvents()
    expect(pendingAfter.length).toBe(0)
  })

  test('2. Acknowledgment Persistence: confirmed events survive restart and are not re-emitted', async () => {
    const outboxFile = path.join(tmpDir, 'ack_persistence.json')
    const store1 = new FileOutboxStore(outboxFile)
    const bus1 = new SecurityEventBus({ outboxStore: store1 })

    let callCount = 0
    bus1.subscribe('IP_BLOCKED', () => {
      callCount++
    })

    const pubRes = await bus1.publishDurable(
      { eventType: 'IP_BLOCKED', payload: { targetIP: '198.51.100.99' } },
      async () => {}
    )
    expect(pubRes.status).toBe('published')
    expect(callCount).toBe(1)

    // Bus 2 restarts
    const store2 = new FileOutboxStore(outboxFile)
    const bus2 = new SecurityEventBus({ outboxStore: store2 })
    let callCount2 = 0
    bus2.subscribe('IP_BLOCKED', () => {
      callCount2++
    })

    const replayRes = await bus2.replayPendingOutbox()
    expect(replayRes.replayed).toBe(0)
    expect(replayRes.pending).toBe(0)
    expect(callCount2).toBe(0) // Already acknowledged, not re-emitted
  })

  test('3. Corrupted / Partial Write Handling: malformed JSON triggers backup preservation without crashing', async () => {
    const outboxFile = path.join(tmpDir, 'corrupt_outbox.json')
    // Write partial/corrupted JSON
    fs.writeFileSync(outboxFile, '{"test-1": { "status": "PENDING", "enve', 'utf8')

    const store = new FileOutboxStore(outboxFile)
    // Should not throw SyntaxError; should recover cleanly
    const pending = await store.getPendingEvents()
    expect(pending).toEqual([])

    // Verify a corrupt backup was created
    const filesInDir = fs.readdirSync(tmpDir)
    const hasCorruptBackup = filesInDir.some((f) => f.includes('corrupt_outbox.json.corrupt'))
    expect(hasCorruptBackup).toBe(true)

    // Now write a valid event to the recovered store
    await store.persistEnvelope({ eventId: 'new-evt', eventType: 'SYSTEM_HEALTH', payload: {} })
    const pendingNew = await store.getPendingEvents()
    expect(pendingNew.length).toBe(1)
  })

  test('4. Retry Exhaustion (Poison Pill): events exceeding 3 failed attempts transition to FAILED', async () => {
    const store = new InMemoryOutboxStore()
    const bus = new SecurityEventBus({ outboxStore: store })

    bus.subscribe('THREAT_DETECTED', () => {
      throw new Error('Poison pill consumer crash')
    })

    // Attempt 1
    await bus.publishDurable({ eventType: 'THREAT_DETECTED', payload: { badData: true } }, async () => {})

    // Replay 1 (Attempt 2)
    await bus.replayPendingOutbox()
    let pending = await store.getPendingEvents()
    expect(pending.length).toBe(1)

    // Replay 2 (Attempt 3 -> marks FAILED)
    await bus.replayPendingOutbox()
    pending = await store.getPendingEvents()
    expect(pending.length).toBe(0) // Quarantined out of pending queue

    const rawRecord = Array.from(store.records.values())[0]
    expect(rawRecord.status).toBe('FAILED')
    expect(rawRecord.attempts).toBeGreaterThanOrEqual(3)
    expect(rawRecord.lastError).toContain('Poison pill')
  })

  test('5. Concurrent Delivery: multiple parallel publishers write safely with atomic locking', async () => {
    const outboxFile = path.join(tmpDir, 'concurrent_outbox.json')
    const store = new FileOutboxStore(outboxFile)
    const bus = new SecurityEventBus({ outboxStore: store })

    const received = []
    bus.subscribe('ALERT_CREATED', (e) => {
      received.push(e)
    })

    // Publish 20 events concurrently
    const promises = []
    for (let i = 0; i < 20; i++) {
      promises.push(bus.publishDurable({ eventType: 'ALERT_CREATED', payload: { index: i } }, async () => {}))
    }

    const results = await Promise.all(promises)
    expect(results.length).toBe(20)
    expect(received.length).toBe(20)

    // Verify all 20 were marked delivered
    const pending = await store.getPendingEvents()
    expect(pending.length).toBe(0)
  })

  test('6. Retention Pruning: delivered events are pruned past threshold while pending events are preserved', async () => {
    const outboxFile = path.join(tmpDir, 'prune_outbox.json')
    const store = new FileOutboxStore(outboxFile)

    const data = {}
    // Inject 350 DELIVERED records and 2 PENDING records
    for (let i = 0; i < 350; i++) {
      data[`del-${i}`] = {
        envelope: { eventId: `del-${i}`, eventType: 'SYSTEM_HEALTH', payload: {} },
        status: 'DELIVERED',
        createdAt: new Date().toISOString(),
      }
    }
    data['pending-1'] = {
      envelope: { eventId: 'pending-1', eventType: 'ALERT_CREATED', payload: {} },
      status: 'PENDING',
      createdAt: new Date().toISOString(),
    }
    data['pending-2'] = {
      envelope: { eventId: 'pending-2', eventType: 'ALERT_CREATED', payload: {} },
      status: 'PENDING',
      createdAt: new Date().toISOString(),
    }

    store._writeAll(data)

    // After write, total entries should be capped to 100 delivered + 2 pending = 102
    const readBack = store._readAll()
    const count = Object.keys(readBack).length
    expect(count).toBe(102)
    expect(readBack['pending-1']).toBeDefined()
    expect(readBack['pending-2']).toBeDefined()
  })

  test('7. Delivery Semantics: at-least-once delivery documented and verified', async () => {
    // If a subscriber crashes AFTER receiving an event, the event is re-emitted on restart,
    // demonstrating at-least-once (not exactly-once) delivery.
    const store = new InMemoryOutboxStore()
    const bus1 = new SecurityEventBus({ outboxStore: store })

    let process1Handled = false
    bus1.subscribe('IP_UNBLOCKED', () => {
      process1Handled = true
      // Process dies immediately before bus confirms to outbox
      throw new Error('Power failure simulation')
    })

    await bus1.publishDurable({ eventType: 'IP_UNBLOCKED', payload: { ip: '10.0.0.1' } }, async () => {})
    expect(process1Handled).toBe(true)

    // Restart process
    const bus2 = new SecurityEventBus({ outboxStore: store })
    let process2Handled = false
    bus2.subscribe('IP_UNBLOCKED', () => {
      process2Handled = true
    })

    await bus2.replayPendingOutbox()
    expect(process2Handled).toBe(true) // Re-delivered! Proves at-least-once semantics
  })

  test('8. Operational Visibility: outbox stats report accurate counts for pending, delivered, and failed', async () => {
    const outboxFile = path.join(tmpDir, 'metrics_outbox.json')
    const store = new FileOutboxStore(outboxFile)
    const bus = new SecurityEventBus({ outboxStore: store })

    bus.subscribe('ALERT_CREATED', () => {}) // succeeds
    bus.subscribe('THREAT_DETECTED', () => {
      throw new Error('fail')
    }) // fails

    await bus.publishDurable({ eventType: 'ALERT_CREATED', payload: { a: 1 } }, async () => {})
    await bus.publishDurable({ eventType: 'THREAT_DETECTED', payload: { b: 2 } }, async () => {})

    const stats = await bus.getOutboxStatus()
    expect(stats.supported).toBe(true)
    expect(stats.total).toBe(2)
    expect(stats.delivered).toBe(1)
    expect(stats.pending).toBe(1) // THREAT_DETECTED is pending retry
    expect(stats.failed).toBe(0)
  })

  test('9. Failed Event Recovery & Manual Redrive: quarantined events can be inspected and redriven', async () => {
    const outboxFile = path.join(tmpDir, 'redrive_outbox.json')
    const store = new FileOutboxStore(outboxFile)
    const bus = new SecurityEventBus({ outboxStore: store })

    let failCount = 0
    bus.subscribe('ALERT_CREATED', () => {
      failCount++
      if (failCount <= 3) throw new Error('Temporary downstream outage')
    })

    // Exhaust retries to force status -> FAILED
    await bus.publishDurable({ eventType: 'ALERT_CREATED', payload: { alert: 'test' } }, async () => {})
    await bus.replayPendingOutbox()
    await bus.replayPendingOutbox()

    const failedBefore = await store.getFailedEvents()
    expect(failedBefore.length).toBe(1)
    expect(failedBefore[0].attempts).toBe(3)
    expect(failedBefore[0].lastError).toContain('Temporary downstream outage')

    // Operator triggers manual redrive
    const redriveRes = await bus.redriveFailedOutbox()
    expect(redriveRes.redriven).toBe(1)

    // Verify it is back in pending and replay succeeds
    const statsAfterRedrive = await bus.getOutboxStatus()
    expect(statsAfterRedrive.pending).toBe(1)
    expect(statsAfterRedrive.failed).toBe(0)

    // Now subscriber succeeds on 4th attempt
    const replayRes = await bus.replayPendingOutbox()
    expect(replayRes.replayed).toBe(1)

    const finalStats = await bus.getOutboxStatus()
    expect(finalStats.delivered).toBe(1)
    expect(finalStats.pending).toBe(0)
  })
})
