'use strict'
/**
 * SentinelContainmentAuditLoss alerts on increase(sentinel_containment_audit_loss_total[15m]) > 0. Prometheus cannot see
 * an increase on a series whose first sample is already non-zero, so the first audit loss would never alert unless
 * each reason is exported at 0 from startup.
 */
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

test('every audit loss reason is exported at zero before any loss happens', () => {
  jest.isolateModules(() => {
    const metrics = require('../utils/metrics')
    require('../utils/containmentAudit')
    const text = metrics.render()
    for (const reason of ['backlog_full', 'spool_unavailable', 'spool_unreadable']) {
      expect(text).toContain(`sentinel_containment_audit_loss_total{reason="${reason}"} 0`)
    }
  })
})
