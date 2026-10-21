'use strict'
/** M5: retention runs on a schedule only when both enabled and given an interval, and never at startup. */
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
const { RetentionScheduler } = require('../services/retentionScheduler')

describe('RetentionScheduler', () => {
  beforeEach(() => jest.useFakeTimers())
  afterEach(() => jest.useRealTimers())

  test.each([
    [false, 24],
    [true, undefined],
    [true, 0],
    [true, NaN],
  ])('not scheduled when enabled=%s, interval=%s', (enabled, intervalHours) => {
    const run = jest.fn()
    const s = new RetentionScheduler({ enabled, intervalHours, run })
    expect(s.start()).toBe(false)
    jest.advanceTimersByTime(48 * 3600 * 1000)
    expect(run).not.toHaveBeenCalled()
  })

  test('runs an applied retention once per interval, first after one interval', async () => {
    const run = jest.fn().mockResolvedValue({ deleted: { sessions: 1 } })
    const s = new RetentionScheduler({ enabled: true, intervalHours: 24, run })
    expect(s.start()).toBe(true)
    expect(run).not.toHaveBeenCalled() // never at startup
    jest.advanceTimersByTime(24 * 3600 * 1000)
    expect(run).toHaveBeenCalledTimes(1)
    expect(run).toHaveBeenCalledWith({ dryRun: false, actor: { id: 'retention-scheduler', role: 'service' } })
    await Promise.resolve()
    jest.advanceTimersByTime(24 * 3600 * 1000)
    expect(run).toHaveBeenCalledTimes(2)
    s.stop()
    jest.advanceTimersByTime(48 * 3600 * 1000)
    expect(run).toHaveBeenCalledTimes(2)
  })

  test('a failing run is logged and does not stop the schedule', async () => {
    const run = jest.fn().mockRejectedValue(new Error('db down'))
    const s = new RetentionScheduler({ enabled: true, intervalHours: 1, run })
    s.start()
    jest.advanceTimersByTime(3600 * 1000)
    await Promise.resolve()
    await Promise.resolve()
    expect(require('../utils/logger').error).toHaveBeenCalledWith('[RetentionScheduler] Run failed: db down')
    jest.advanceTimersByTime(3600 * 1000)
    expect(run).toHaveBeenCalledTimes(2)
    s.stop()
  })
})
