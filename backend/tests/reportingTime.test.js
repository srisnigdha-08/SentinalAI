const { calendarRange, filter, metadata, dayGroup, hourGroup, TIME_ZONE } = require('../utils/reportingTime')
test.each([
  ['2026-10-13T18:29:59.999Z', '2026-10-12T18:30:00.000Z', '2026-10-13T18:30:00.000Z'],
  ['2026-10-13T18:30:00.000Z', '2026-10-13T18:30:00.000Z', '2026-10-14T18:30:00.000Z'],
  ['2025-12-31T18:30:00.000Z', '2025-12-31T18:30:00.000Z', '2026-01-01T18:30:00.000Z'],
  ['2024-02-28T18:30:00.000Z', '2024-02-28T18:30:00.000Z', '2024-02-29T18:30:00.000Z'],
  ['2024-02-29T18:30:00.000Z', '2024-02-29T18:30:00.000Z', '2024-03-01T18:30:00.000Z'],
])('IST calendar boundary for %s', (instant, start, end) => {
  const range = calendarRange(1, new Date(instant))
  expect(range.start.toISOString()).toBe(start)
  expect(range.end.toISOString()).toBe(end)
  expect(filter(1, new Date(instant))).toEqual({ $gte: range.start, $lt: range.end })
})
test('seven-day window is today plus six preceding IST calendar days', () => {
  expect(metadata(7, new Date('2026-10-13T20:00:00Z'))).toEqual({
    timeZone: 'Asia/Kolkata',
    window: 'calendar-days',
    days: 7,
    rangeStart: '2026-10-07T18:30:00.000Z',
    rangeEnd: '2026-10-14T18:30:00.000Z',
  })
})
test('bounds are invariant across host timezone settings', () => {
  const old = process.env.TZ
  const results = ['UTC', 'Asia/Kolkata', 'America/New_York'].map((zone) => {
    process.env.TZ = zone
    return metadata(1, new Date('2026-01-01T02:00:00Z'))
  })
  if (old === undefined) delete process.env.TZ
  else process.env.TZ = old
  expect(results[0]).toEqual(results[1])
  expect(results[1]).toEqual(results[2])
})
test('MongoDB expressions explicitly specify reporting zone and account for half-hour offset', () => {
  expect(dayGroup().$dateToString.timezone).toBe(TIME_ZONE)
  expect(hourGroup().$hour.timezone).toBe(TIME_ZONE)
  const clock = (instant) => new Date(instant).toLocaleTimeString('en-IN', { timeZone: TIME_ZONE, hour12: false })
  expect(clock('2026-10-14T00:00:00Z')).toBe('05:30:00')
  expect(clock('2026-10-14T00:30:00Z')).toBe('06:00:00')
})
test('invalid range input fails explicitly', () => {
  for (const value of [0, -1, 1.5, 91, NaN]) expect(() => calendarRange(value)).toThrow()
  expect(() => calendarRange(1, new Date('invalid'))).toThrow()
})
