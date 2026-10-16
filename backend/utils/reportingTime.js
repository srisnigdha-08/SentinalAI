// Modern Indian civil time: UTC+05:30, no DST. Stored dates remain UTC instants.
const TIME_ZONE = 'Asia/Kolkata'
const OFFSET = 330 * 60000
const DAY = 86400000
function calendarRange(days = 1, now = new Date()) {
  if (!Number.isInteger(days) || days < 1 || days > 90 || !Number.isFinite(now.getTime()))
    throw new Error('Invalid reporting range')
  const local = new Date(now.getTime() + OFFSET)
  const midnight = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate()) - OFFSET
  return { start: new Date(midnight - (days - 1) * DAY), end: new Date(midnight + DAY) }
}
function filter(days = 1, now = new Date()) {
  const range = calendarRange(days, now)
  return { $gte: range.start, $lt: range.end }
}
function metadata(days = 1, now = new Date()) {
  const range = calendarRange(days, now)
  return {
    timeZone: TIME_ZONE,
    window: days === 1 ? 'calendar-day' : 'calendar-days',
    days,
    rangeStart: range.start.toISOString(),
    rangeEnd: range.end.toISOString(),
  }
}
function reporting(now = new Date()) {
  return { timeZone: TIME_ZONE, today: metadata(1, now), sevenDay: metadata(7, now) }
}
const dayGroup = () => ({ $dateToString: { format: '%Y-%m-%d', date: '$createdAt', timezone: TIME_ZONE } })
const hourGroup = () => ({ $hour: { date: '$createdAt', timezone: TIME_ZONE } })
module.exports = { TIME_ZONE, calendarRange, filter, metadata, reporting, dayGroup, hourGroup }
