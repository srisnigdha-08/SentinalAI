const mongoose = require('mongoose')
const crypto = require('crypto')
const suite = process.env.AUTH_TEST_MONGO_URI ? describe : describe.skip
const Threat = require('../models/ThreatLog')
const Prediction = require('../models/AIPrediction')
const Honeypot = require('../models/HoneypotSession')
const { getDashboardAnalytics, getAttackVectorTrend } = require('../services/threatService')
const { getModelStats } = require('../services/aiService')
const getFullAnalytics = (...args) => require('../services/honeypotService').getFullAnalytics(...args)
suite('Actual MongoDB reporting aggregates in isolated regression database', () => {
  beforeAll(async () => {
    const url = new URL(process.env.AUTH_TEST_MONGO_URI)
    if (
      url.hostname !== '127.0.0.1' ||
      url.port !== '27029' ||
      url.pathname !== '/sentinelai_auth_timezone_test_20261014'
    )
      throw new Error('Unapproved database')
    await mongoose.connect(process.env.AUTH_TEST_MONGO_URI)
  })
  afterAll(() => mongoose.disconnect())
  test('IST Today/hour/week counts agree and exclude next midnight; persisted dates are unchanged', async () => {
    let year = 2032
    while (
      await Threat.exists({
        createdAt: require('../utils/reportingTime').filter(1, new Date(`${year}-01-01T08:00:00Z`)),
      })
    )
      year++
    const previous = year - 1
    const instants = [
      `${previous}-12-30T18:30:00Z`,
      `${previous}-12-31T18:29:59.999Z`,
      `${previous}-12-31T18:30:00Z`,
      `${year}-01-01T00:00:00Z`,
      `${year}-01-01T00:30:00Z`,
      `${year}-01-01T18:30:00Z`,
    ]
    const tag = 'TIMEZONE-REGRESSION-' + crypto.randomUUID()
    const documents = instants.map((instant, index) => ({
      sourceIP: '192.0.2.' + (index + 1),
      attackType: 'DDoS',
      severity: 'HIGH',
      status: index === 3 ? 'BLOCKED' : 'MONITORING',
      notes: tag,
      createdAt: new Date(instant),
    }))
    await Threat.collection.insertMany(documents) // Explicit test fixtures only, no alerts/feed callbacks.
    await Prediction.collection.insertMany(
      instants.map((instant) => ({
        predictedClass: 'DDoS',
        threatScore: 0.7,
        createdAt: new Date(instant),
        rawFeatures: { regressionFixture: tag },
      }))
    )
    await Honeypot.collection.insertMany(
      instants.map((instant, index) => ({
        sessionId: tag + index,
        sourceIP: '192.0.2.100',
        honeypotNode: 'SSH-COWRIE-01',
        status: 'closed',
        createdAt: new Date(instant),
        commands: [],
        durationSeconds: 0,
      }))
    )
    const now = new Date(`${year}-01-01T08:00:00Z`)
    const analytics = await getDashboardAnalytics(now)
    expect(analytics.kpis.totalToday).toBe(3)
    expect(analytics.charts.hourlyToday.reduce((sum, hour) => sum + hour.count, 0)).toBe(3)
    expect(analytics.charts.hourlyToday.find((hour) => hour.hour === '00:00').count).toBe(1)
    expect(analytics.charts.hourlyToday.find((hour) => hour.hour === '05:00').count).toBe(1)
    expect(analytics.charts.hourlyToday.find((hour) => hour.hour === '06:00').count).toBe(1)
    expect(analytics.charts.hourlyToday.reduce((sum, hour) => sum + hour.blocked, 0)).toBe(1)
    expect(analytics.charts.weeklyTrend.find((day) => day._id === `${year}-01-01`).total).toBe(3)
    expect(analytics.reporting.today.rangeStart).toBe(`${previous}-12-31T18:30:00.000Z`)
    const vector = await getAttackVectorTrend(7, now)
    expect(vector.find((day) => day._id.date === `${year}-01-01`).count).toBe(3)
    const ai = await getModelStats(now)
    expect(ai.summary.weekPredictions).toBe(5)
    expect(ai.charts.dailyPredictions.find((day) => day._id === `${year}-01-01`).count).toBe(3)
    const hp = await getFullAnalytics(now)
    expect(hp.kpis.totalToday).toBe(3)
    expect(hp.charts.dailySessions.find((day) => day._id === `${year}-01-01`).sessions).toBe(3)
    const saved = await Threat.find({ notes: tag }).sort({ createdAt: 1 }).lean()
    expect(saved.map((row) => row.createdAt.toISOString())).toEqual(
      instants.map((value) => new Date(value).toISOString())
    )
  })
})
