/* global localStorage, location, document */
const suite = process.env.AUTH_TEST_MONGO_URI ? describe : describe.skip
const mongoose = require('mongoose')
const crypto = require('crypto')
const net = require('net')
const fs = require('fs')
const path = require('path')
const { spawn } = require('child_process')
const request = require('supertest')
// Native Node 24 loader supports Puppeteer's ESM entry; Jest's CJS transformer does not.
const puppeteer = process.getBuiltinModule('module').createRequire(__filename)('puppeteer-core')
const User = require('../models/User')
const Session = require('../models/AuthSession')
suite('Actual browser cookie, cross-tab session and cutover regressions', () => {
  let app
  let server
  let io
  let vite
  let browser
  let origin
  let user
  let password
  const root = path.resolve(__dirname, '../..')
  const evidence = path.join(root, '.test-runtime/auth-timezone-db-20261014-01/evidence')
  beforeAll(async () => {
    const uri = new URL(process.env.AUTH_TEST_MONGO_URI)
    if (
      uri.port !== '27029' ||
      uri.hostname !== '127.0.0.1' ||
      uri.pathname !== '/sentinelai_auth_timezone_test_20261014'
    )
      throw new Error('Unapproved test data')
    await mongoose.connect(process.env.AUTH_TEST_MONGO_URI)
    const port = await new Promise((resolve) => {
      const probe = net.createServer()
      probe.listen(0, '127.0.0.1', () => {
        const number = probe.address().port
        probe.close(() => resolve(number))
      })
    })
    origin = 'http://127.0.0.1:' + port
    process.env.CLIENT_URL = origin
    ;({ app, server, io } = require('../server'))
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    password = crypto.randomBytes(24).toString('hex')
    user = await User.create({
      name: 'AUTH BROWSER REGRESSION',
      email: 'browser-regression-' + crypto.randomUUID() + '@example.invalid',
      password,
      role: 'admin',
    })
    const log = fs.openSync(path.join(evidence, 'vite-browser.log'), 'a')
    vite = spawn(
      process.execPath,
      [
        path.join(root, 'frontend/node_modules/vite/bin/vite.js'),
        '--host',
        '127.0.0.1',
        '--port',
        String(port),
        '--strictPort',
      ],
      {
        cwd: path.join(root, 'frontend'),
        windowsHide: true,
        env: { ...process.env, SENTINEL_DEV_API_PROXY: 'http://127.0.0.1:' + server.address().port },
        stdio: ['ignore', log, log],
      }
    )
    fs.closeSync(log)
    let ready = false
    for (let attempt = 0; attempt < 60; attempt++) {
      try {
        if ((await fetch(origin)).ok) {
          ready = true
          break
        }
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 250))
    }
    if (!ready) throw new Error('Test Vite unavailable')
    browser = await puppeteer.launch({
      headless: true,
      executablePath: process.env.BROWSER_EXECUTABLE || 'C:/Program Files/Google/Chrome/Application/chrome.exe',
      userDataDir: path.join(
        root,
        '.test-runtime/auth-timezone-db-20261014-01/browser-hardening-' + crypto.randomUUID()
      ),
      args: ['--no-first-run', '--disable-background-networking'],
    })
  }, 60000)
  afterAll(async () => {
    if (browser) await browser.close()
    if (vite) {
      vite.kill()
      await new Promise((resolve) => {
        if (vite.exitCode !== null || vite.signalCode) resolve()
        else vite.once('exit', resolve)
      })
    }
    require('../websocket/socketManager').stopHealthBroadcast()
    if (io) await new Promise((resolve) => io.close(resolve))
    await mongoose.disconnect()
  })
  test('mandatory cutover, memory access, HttpOnly cookie, actual cross-tab rotation and server logout', async () => {
    const a = await browser.newPage()
    const errors = []
    a.on('pageerror', () => errors.push(true))
    await a.emulateTimezone('UTC')
    await a.evaluateOnNewDocument(() => {
      localStorage.setItem('sentinel_token', 'legacy-token-for-cutover-test')
      localStorage.setItem('sentinel_refresh', 'legacy-refresh-for-cutover-test')
      localStorage.setItem('sentinel_user', '{invalid-legacy}')
    })
    await a.goto(origin + '/dashboard')
    await a.waitForSelector('input[type=email]')
    expect(
      await a.evaluate(() =>
        ['sentinel_token', 'sentinel_refresh', 'sentinel_user'].every((key) => localStorage.getItem(key) === null)
      )
    ).toBe(true)
    await a.type('input[type=email]', user.email)
    await a.type('input[type=password]', password)
    await a.keyboard.press('Enter')
    await a.waitForFunction(() => location.pathname === '/dashboard')
    await a.waitForFunction(() => document.body.innerText.toLowerCase().includes('today (ist)'))
    const actualCookie = (await browser.defaultBrowserContext().cookies()).find(
      (cookie) => cookie.name === 'sentinel_refresh_v2'
    )
    expect(actualCookie.httpOnly).toBe(true)
    expect(actualCookie.sameSite).toBe('Strict')
    expect(await a.evaluate(() => document.cookie.includes('sentinel_refresh'))).toBe(false)
    const token = await a.evaluate(
      async () => (await import('/src/services/authSession.js')).authSession.getState().token
    )
    expect(typeof token).toBe('string')
    expect(await a.evaluate(() => localStorage.getItem('sentinel_token'))).toBeNull()
    const b = await browser.newPage()
    await b.goto(origin + '/dashboard')
    await b.waitForFunction(
      () => location.pathname === '/dashboard' && document.body.innerText.toLowerCase().includes('today (ist)')
    )
    await Promise.all([
      a.evaluate(async () => {
        await (await import('/src/services/authSession.js')).authSession.refresh()
      }),
      b.evaluate(async () => {
        await (await import('/src/services/authSession.js')).authSession.refresh()
      }),
    ])
    const active = await Session.find({ user: user._id, revokedAt: null })
    expect(active.length).toBe(1)
    expect(active[0].generation).toBeGreaterThanOrEqual(3)
    const clock = await a.evaluate(() => document.body.innerText.match(/\d{2}:\d{2}:\d{2}\s+IST/)?.[0])
    expect(clock).toBeDefined()
    await a.screenshot({ path: path.join(evidence, 'auth-memory-cookie-ist.png'), fullPage: true })
    await a.evaluate(() =>
      [...document.querySelectorAll('button')].find((button) => /logout/i.test(button.innerText)).click()
    )
    await a.waitForFunction(() => location.pathname === '/' || location.pathname === '/login', { polling: 100 })
    await b.waitForSelector('input[type=email]')
    for (let attempt = 0; attempt < 40; attempt++) {
      if ((await Session.findById(active[0]._id)).revokedAt) break
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
    expect(
      (
        await request(app)
          .get('/api/auth/me')
          .set('Authorization', 'Bearer ' + token)
      ).status
    ).toBe(401)
    expect((await Session.findById(active[0]._id)).revokedAt).toBeTruthy()
    // Re-login and exercise the dashboard's explicit all-sessions control.
    // Chrome may pause requestAnimationFrame polling in a background tab.
    await a.bringToFront()
    // The logout commit can precede its browser response/confirmation marker.
    await a.waitForFunction(() => localStorage.getItem('sentinel_logout_pending') === null, { polling: 100 })
    await a.goto(origin + '/login')
    await a.waitForSelector('input[type=email]')
    await a.type('input[type=email]', user.email)
    await a.type('input[type=password]', password)
    await a.keyboard.press('Enter')
    try {
      await a.waitForFunction(() => location.pathname === '/dashboard', { polling: 100 })
    } catch {
      const state = await a.evaluate(async () => {
        const state = (await import('/src/services/authSession.js')).authSession.getState()
        return {
          path: location.pathname,
          hasUser: Boolean(state.user),
          hasAccess: Boolean(state.token),
          pendingLogout: localStorage.getItem('sentinel_logout_pending') === '1',
        }
      })
      await a.screenshot({ path: path.join(evidence, 'logout-all-transition-failure.png') })
      throw new Error('Re-login transition failed: ' + JSON.stringify(state))
    }
    const independent = await require('../services/authSessionService').issue(await User.findById(user._id))
    await a.waitForFunction(
      () => [...document.querySelectorAll('button')].some((button) => /logout all sessions/i.test(button.innerText)),
      { polling: 100 }
    )
    await a.evaluate(() =>
      [...document.querySelectorAll('button')].find((button) => /logout all sessions/i.test(button.innerText)).click()
    )
    await a.waitForFunction(() => location.pathname === '/' || location.pathname === '/login', { polling: 100 })
    for (let attempt = 0; attempt < 40; attempt++) {
      if ((await User.findById(user._id)).authVersion === 1) break
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
    expect((await User.findById(user._id)).authVersion).toBe(1)
    expect(
      (
        await request(app)
          .get('/api/auth/me')
          .set('Authorization', 'Bearer ' + independent.token)
      ).status
    ).toBe(401)
    expect(await Session.countDocuments({ user: user._id, revokedAt: null })).toBe(0)
    expect(errors.length).toBe(0)
    await a.close()
    await b.close()
  }, 60000)
})
