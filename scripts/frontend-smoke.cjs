// Retired safely: preserve historical source, but do not execute its old protocol/data paths.
throw new Error('Legacy localStorage-auth browser fixture retired. Run the new authBrowser regression using the separately approved test database; see docs/AUTH_TIMEZONE_IMPLEMENTATION.md.')
// Isolated browser checks: no production backend, accounts, telemetry, or database writes.
const http = require('node:http')
const fs = require('node:fs')
const path = require('node:path')
const assert = require('node:assert/strict')
const puppeteer = require('../backend/node_modules/puppeteer-core')
const root = path.resolve(__dirname, '..')
const dist = path.join(root, 'frontend', 'dist')
const server = http.createServer((req, res) => {
  if (req.url.startsWith('/api/') || req.url.startsWith('/socket.io')) {
    res.writeHead(503, { 'Content-Type': 'application/json' })
    return res.end(JSON.stringify({ success: false, error: 'Test backend unavailable' }))
  }
  const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname)
  const target = path.resolve(dist, '.' + pathname)
  if (!target.startsWith(dist + path.sep) && target !== dist) { res.writeHead(403); return res.end() }
  const file = fs.existsSync(target) && fs.statSync(target).isFile() ? target : path.join(dist, 'index.html')
  const mime = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html' }
  res.writeHead(200, { 'Content-Type': mime[path.extname(file)] || 'application/octet-stream' })
  fs.createReadStream(file).pipe(res)
})
;(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  let browser
  try {
    browser = await puppeteer.launch({
      executablePath: process.env.BROWSER_EXECUTABLE || 'C:/Program Files/Google/Chrome/Application/chrome.exe',
      headless: true,
      userDataDir: path.join(root, '.test-runtime', 'browser-profile'),
      args: ['--no-first-run', '--disable-background-networking']
    })
    const page = await browser.newPage()
    const errors = []
    page.on('pageerror', error => errors.push(error.message))
    const origin = 'http://127.0.0.1:' + server.address().port
    await page.goto(origin + '/login')
    await page.waitForSelector('input[type=email]')
    await page.evaluate(() => {
      localStorage.setItem('sentinel_token', 'test-only-token')
      localStorage.setItem('sentinel_user', '{broken')
      localStorage.setItem('sentinel_refresh', 'test-only-refresh')
    })
    await page.reload()
    await page.waitForSelector('input[type=email]')
    assert.equal(await page.evaluate(() => localStorage.getItem('sentinel_token')), null)
    assert.equal(await page.evaluate(() => localStorage.getItem('sentinel_refresh')), null)
    await page.type('input[type=email]', 'browser-check@example.invalid')
    await page.type('input[type=password]', 'test-only-password')
    await page.keyboard.press('Enter')
    await page.waitForFunction(() => document.body.innerText.includes('Test backend unavailable'))
    await page.evaluate(() => {
      localStorage.setItem('sentinel_token', 'test-only-token')
      localStorage.setItem('sentinel_user', JSON.stringify({ _id: 'browser-only', name: 'Browser check', role: 'admin' }))
      localStorage.setItem('sentinel_refresh', 'test-only-refresh')
    })
    await page.goto(origin + '/dashboard')
    await page.waitForFunction(() => document.body.innerText.includes('Dashboard data is unavailable'))
    const dashboard = await page.evaluate(() => document.body.innerText)
    assert.ok(dashboard.includes('UNAVAILABLE'))
    assert.ok(!dashboard.includes('inference ready'))
    assert.ok(!dashboard.includes('pipeline operational'))
    await page.screenshot({ path: path.join(root, '.test-runtime', 'dashboard-unavailable.png'), fullPage: true })
    await page.goto(origin + '/dashboard/threats')
    await page.waitForFunction(() => document.body.innerText.includes('Threat logs are unavailable'))
    await page.evaluate(() => [...document.querySelectorAll('button')].find(button => /logout/i.test(button.innerText)).click())
    await page.waitForFunction(() => location.pathname === '/')
    assert.deepEqual(await page.evaluate(() => ['sentinel_token', 'sentinel_user', 'sentinel_refresh'].map(key => localStorage.getItem(key))), [null, null, null])
    await page.goto(origin + '/dashboard')
    await page.waitForSelector('input[type=email]')
    assert.deepEqual(errors, [])
    console.log('PASS: login failure, corrupt auth recovery, dashboard unavailable state, threat-log error state, logout clears all credentials; no browser exceptions')
  } finally {
    if (browser) await browser.close()
    await new Promise(resolve => server.close(resolve))
  }
})().catch(error => { console.error(error); process.exitCode = 1 })
