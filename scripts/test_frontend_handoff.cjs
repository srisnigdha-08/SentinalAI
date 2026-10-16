// Explicit offline component fixtures: no database, token, telemetry or live acceptance.
const fs = require('node:fs')
const path = require('node:path')
const { pathToFileURL } = require('node:url')
const assert = require('node:assert/strict')
const { createRequire } = require('node:module')
const root = path.resolve(__dirname, '..')
const task = path.join(root, '.test-runtime/docker-completion-20261015-6c831d9a')
const mode = process.argv.includes('--baseline') ? 'baseline' : 'final'
const evidence = path.join(task, 'ui-' + mode + '-' + Date.now())
if (fs.existsSync(evidence)) throw new Error('UI evidence already exists')
fs.mkdirSync(evidence)
const fixtures = path.join(evidence, 'fixtures')
fs.mkdirSync(fixtures)
const frontend = path.join(root, 'frontend')
const frontendRequire = createRequire(path.join(frontend, 'package.json'))
const frontendModule = relative => pathToFileURL(path.join(frontend, 'node_modules', relative)).href
const jsxPath = relative => JSON.stringify('/@fs/' + path.join(frontend, relative).replaceAll('\\', '/'))
fs.writeFileSync(path.join(fixtures, 'hooks.js'), `
export const useAuth=()=>({user:new URLSearchParams(location.search).get('role')==='anonymous'?null:{role:new URLSearchParams(location.search).get('role')||'analyst',email:'offline-component@example.invalid'},logout:async()=>({confirmed:false}),logoutAll:async()=>({confirmed:false})})
export const useSocket=()=>({connected:false,on:()=>()=>{}})
`)
fs.writeFileSync(path.join(fixtures, 'api.js'), `
const response=data=>Promise.resolve({data:{data}})
export const threatAPI={analytics:()=>response({kpis:{},charts:{}}),list:()=>response([]),recent:()=>response([]),vectorTrend:()=>response({trend:[]})}
export const honeypotAPI={nodes:()=>response({nodes:[]})}
export const systemAPI={health:()=>response({aiEngine:{status:'unavailable'},database:{status:'unavailable'},memory:{}})}
export const alertAPI={list:()=>response([]),unreadCount:()=>response({count:0})}
export const userAPI={list:()=>response([]),stats:()=>response({total:0,byRole:[]}),create:async data=>{window.__offlineProvision={...data,password:'[omitted]'};return response({user:{_id:'offline-only',name:data.name,email:data.email,role:data.role}})}}
`)
fs.writeFileSync(path.join(fixtures, 'entry.jsx'), `
import React from 'react'
import {createRoot} from 'react-dom/client'
import {BrowserRouter} from 'react-router-dom'
import Dashboard from ${jsxPath('src/pages/Dashboard.jsx')}
import Register from ${jsxPath('src/pages/Register.jsx')}
import Users from ${jsxPath('src/pages/UserManagement.jsx')}
import ${jsxPath('src/styles/globals.css')}
const screen=new URLSearchParams(location.search).get('screen')
createRoot(document.getElementById('root')).render(<BrowserRouter><div style={{position:'relative',marginTop:56,padding:8,color:'#ffaa00'}}>OFFLINE COMPONENT TEST — mocked API, no telemetry or authentication acceptance</div>{screen==='register'?<Register/>:screen==='users'?<Users/>:<Dashboard/>}</BrowserRouter>)
`)
;(async () => {
  let server, browser, serverPort
  const checks = [], failures = [], errors = []
  try {
    const { createServer } = await import(frontendModule('vite/dist/node/index.js'))
    const react = (await import(frontendModule('@vitejs/plugin-react/dist/index.js'))).default
    process.chdir(frontend)
    const harness = { name: 'offline-component-harness', configureServer(vite) {
      vite.middlewares.use(async (req, res, next) => {
        if (!req.url.startsWith('/offline-handoff')) return next()
        const html = await vite.transformIndexHtml(req.url, '<html><head><title>Offline SentinelAI component regression</title></head><body><div id="root"></div><script type="module" src="/@fs/' + path.join(fixtures, 'entry.jsx').replaceAll('\\', '/') + '"></script></body></html>')
        res.setHeader('Content-Type', 'text/html'); res.end(html)
      })
    } }
    server = await createServer({ configFile: false, root: frontend, cacheDir: path.join(evidence, 'vite-cache'),
      optimizeDeps: { entries: [path.join(fixtures, 'entry.jsx')] },
      plugins: [react(), harness], resolve: { alias: [
        ...['react', 'react/jsx-runtime', 'react/jsx-dev-runtime', 'react-dom/client', 'react-router-dom'].map(name => ({ find: new RegExp('^' + name + '$'), replacement: frontendRequire.resolve(name) })),
        { find: /.*\/hooks\/useAuth\.js$/, replacement: path.join(fixtures, 'hooks.js') },
        { find: /.*\/hooks\/useSocket\.js$/, replacement: path.join(fixtures, 'hooks.js') },
        { find: /.*\/services\/api\.js$/, replacement: path.join(fixtures, 'api.js') },
      ] }, server: { host: '127.0.0.1', port: 0, fs: { allow: [root] } } })
    await server.listen()
    const port = server.httpServer.address().port
    serverPort = port
    const puppeteer = require(path.join(root, 'backend/node_modules/puppeteer-core'))
    const executablePath = ['C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe'].find(file => fs.existsSync(file))
    if (!executablePath) throw new Error('Existing Chrome unavailable; no download permitted')
    browser = await puppeteer.launch({ executablePath, headless: true, pipe: true, userDataDir: path.join(evidence, 'browser-profile'), args: ['--no-first-run', '--disable-background-networking'] })
    const page = await browser.newPage()
    await page.setRequestInterception(true)
    page.on('request', req => req.url().startsWith('http://127.0.0.1:' + port) || req.url().startsWith('data:') ? req.continue() : req.abort())
    page.on('pageerror', error => errors.push(error.message))
    const origin = 'http://127.0.0.1:' + port
    for (const role of ['admin', 'analyst', 'viewer']) for (const width of [375, 800, 1440]) {
      await page.setViewport({ width, height: 1000 })
      await page.goto(origin + '/offline-handoff?role=' + role, { waitUntil: 'networkidle0', timeout: 60000 })
      await page.waitForSelector('main table', { timeout: 15000 })
      const metrics = await page.evaluate(() => {
        const main = document.querySelector('main'), mainRect = main.getBoundingClientRect()
        const tables = [...main.querySelectorAll('table')]
        return { documentWidth: document.documentElement.scrollWidth, viewport: innerWidth, mainWidth: mainRect.width,
          permissionLabel: main.textContent.includes('CONTAINMENT ARMED') ? 'misleading' : main.textContent.includes('ANALYST PERMISSIONS') ? 'analyst' : main.textContent.includes('ADMIN PERMISSIONS') ? 'admin' : main.textContent.includes('READ ONLY') ? 'viewer' : 'missing',
          panelRightMax: Math.max(...[...main.querySelectorAll('[data-sentinel-panel]')].map(panel => panel.getBoundingClientRect().right), 0),
          mainRight: mainRect.right,
          tableScrollLocal: tables.every(table => { let parent=table.parentElement; while(parent && parent!==main){if(['auto','scroll'].includes(getComputedStyle(parent).overflowX))return true;parent=parent.parentElement}return table.scrollWidth<=mainRect.width }) }
      })
      const geometryPass = metrics.documentWidth <= width + 1 && metrics.panelRightMax <= metrics.mainRight + 1 && metrics.tableScrollLocal
      const labelPass = metrics.permissionLabel === role
      checks.push({ role, width, geometryPass, labelPass, metrics, category: 'actual Chrome/component rendering; explicit mocked API' })
      if (!labelPass || (mode === 'final' && !geometryPass)) failures.push({ role, width, geometryPass, labelPass })
      if (role === 'analyst') await page.screenshot({ path: path.join(evidence, 'dashboard-' + width + '.png'), fullPage: true })
    }
    await page.setViewport({ width: 375, height: 1000 })
    await page.goto(origin + '/offline-handoff?screen=register&role=anonymous', { waitUntil: 'networkidle0' })
    assert.equal((await page.$$('form')).length, 0)
    assert.match(await page.$eval('body', el => el.textContent), /Public registration is disabled/)
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    checks.push({ name: 'Retired registration view has no form and explains administrator-only access', passed: true })
    await page.goto(origin + '/offline-handoff?screen=users&role=admin', { waitUntil: 'networkidle0' })
    const buttons = await page.$$('button')
    let opened = false
    for (const button of buttons) if ((await button.evaluate(el => el.textContent)).includes('Provision Operator')) { await button.click(); opened = true; break }
    assert.equal(opened, true)
    await page.waitForSelector('form')
    assert.equal(await page.$eval('form select', el => el.value), 'viewer')
    const values = ['Offline UI Regression', 'ui-regression@example.invalid', 'OnlyForOfflineComponentTest123']
    const inputs = await page.$$('form input')
    for (let i = 0; i < values.length; i++) await inputs[i].type(values[i])
    await page.click('form button[type=submit]')
    await page.waitForFunction(() => window.__offlineProvision)
    assert.equal(await page.evaluate(() => window.__offlineProvision.role), 'viewer')
    await page.waitForFunction(() => !document.querySelector('form'))
    checks.push({ name: 'Actual admin form submits viewer-default payload and clears after mocked API acknowledgement', passed: true, category: 'mocked API; no persistent account' })
    if (errors.length) throw new Error('Browser runtime errors: ' + errors.join('; '))
    if (failures.length) throw new Error('Component regression failed; see per-viewport evidence')
  } catch (error) { failures.push({ error: error.message }); process.exitCode = 1 }
  finally {
    const browserPID = browser?.process()?.pid
    if (browser) await browser.close()
    if (server) await server.close()
    const result = { mode, category: 'offline browser component regressions; mocked API; no models/database/live telemetry', parentPID: process.pid, serverAddress: '127.0.0.1', serverPort, checks, failures, errors, browserPID, browserClosed: !browser || browser.process().exitCode !== null, ownedServerClosed: !server || !server.httpServer.listening }
    fs.writeFileSync(path.join(evidence, 'results.json'), JSON.stringify(result, null, 2), { flag: 'wx' })
    console.log(JSON.stringify({ mode, checks: checks.length, failures: failures.length, browserPID, evidence, browserClosed: result.browserClosed, ownedServerClosed: result.ownedServerClosed }))
  }
})().catch(error => { console.error(error.name + ': ' + error.message); process.exitCode = 1 })
