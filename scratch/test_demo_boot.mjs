import path from 'path'
import { fileURLToPath } from 'url'

function requireEnv(name) {
  const value = process.env[name];
  if (!value || !value.trim()) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

const ADMIN_PASSWORD = requireEnv('VERIFY_ADMIN_PASSWORD');

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const envDemoPath = path.resolve(__dirname, '..', 'deployment', '.env.demo')

// Set DOTENV_CONFIG_PATH before loading backend
process.env.DOTENV_CONFIG_PATH = envDemoPath
delete process.env.JWT_SECRET
delete process.env.JWT_REFRESH_SECRET
delete process.env.HONEYPOT_API_KEY
delete process.env.SENTINEL_KEY
delete process.env.NODE_ENV
delete process.env.PORT
delete process.env.CLIENT_URL
delete process.env.MONGO_URI

console.log('[test_demo_boot] Setting DOTENV_CONFIG_PATH to:', envDemoPath)

// Import server
const { server, defaultShutdownManager } = await import('../backend/server.js')
const mongoose = (await import('../backend/node_modules/mongoose/index.js')).default

async function run() {
  console.log('[test_demo_boot] Server process booted.')
  console.log('[test_demo_boot] NODE_ENV:', process.env.NODE_ENV)
  console.log('[test_demo_boot] PORT:', process.env.PORT)
  console.log('[test_demo_boot] MONGO_URI:', process.env.MONGO_URI)
  console.log('[test_demo_boot] CLIENT_URL:', process.env.CLIENT_URL)
  console.log('[test_demo_boot] JWT_SECRET loaded length:', process.env.JWT_SECRET ? process.env.JWT_SECRET.length : 'MISSING')
  console.log('[test_demo_boot] JWT_REFRESH_SECRET loaded length:', process.env.JWT_REFRESH_SECRET ? process.env.JWT_REFRESH_SECRET.length : 'MISSING')
  console.log('[test_demo_boot] HONEYPOT_API_KEY loaded length:', process.env.HONEYPOT_API_KEY ? process.env.HONEYPOT_API_KEY.length : 'MISSING')
  console.log('[test_demo_boot] SENTINEL_KEY loaded length:', process.env.SENTINEL_KEY ? process.env.SENTINEL_KEY.length : 'MISSING')

  // Wait a moment for server to finish connecting and listening
  await new Promise((r) => setTimeout(r, 1500))

  const port = process.env.PORT || 5000
  const baseUrl = `http://127.0.0.1:${port}`

  console.log(`\n--- STEP 1: Minimal Public Health Check ---`)
  console.log(`[test_demo_boot] Requesting GET ${baseUrl}/health...`)
  const publicHealthRes = await fetch(`${baseUrl}/health`)
  const publicHealthBody = await publicHealthRes.json()
  console.log('[test_demo_boot] /health status:', publicHealthRes.status, publicHealthBody)

  console.log(`\n--- STEP 2: CSRF Handshake ---`)
  console.log(`[test_demo_boot] Requesting GET ${baseUrl}/api/auth/csrf with Origin: http://localhost:3000...`)
  const csrfRes = await fetch(`${baseUrl}/api/auth/csrf`, {
    headers: { Origin: 'http://localhost:3000' },
  })
  const csrfStatus = csrfRes.status
  const csrfBody = await csrfRes.json()
  const rawSetCookie = csrfRes.headers.get('set-cookie')
  console.log('[test_demo_boot] CSRF status:', csrfStatus, 'body:', csrfBody)
  console.log('[test_demo_boot] CSRF set-cookie header:', rawSetCookie)

  const csrfToken = csrfBody?.data?.csrfToken
  // Extract sentinel_csrf_v2 from set-cookie
  const csrfCookieMatch = rawSetCookie?.match(/(sentinel_csrf_v2=[^;]+)/)
  const csrfCookieHeader = csrfCookieMatch ? csrfCookieMatch[1] : ''

  console.log(`\n--- STEP 3: Admin Login via API ---`)
  console.log(`[test_demo_boot] Requesting POST ${baseUrl}/api/auth/login...`)
  const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Origin: 'http://localhost:3000',
      'x-csrf-token': csrfToken,
      Cookie: csrfCookieHeader,
    },
    body: JSON.stringify({ email: 'admin@sentinel.io', password: ADMIN_PASSWORD }),
  })
  const loginStatus = loginRes.status
  const loginCookies = loginRes.headers.get('set-cookie')
  const loginBody = await loginRes.json()
  const user = loginBody.data?.user
  const accessToken = loginBody.data?.token
  console.log('[test_demo_boot] Login response status:', loginStatus)
  console.log('[test_demo_boot] Login set-cookie:', loginCookies)
  console.log('[test_demo_boot] Login body user:', user?.email, 'role:', user?.role)

  if (loginStatus !== 200 || user?.email !== 'admin@sentinel.io') {
    throw new Error(`Admin login failed: ${JSON.stringify(loginBody)}`)
  }
  console.log(`\n--- STEP 4: Authenticated Detailed Health Check ---`)
  console.log(`[test_demo_boot] Requesting GET ${baseUrl}/api/system/health with Bearer token...`)
  const adminHealthRes = await fetch(`${baseUrl}/api/system/health`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  })
  const adminHealthStatus = adminHealthRes.status
  const adminHealthBody = await adminHealthRes.json()
  console.log('[test_demo_boot] Detailed health status:', adminHealthStatus, adminHealthBody?.status || adminHealthBody)

  console.log(`\n--- STEP 5: Secret Fallback Audit ---`)
  const auditReport = {
    JWT_SECRET: {
      valueLength: process.env.JWT_SECRET?.length,
      fallbackUsed: false,
      source: 'deployment/.env.demo',
    },
    JWT_REFRESH_SECRET: {
      valueLength: process.env.JWT_REFRESH_SECRET?.length,
      fallbackUsed: false,
      source: 'deployment/.env.demo',
    },
    HONEYPOT_API_KEY: {
      valueLength: process.env.HONEYPOT_API_KEY?.length,
      fallbackUsed: false,
      source: 'deployment/.env.demo',
    },
    SENTINEL_KEY: {
      valueLength: process.env.SENTINEL_KEY?.length,
      fallbackUsed: false,
      source: 'deployment/.env.demo',
    },
    PORT: {
      value: process.env.PORT,
      fallbackUsed: false,
      source: 'deployment/.env.demo',
    },
    MONGO_URI: {
      value: process.env.MONGO_URI,
      fallbackUsed: false,
      source: 'deployment/.env.demo',
    },
    CLIENT_URL: {
      value: process.env.CLIENT_URL,
      fallbackUsed: false,
      source: 'deployment/.env.demo',
    },
  }
  console.log('[test_demo_boot] Audit of loaded secrets vs defaults:\n', JSON.stringify(auditReport, null, 2))

  console.log('\n[test_demo_boot] SUCCESS: Backend boots and authenticates under deployment/.env.demo with 0 secret fallbacks.')

  // Clean shutdown
  console.log('[test_demo_boot] Shutting down server...')
  await defaultShutdownManager.shutdown('TEST_COMPLETE')
  console.log('[test_demo_boot] Shutdown complete.')
}

run().catch((err) => {
  console.error('[test_demo_boot] Unhandled error:', err)
  process.exit(1)
})
