import http from 'http'

const accounts = [
  { role: 'admin', email: 'admin@sentinel.io', passEnv: 'VERIFY_ADMIN_PASSWORD' },
  { role: 'analyst', email: 'arjun@sentinel.io', passEnv: 'VERIFY_ANALYST_PASSWORD' },
  { role: 'viewer', email: 'sara@sentinel.io', passEnv: 'VERIFY_VIEWER_PASSWORD' }
]

function getCsrf() {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: 'localhost',
      port: 5000,
      path: '/api/auth/csrf',
      method: 'GET',
      headers: {
        'Origin': 'http://localhost:3000'
      }
    }, (res) => {
      let data = ''
      res.on('data', chunk => data += chunk)
      res.on('end', () => {
        const cookies = res.headers['set-cookie'] || []
        const body = JSON.parse(data)
        resolve({
          csrfToken: body.data?.csrfToken,
          cookie: cookies.map(c => c.split(';')[0]).join('; ')
        })
      })
    })
    req.on('error', reject)
    req.end()
  })
}

async function testLogin(account) {
  const { csrfToken, cookie } = await getCsrf()
  const password = process.env[account.passEnv]
  if (!password) {
    throw new Error(`Missing required environment variable ${account.passEnv}`)
  }
  const payload = JSON.stringify({ email: account.email, password })

  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: 'localhost',
      port: 5000,
      path: '/api/auth/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'Origin': 'http://localhost:3000',
        'X-CSRF-Token': csrfToken,
        'Cookie': cookie
      }
    }, (res) => {
      let data = ''
      res.on('data', chunk => data += chunk)
      res.on('end', () => {
        try {
          const body = JSON.parse(data)
          resolve({ status: res.statusCode, role: account.role, email: account.email, success: body.success, userRole: body.data?.user?.role })
        } catch (e) {
          resolve({ status: res.statusCode, error: data })
        }
      })
    })
    req.on('error', reject)
    req.write(payload)
    req.end()
  })
}

async function run() {
  console.log('=== COLD START LOGIN VERIFICATION ===')
  for (const acc of accounts) {
    const res = await testLogin(acc)
    console.log(`[Role: ${acc.role.padEnd(8)}] Email: ${acc.email.padEnd(20)} -> HTTP ${res.status} | Success: ${res.success} | Verified Role: ${res.userRole}`)
  }
}

run().catch(console.error)
