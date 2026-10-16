// Runs only against the separately approved port/database; never against live development or acceptance DB.
const available = Boolean(process.env.AUTH_TEST_MONGO_URI)
const suite = available ? describe : describe.skip
const mongoose = require('mongoose')
const request = require('supertest')
const crypto = require('crypto')
const User = require('../models/User')
const Session = require('../models/AuthSession')

suite('Disposable MongoDB Credential Lifecycle Integration', () => {
  let app
  let server
  let io

  beforeAll(async () => {
    const url = new URL(process.env.AUTH_TEST_MONGO_URI)
    if (
      url.hostname !== '127.0.0.1' ||
      url.port !== '27029' ||
      url.pathname !== '/sentinelai_auth_timezone_test_20261014'
    ) {
      throw new Error('Unapproved test database')
    }
    await mongoose.connect(process.env.AUTH_TEST_MONGO_URI)
    await Session.init()
    await User.init()
    ;({ app, server, io } = require('../server'))
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  })

  afterAll(async () => {
    require('../websocket/socketManager').stopHealthBroadcast()
    if (io) await new Promise((resolve) => io.close(resolve))
    await mongoose.disconnect()
  })

  async function mutate(agent, endpoint, body = {}, token, method = 'post') {
    const csrf = await agent.get('/api/auth/csrf').set('Origin', process.env.CLIENT_URL || 'http://localhost:3000')
    let call = agent[method]('/api/auth/' + endpoint)
      .set('Origin', process.env.CLIENT_URL || 'http://localhost:3000')
      .set('X-CSRF-Token', csrf.body.data.csrfToken)
    if (token) call = call.set('Authorization', 'Bearer ' + token)
    return call.send(body)
  }

  test('end-to-end credential lifecycle: provision -> restricted login -> blocked SOC access -> password change -> unblocked access', async () => {
    // 1. Create a disposable test administrator
    const adminCredentials = {
      email: 'disp-admin-' + crypto.randomUUID() + '@example.invalid',
      password: 'AdminPassword123!',
    }
    const adminUser = await User.create({
      ...adminCredentials,
      name: 'Disposable Admin',
      role: 'admin',
      status: 'active',
    })
    expect(adminUser.mustChangePassword).toBe(false)

    // Admin logs in
    const adminAgent = request.agent(app)
    const adminLoginRes = await mutate(adminAgent, 'login', adminCredentials)
    expect(adminLoginRes.status).toBe(200)
    const adminToken = adminLoginRes.body.data.token

    // 2. Provision a test operator
    const operatorEmail = 'disp-operator-' + crypto.randomUUID() + '@example.invalid'
    const initialPassword = 'InitialTempPassword123!'
    const provisionRes = await mutate(
      adminAgent,
      'provision',
      {
        name: 'Provisioned Operator',
        email: operatorEmail,
        password: initialPassword,
        role: 'analyst',
        department: 'SOC',
      },
      adminToken
    )
    expect(provisionRes.status).toBe(201)

    // 3. Verify that the operator has mustChangePassword: true in DB and response
    expect(provisionRes.body.data.user.mustChangePassword).toBe(true)
    const storedOperator = await User.findOne({ email: operatorEmail })
    expect(storedOperator.mustChangePassword).toBe(true)
    expect(storedOperator.authVersion).toBe(0)

    // 4. Log in as the operator using test-only credentials
    const opAgent = request.agent(app)
    const opLoginRes = await mutate(opAgent, 'login', {
      email: operatorEmail,
      password: initialPassword,
    })
    expect(opLoginRes.status).toBe(200)
    expect(opLoginRes.body.data.user.mustChangePassword).toBe(true)
    const opToken = opLoginRes.body.data.token

    // 5. Attempt to access a protected SOC endpoint (/api/threats) and verify it is blocked
    const threatsRes = await request(app)
      .get('/api/threats')
      .set('Authorization', 'Bearer ' + opToken)
    expect(threatsRes.status).toBe(403)
    expect(threatsRes.body.code).toBe('PASSWORD_CHANGE_REQUIRED')

    // 6. Change the password successfully
    const newPassword = 'BrandNewPermanentPassword123!'
    const changeRes = await mutate(
      opAgent,
      'update-password',
      {
        currentPassword: initialPassword,
        newPassword,
      },
      opToken,
      'put'
    )
    expect(changeRes.status).toBe(200)
    expect(changeRes.body.data.user.mustChangePassword).toBe(false)
    const replacementToken = changeRes.body.data.token

    // 7. Verify stored flag is false and authVersion has advanced
    const updatedStoredOperator = await User.findOne({ email: operatorEmail })
    expect(updatedStoredOperator.mustChangePassword).toBe(false)
    expect(updatedStoredOperator.authVersion).toBe(1)

    // 8. Verify old credentials cannot restore old session
    const oldAccessRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer ' + opToken)
    expect(oldAccessRes.status).toBe(401)

    // 9. Verify new session can access an authorized endpoint
    const newMeRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer ' + replacementToken)
    expect(newMeRes.status).toBe(200)
    expect(newMeRes.body.data.user.mustChangePassword).toBe(false)

    // 10. Verify port 27029 and disposable database isolation
    expect(mongoose.connection.port).toBe(27029)
    expect(mongoose.connection.name).toBe('sentinelai_auth_timezone_test_20261014')
  })
})
