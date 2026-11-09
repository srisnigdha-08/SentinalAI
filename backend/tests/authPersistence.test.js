// Runs only against the separately approved port/database; never against retained acceptance.
const available = Boolean(process.env.AUTH_TEST_MONGO_URI)
const suite = available ? describe : describe.skip
const mongoose = require('mongoose')
const request = require('supertest')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const { io: connect } = require('../../frontend/node_modules/socket.io-client')
const User = require('../models/User')
const Session = require('../models/AuthSession')
const auth = require('../services/authSessionService')
suite('Real isolated authentication persistence and concurrency', () => {
  let app
  let server
  let io
  let user
  let credentials
  const clients = []
  beforeAll(async () => {
    const url = new URL(process.env.AUTH_TEST_MONGO_URI)
    if (
      url.hostname !== '127.0.0.1' ||
      url.port !== '27029' ||
      url.pathname !== '/sentinelai_auth_timezone_test_20261014'
    )
      throw new Error('Unapproved test database')
    await mongoose.connect(process.env.AUTH_TEST_MONGO_URI)
    await Session.init()
    await User.init()
    ;({ app, server, io } = require('../server'))
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  })
  beforeEach(async () => {
    credentials = {
      email: 'auth-regression-' + crypto.randomUUID() + '@example.invalid',
      password: 'Regression-Password-123',
    }
    user = await User.create({ ...credentials, name: 'AUTH REGRESSION FIXTURE', role: 'admin' })
  })
  afterEach(() => {
    for (const socket of clients.splice(0)) socket.disconnect()
  })
  afterAll(async () => {
    require('../websocket/socketManager').stopHealthBroadcast()
    if (io) await new Promise((resolve) => io.close(resolve))
    await mongoose.disconnect()
  })
  // Administrators may not demote or deactivate their own account (efd76a4), so role/status changes to the
  // fixture user are made by a second administrator; the assertions about the fixture's sessions are unchanged.
  async function otherAdminToken() {
    const admin = await User.create({
      email: 'auth-regression-admin-' + crypto.randomUUID() + '@example.invalid',
      password: 'Regression-Password-123',
      name: 'AUTH REGRESSION SECOND ADMIN',
      role: 'admin',
    })
    return (await auth.issue(admin)).token
  }
  async function mutate(agent, endpoint, body = {}, token, method = 'post') {
    const csrf = await agent.get('/api/auth/csrf').set('Origin', process.env.CLIENT_URL)
    let call = agent[method]('/api/auth/' + endpoint)
      .set('Origin', process.env.CLIENT_URL)
      .set('X-CSRF-Token', csrf.body.data.csrfToken)
    if (token) call = call.set('Authorization', 'Bearer ' + token)
    return call.send(body)
  }
  async function socketFor(token) {
    const socket = connect('http://127.0.0.1:' + server.address().port, {
      auth: { token },
      transports: ['websocket'],
      reconnection: false,
    })
    clients.push(socket)
    await new Promise((resolve, reject) => {
      socket.once('connect', resolve)
      socket.once('connect_error', reject)
    })
    socket.emit('join_room', { role: 'admin' })
    await new Promise((resolve) => socket.once('connected', resolve))
    return socket
  }
  test('real login, cookie rotation and logout reject copied credentials', async () => {
    const agent = request.agent(app)
    const logged = await mutate(agent, 'login', credentials)
    expect(logged.status).toBe(200)
    expect(logged.body.data.refreshToken).toBeUndefined()
    const old = decodeURIComponent(logged.headers['set-cookie'][0].split(';')[0].split('=').slice(1).join('='))
    const refreshed = await mutate(agent, 'refresh-token')
    expect(refreshed.status).toBe(200)
    expect(jwt.decode(logged.body.data.token).sid).toBe(jwt.decode(refreshed.body.data.token).sid)
    const logout = await mutate(agent, 'logout')
    expect(logout.status).toBe(200)
    await expect(auth.authorize(logged.body.data.token)).rejects.toMatchObject({ statusCode: 401 })
    await expect(auth.rotate(old)).rejects.toMatchObject({ statusCode: 401 })
    expect((await mutate(agent, 'logout')).status).toBe(200)
  })
  test('MongoDB CAS permits one generation advance under simultaneous refresh and revokes on reuse', async () => {
    const session = await auth.issue(user)
    const results = await Promise.allSettled([auth.rotate(session.refreshToken), auth.rotate(session.refreshToken)])
    expect(results.filter((result) => result.status === 'fulfilled').length).toBeLessThanOrEqual(1)
    const stored = await Session.findById(jwt.decode(session.token).sid)
    expect(stored.generation).toBe(1)
    expect(stored.revokedAt).toBeTruthy()
    for (const result of results)
      if (result.status === 'fulfilled')
        await expect(auth.authorize(result.value.token)).rejects.toMatchObject({ statusCode: 401 })
  })
  test('sequential replay revokes newest token while independent family survives', async () => {
    const first = await auth.issue(user)
    const independent = await auth.issue(user)
    const rotated = await auth.rotate(first.refreshToken)
    expect(jwt.decode(rotated.refreshToken).exp).toBe(jwt.decode(first.refreshToken).exp)
    await expect(auth.rotate(first.refreshToken)).rejects.toMatchObject({ statusCode: 401 })
    await expect(auth.authorize(rotated.token)).rejects.toMatchObject({ statusCode: 401 })
    await expect(auth.authorize(independent.token)).resolves.toHaveProperty('user.role', 'admin')
  })
  test('password change increments version, preserves bcrypt and invalidates tokens independent of timestamps', async () => {
    const agent = request.agent(app)
    const logged = await mutate(agent, 'login', credentials)
    const token = logged.body.data.token
    const previous = await auth.issue(user)
    const result = await mutate(
      agent,
      'update-password',
      { currentPassword: credentials.password, newPassword: 'Changed-Regression-123' },
      token,
      'put'
    )
    expect(result.status).toBe(200)
    await expect(auth.authorize(token)).rejects.toMatchObject({ statusCode: 401 })
    await expect(auth.rotate(previous.refreshToken)).rejects.toMatchObject({ statusCode: 401 })
    const updated = await User.findById(user._id).select('+password')
    expect(updated.authVersion).toBe(1)
    expect(await updated.comparePassword('Changed-Regression-123')).toBe(true)
    expect(updated.password.startsWith('$2')).toBe(true)
    await expect(auth.authorize(result.body.data.token)).resolves.toHaveProperty('user')
  })
  test('logout-all and role/status changes reject every family and cannot be undone by reactivation', async () => {
    const first = await auth.issue(user)
    const second = await auth.issue(user)
    await auth.logoutAll(user)
    await expect(auth.authorize(first.token)).rejects.toMatchObject({ statusCode: 401 })
    await expect(auth.rotate(second.refreshToken)).rejects.toMatchObject({ statusCode: 401 })
    const current = await User.findById(user._id)
    const latest = await auth.issue(current)
    const result = await request(app)
      .put('/api/users/' + user._id)
      .set('Authorization', 'Bearer ' + (await otherAdminToken()))
      .send({ status: 'inactive' })
    expect(result.status).toBe(200)
    await User.findByIdAndUpdate(user._id, { $set: { status: 'active' } }) // Test-only reactivation fixture.
    await expect(auth.authorize(latest.token)).rejects.toMatchObject({ statusCode: 401 })
  })
  test('logout disconnects an already connected production-authenticated socket', async () => {
    const issued = await auth.issue(user)
    const socket = await socketFor(issued.token)
    const disconnected = new Promise((resolve) => socket.once('disconnect', resolve))
    await auth.logout(issued.refreshToken)
    await disconnected
    expect(socket.connected).toBe(false)
  })
  test('socket expires at JWT expiry even if the connection is healthy', async () => {
    const issued = await auth.issue(user)
    const claims = jwt.decode(issued.token)
    claims.exp = Math.floor(Date.now() / 1000) + 2
    const short = jwt.sign(claims, process.env.JWT_SECRET, { algorithm: 'HS256' })
    const socket = await socketFor(short)
    await new Promise((resolve) => socket.once('disconnect', resolve))
    expect(socket.connected).toBe(false)
  })
  test('post-join revalidation closes a handshake/revocation race', async () => {
    const issued = await auth.issue(user)
    const original = auth.authorize
    let calls = 0
    const spy = jest.spyOn(auth, 'authorize').mockImplementation(async (token) => {
      const state = await original(token)
      if (++calls === 1) await auth.revokeSession(state.claims.sid, 'race-fixture')
      return state
    })
    try {
      const socket = connect('http://127.0.0.1:' + server.address().port, {
        auth: { token: issued.token },
        transports: ['websocket'],
        reconnection: false,
      })
      clients.push(socket)
      await new Promise((resolve) => {
        socket.once('disconnect', resolve)
        socket.once('connect_error', resolve)
      })
      expect(socket.connected).toBe(false)
    } finally {
      spy.mockRestore()
    }
  })
  test('revocation racing with refresh leaves no valid successor', async () => {
    const issued = await auth.issue(user)
    const [refresh] = await Promise.allSettled([auth.rotate(issued.refreshToken), auth.logout(issued.refreshToken)])
    if (refresh.status === 'fulfilled')
      await expect(auth.authorize(refresh.value.token)).rejects.toMatchObject({ statusCode: 401 })
    expect((await Session.findById(jwt.decode(issued.token).sid)).revokedAt).toBeTruthy()
  })
  test('account role downgrade disconnects sockets and enforces database role on new sessions', async () => {
    const issued = await auth.issue(user)
    const socket = await socketFor(issued.token)
    const disconnected = new Promise((resolve) => socket.once('disconnect', resolve))
    const changed = await request(app)
      .put('/api/users/' + user._id)
      .set('Authorization', 'Bearer ' + (await otherAdminToken()))
      .send({ role: 'viewer' })
    expect(changed.status).toBe(200)
    await disconnected
    await expect(auth.authorize(issued.token)).rejects.toMatchObject({ statusCode: 401 })
    const current = await User.findById(user._id)
    const replacement = await auth.issue(current)
    expect((await auth.authorize(replacement.token)).user.role).toBe('viewer')
    expect(
      (
        await request(app)
          .get('/api/users/stats')
          .set('Authorization', 'Bearer ' + replacement.token)
      ).status
    ).toBe(403)
  })
})
