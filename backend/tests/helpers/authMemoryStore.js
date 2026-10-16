// In-memory fixtures for authentication unit tests; no database connections.
function clone(value) {
  if (value instanceof Date) return value.toISOString()
  if (Array.isArray(value)) return value.map(clone)
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, item]) => typeof item !== 'function')
        .map(([key, item]) => [key, clone(item)])
    )
  return value
}
function query(value) {
  return {
    select() {
      return this
    },
    then(resolve, reject) {
      return Promise.resolve(value).then(resolve, reject)
    },
  }
}
function install(User, Session) {
  const users = new Map()
  const sessions = new Map()
  function userDocument(data) {
    if (!data) return null
    const value = clone(data)
    value.toJSON = () => {
      const result = clone(value)
      delete result.password
      return result
    }
    value.comparePassword = async (password) => password === 'CorrectPassword123'
    value.save = async () => {
      users.set(value._id, clone(value))
      return value
    }
    return value
  }
  function sessionDocument(data) {
    if (!data) return null
    const value = clone(data)
    value.toObject = () => clone(value)
    return value
  }
  function matches(value, filter) {
    return Object.entries(filter).every(([key, expected]) => {
      if (key === '$expr') return (value.authVersion ?? 0) === expected.$eq[1]
      if (expected && typeof expected === 'object') {
        if ('$gt' in expected && !(new Date(value[key]) > expected.$gt)) return false
        if ('$lt' in expected && !(new Date(value[key]) < expected.$lt)) return false
        return true
      }
      if (expected === null) return value[key] == null
      return String(value[key]) === String(expected)
    })
  }
  function update(value, changes) {
    Object.assign(value, clone(changes.$set || {}))
    for (const [key, delta] of Object.entries(changes.$inc || {})) value[key] = (value[key] || 0) + delta
  }
  User.findById.mockImplementation((id) => query(userDocument(users.get(String(id)))))
  User.findOne.mockImplementation((filter) =>
    query(userDocument([...users.values()].find((user) => matches(user, filter))))
  )
  User.create.mockImplementation(async (data) => {
    const value = { _id: '123456789012345678901234', status: 'active', authVersion: 0, ...data }
    users.set(value._id, clone(value))
    return userDocument(value)
  })
  User.findOneAndUpdate.mockImplementation((filter, changes) => {
    const value = [...users.values()].find((user) => matches(user, filter))
    if (value) update(value, changes)
    return query(userDocument(value))
  })
  User.findByIdAndUpdate.mockImplementation((id, changes) => {
    const value = users.get(String(id))
    if (value) update(value, changes)
    return query(userDocument(value))
  })
  Session.create.mockImplementation(async (data) => {
    sessions.set(data._id, clone(data))
    return sessionDocument(data)
  })
  Session.findById.mockImplementation((id) => query(sessionDocument(sessions.get(id))))
  Session.findOneAndUpdate.mockImplementation(async (filter, changes) => {
    const value = [...sessions.values()].find((session) => matches(session, filter))
    if (!value) return null
    update(value, changes)
    return sessionDocument(value)
  })
  Session.updateOne.mockImplementation(async (filter, changes) => {
    const value = [...sessions.values()].find((session) => matches(session, filter))
    if (value) update(value, changes)
    return { modifiedCount: value ? 1 : 0 }
  })
  Session.updateMany.mockImplementation(async (filter, changes) => {
    for (const value of sessions.values()) if (matches(value, filter)) update(value, changes)
  })
  const data = {
    _id: '123456789012345678901234',
    name: 'Unit User',
    email: 'unit@example.invalid',
    password: 'unit-only-hash',
    role: 'analyst',
    status: 'active',
    authVersion: 0,
  }
  users.set(data._id, data)
  return { users, sessions, user: userDocument(data), query }
}
module.exports = { install, query }
