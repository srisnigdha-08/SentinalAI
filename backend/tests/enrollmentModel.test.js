const bcrypt = require('bcryptjs')
const User = require('../models/User')

afterEach(() => jest.restoreAllMocks())
test('new accounts default to viewer; real save middleware hashes with existing bcrypt cost', async () => {
  const insert = jest.spyOn(User.collection, 'insertOne').mockResolvedValue({ acknowledged: true })
  const password = 'OnlyForUnitRegression123'
  const user = new User({ name: 'Model Regression', email: 'model@example.invalid', password })
  expect(user.role).toBe('viewer')
  await user.save()
  expect(insert).toHaveBeenCalledTimes(1)
  expect(user.password).not.toBe(password)
  expect(bcrypt.getRounds(user.password)).toBe(12)
  expect(await user.comparePassword(password)).toBe(true)
  expect(user.toJSON()).not.toHaveProperty('password')
})
