'use strict'

const { databaseName, requireDatabaseConfirmation } = require('../utils/destructiveGuard')

describe('destructive script guard (seed/clean)', () => {
  let exitSpy
  let errSpy
  beforeEach(() => {
    exitSpy = jest.spyOn(process, 'exit').mockImplementation((code) => {
      throw new Error(`exit:${code}`)
    })
    errSpy = jest.spyOn(console, 'error').mockImplementation(() => {})
  })
  afterEach(() => {
    exitSpy.mockRestore()
    errSpy.mockRestore()
  })

  test('parses the database name from a Mongo URI', () => {
    expect(databaseName('mongodb://localhost:27017/sentinel-db')).toBe('sentinel-db')
    expect(databaseName('mongodb://u:p@127.0.0.1:27017/sentinelai_test?authSource=admin')).toBe('sentinelai_test')
    expect(databaseName('mongodb://localhost:27017/')).toBeNull()
  })

  test('blocks when no confirmation is given', () => {
    expect(() =>
      requireDatabaseConfirmation('mongodb://localhost:27017/sentinel-db', 'seed', ['users'], ['node', 'seed.js'])
    ).toThrow('exit:1')
  })

  test('blocks when the confirmation names a different database', () => {
    expect(() =>
      requireDatabaseConfirmation('mongodb://localhost:27017/sentinel-db', 'seed', ['users'], [
        'node',
        'seed.js',
        '--confirm=sentinelai_test',
      ])
    ).toThrow('exit:1')
  })

  test('allows when the confirmation matches the target database', () => {
    expect(
      requireDatabaseConfirmation('mongodb://localhost:27017/sentinel-db', 'seed', ['users'], [
        'node',
        'seed.js',
        '--confirm=sentinel-db',
      ])
    ).toBe('sentinel-db')
    expect(exitSpy).not.toHaveBeenCalled()
  })
})
