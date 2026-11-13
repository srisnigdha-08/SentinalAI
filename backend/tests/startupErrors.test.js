'use strict'
const { describeListenError, describeStartupFailure, listenUrl } = require('../utils/startupErrors')

describe('backend startup messages', () => {
  test('a taken port names the port and how to find its owner', () => {
    const msg = describeListenError({ code: 'EADDRINUSE' }, '172.29.32.1', 5000)
    expect(msg).toMatch(/172\.29\.32\.1:5000.*already in use/)
    expect(msg).toMatch(/Get-NetTCPConnection -LocalPort 5000/)
  })

  test('an address that is not on this machine explains HOST and the WSL gateway', () => {
    const msg = describeListenError({ code: 'EADDRNOTAVAIL' }, '10.255.255.1', 5000)
    expect(msg).toMatch(/no such address/)
    expect(msg).toMatch(/HOST=10\.255\.255\.1/)
    expect(msg).toMatch(/WSL gateway/)
  })

  test('other errors keep their code', () => {
    expect(describeListenError({ code: 'EACCES' }, '127.0.0.1', 80)).toMatch(/permission denied/)
    expect(describeListenError({ code: 'EWHATEVER' }, '127.0.0.1', 1)).toMatch(/EWHATEVER/)
    expect(describeListenError(null, '127.0.0.1', 1)).toMatch(/unknown error/)
  })

  test('a failure after the database connects is described, never silent', () => {
    expect(describeStartupFailure(new Error('revocation store unavailable'))).toBe(
      'Backend failed to start: revocation store unavailable. The process exits with code 1.'
    )
    expect(describeStartupFailure('boom')).toMatch(/boom/)
  })

  test('the ready line shows the one address that answers', () => {
    expect(listenUrl('172.29.32.1', 5000)).toBe('http://172.29.32.1:5000')
    expect(listenUrl('::1', 5000)).toBe('http://[::1]:5000')
  })
})
