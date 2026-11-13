'use strict'
/**
 * Plain-language messages for backend startup failures (server.js). Without them a port clash surfaced only as
 * "[Shutdown] Uncaught exception: listen EADDRINUSE ...", and a failure after the MongoDB connection exited with
 * code 1 and no log line at all.
 */

/** Message for an http.Server 'error' raised by listen(). */
function describeListenError(err, host, port) {
  const where = `${host}:${port}`
  switch (err && err.code) {
    case 'EADDRINUSE':
      return (
        `Cannot listen on ${where}: the port is already in use. Another backend (for example a demo window or a ` +
        `test server) is probably running. Find it with: Get-NetTCPConnection -LocalPort ${port} -State Listen`
      )
    case 'EADDRNOTAVAIL':
      return (
        `Cannot listen on ${where}: this machine has no such address. HOST=${host} must be an address of this ` +
        `machine (the demo uses the WSL gateway address; it changes after a reboot, so start the demo again).`
      )
    case 'EACCES':
      return `Cannot listen on ${where}: permission denied for this port.`
    default:
      return `Cannot listen on ${where}: ${(err && (err.code || err.message)) || 'unknown error'}`
  }
}

/** Message for a failure anywhere in the startup chain before the server listens. */
function describeStartupFailure(err) {
  const detail = (err && (err.message || err.name)) || String(err)
  return `Backend failed to start: ${detail}. The process exits with code 1.`
}

/** "http://host:port", with IPv6 literals bracketed. */
function listenUrl(host, port) {
  const h = String(host).includes(':') ? `[${host}]` : host
  return `http://${h}:${port}`
}

module.exports = { describeListenError, describeStartupFailure, listenUrl }
