// Dedicated approved test proxy. TLS key arrives over parent IPC, never a command argument/file.
const https = require('node:https')
const http = require('node:http')
const net = require('node:net')
const fs = require('node:fs')
const path = require('node:path')
let tlsServer, redirect
function upstreamHeaders(headers) {
  const clean = { ...headers }
  for (const name of Object.keys(clean)) {
    if (name.startsWith('x-forwarded-') || ['forwarded', 'x-test-upstream', 'host'].includes(name)) delete clean[name]
  }
  clean.host = '127.0.0.1'
  clean['x-forwarded-proto'] = 'https'
  return clean
}
process.once('message', ({ key, cert, build }) => {
  tlsServer = https.createServer({ key, cert }, (req, res) => {
    if (req.url.startsWith('/api/') || req.url.startsWith('/socket.io/') || req.url === '/health') {
      const target = http.request({ hostname: '127.0.0.1', localAddress: '127.0.0.2',
        port: req.headers['x-test-upstream'] === 'B' ? 15002 : 15001,
        method: req.method, path: req.url, headers: upstreamHeaders(req.headers) }, reply => {
        res.writeHead(reply.statusCode, reply.headers); reply.pipe(res)
      })
      target.on('error', () => { if (!res.headersSent) res.writeHead(503, { 'Content-Type': 'application/json' }); res.end('{"success":false,"error":"Test upstream unavailable"}') })
      req.pipe(target)
      return
    }
    let file
    try { file = path.resolve(build, '.' + decodeURIComponent(req.url.split('?')[0])) } catch { res.writeHead(400); res.end(); return }
    if (file !== build && !file.startsWith(build + path.sep)) { res.writeHead(403); res.end(); return }
    if (!fs.existsSync(file) || !fs.statSync(file).isFile()) file = path.join(build, 'index.html')
    const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' }
    res.writeHead(200, { 'Content-Type': mime[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' })
    fs.createReadStream(file).pipe(res)
  })
  tlsServer.on('upgrade', (req, client, head) => {
    if (!req.url.startsWith('/socket.io/')) { client.destroy(); return }
    const upstream = net.connect({ host: '127.0.0.1', localAddress: '127.0.0.2', port: req.headers['x-test-upstream'] === 'B' ? 15002 : 15001 }, () => {
      const headers = upstreamHeaders(req.headers)
      upstream.write(req.method + ' ' + req.url + ' HTTP/1.1\r\n' + Object.entries(headers).map(([k, v]) => k + ': ' + v).join('\r\n') + '\r\n\r\n')
      if (head.length) upstream.write(head)
      client.pipe(upstream); upstream.pipe(client)
    })
    upstream.on('error', () => client.destroy()); client.on('error', () => upstream.destroy())
    client.on('close', () => upstream.destroy())
  })
  redirect = http.createServer((_, res) => { res.writeHead(308, { Location: 'https://127.0.0.1:13443/' }); res.end() })
  redirect.listen(13080, '127.0.0.1')
  tlsServer.listen(13443, '127.0.0.1', () => process.send({ ready: true }))
})
process.on('disconnect', () => { tlsServer?.close(); redirect?.close(); process.exit(0) })
