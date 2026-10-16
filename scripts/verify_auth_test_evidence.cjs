// Read only the approved regression instance's logs/evidence; never opens database files or browser profiles.
const fs = require('node:fs')
const path = require('node:path')
const net = require('node:net')
const { spawnSync } = require('node:child_process')
const root = path.resolve(__dirname, '..')
const storage = path.join(root, '.test-runtime/auth-timezone-db-20261014-01')
const owned = JSON.parse(fs.readFileSync(path.join(storage, 'ownership.json'), 'utf8'))
if (owned.storage !== storage || owned.port !== 27029 || owned.database !== 'sentinelai_auth_timezone_test_20261014') throw new Error('Ownership mismatch')
for (const folder of [storage, path.join(storage, 'logs'), path.join(storage, 'evidence')]) {
  if (fs.lstatSync(folder).isSymbolicLink() || fs.realpathSync(folder).toLowerCase() !== folder.toLowerCase()) throw new Error('Redirected path rejected')
}
const decrypted = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'Add-Type -AssemblyName System.Security; $blob=[Convert]::FromBase64String([Console]::In.ReadToEnd()); [Console]::Out.Write([Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($blob,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)))'], {
  input: fs.readFileSync(path.join(storage, 'credentials.dpapi'), 'utf8'), encoding: 'utf8', windowsHide: true,
})
if (decrypted.status !== 0) throw new Error('Test credential verification unavailable')
const secrets = Object.values(JSON.parse(decrypted.stdout))
const files = []
function collect(folder) {
  for (const entry of fs.readdirSync(folder, { withFileTypes: true })) {
    if (entry.name.toLowerCase() === 'cache.db' || entry.isSymbolicLink()) continue
    const file = path.join(folder, entry.name)
    if (entry.isDirectory()) collect(file)
    else if (entry.isFile() && /\.(json|log|txt)$/.test(entry.name)) files.push(file)
  }
}
for (const folder of ['logs', 'evidence']) {
  collect(path.join(storage, folder))
}
const leaks = files.filter(file => {
  const text = fs.readFileSync(file, 'utf8')
  return secrets.some(secret => text.includes(secret)) || /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{30,}/.test(text)
}).map(file => path.relative(root, file))
const probe = net.createServer()
probe.once('error', () => { throw new Error('Approved regression port is still occupied; no process was stopped') })
probe.listen(27029, '127.0.0.1', () => probe.close(() => {
  const result = { scannedFiles: files.length, credentialOrBearerLeakFiles: leaks, port27029Closed: true }
  fs.writeFileSync(path.join(root, '.test-runtime/hardening-evidence-verification.json'), JSON.stringify(result, null, 2) + '\n')
  console.log(JSON.stringify(result))
  if (leaks.length) process.exitCode = 1
}))
