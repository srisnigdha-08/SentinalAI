// Read only this approved new environment's logs/evidence; never traverse data, profiles or cache.db.
const fs = require('node:fs')
const path = require('node:path')
const { spawnSync } = require('node:child_process')
const root = path.resolve(__dirname, '..')
const storage = path.join(root, '.test-runtime/native-readiness-20261014-01')
const owner = JSON.parse(fs.readFileSync(path.join(storage, 'ownership.json')))
if (owner.storage !== storage || owner.database !== 'sentinelai_native_readiness_20261014') throw new Error('Ownership mismatch')
const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'Add-Type -AssemblyName System.Security; $bytes=[Convert]::FromBase64String([Console]::In.ReadToEnd()); [Console]::Out.Write([Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)))'], { input: fs.readFileSync(path.join(storage, 'credentials.dpapi'), 'utf8'), encoding: 'utf8', windowsHide: true })
if (result.status !== 0) throw new Error('New credential scan unavailable')
const credentials = JSON.parse(result.stdout)
const values = ['admin', 'application', 'userPassword', 'JWT_SECRET', 'JWT_REFRESH_SECRET', 'SENTINEL_KEY', 'HONEYPOT_API_KEY', 'replicaKey', 'key'].map(name => credentials[name])
const files = [], findings = []
function walk(directory) {
  if (fs.lstatSync(directory).isSymbolicLink() || fs.realpathSync(directory).toLowerCase() !== path.resolve(directory).toLowerCase()) throw new Error('Redirected evidence path')
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.name.toLowerCase() === 'cache.db' || entry.isSymbolicLink()) continue
    const file = path.join(directory, entry.name)
    if (entry.isDirectory()) { walk(file); continue }
    if (!/\.(json|log|xml|txt)$/i.test(entry.name)) continue
    const text = fs.readFileSync(file, 'utf8')
    files.push(path.relative(root, file))
    const leakedCredential = values.some(value => value && text.includes(value))
    const leakedJWT = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(text)
    const leakedKey = /-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/.test(text)
    if (leakedCredential || leakedJWT || leakedKey) findings.push({ path: path.relative(root, file), credential: leakedCredential, jwt: leakedJWT, privateKey: leakedKey })
  }
}
for (const name of ['logs', 'evidence']) walk(path.join(storage, name))
walk(path.join(root, '.test-runtime/master-native-20261014-80f776da'))
const output = path.join(root, '.test-runtime/master-native-20261014-80f776da/privacy-scan-' + Date.now() + '.json')
fs.writeFileSync(output, JSON.stringify({ scope: 'New owned logs/evidence only; no data, profiles or protected recovery resources', filesChecked: files.length, files, findings, passed: findings.length === 0 }, null, 2), { flag: 'wx' })
console.log(JSON.stringify({ filesChecked: files.length, leaksFound: findings.length, evidence: output }))
process.exitCode = findings.length ? 1 : 0
