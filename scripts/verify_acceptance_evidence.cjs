// Scan only this run's new textual evidence. Never print decrypted credentials.
const fs = require('node:fs')
const path = require('node:path')
const { spawnSync } = require('node:child_process')
const storage = 'C:\\Users\\srisn\\Desktop\\Projects\\sentinelai-complete.native-integration\\mongodb-acceptance-20261014'
const decrypted = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
  'Add-Type -AssemblyName System.Security; $blob=[Convert]::FromBase64String([Console]::In.ReadToEnd()); $bytes=[Security.Cryptography.ProtectedData]::Unprotect($blob,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write([Text.Encoding]::UTF8.GetString($bytes))'],
  { input: fs.readFileSync(path.join(storage, 'acceptance-credentials.dpapi'), 'utf8'), encoding: 'utf8', windowsHide: true })
if (decrypted.status !== 0) throw new Error('Could not inspect encrypted acceptance credentials')
const credentials = Object.values(JSON.parse(decrypted.stdout))
const leaks = []
let filesChecked = 0
function scan(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name)
    if (entry.isDirectory()) scan(file)
    else if (/\.(log|json|txt)$/.test(entry.name)) {
      filesChecked++
      const text = fs.readFileSync(file, 'utf8')
      if (credentials.some(secret => text.includes(secret))) leaks.push(path.relative(storage, file))
    }
  }
}
scan(path.join(storage, 'logs'))
scan(path.join(storage, 'evidence'))
const report = { filesChecked, credentialLeaks: leaks, credentialStorage: 'Windows DPAPI CurrentUser' }
fs.writeFileSync(path.join(storage, 'evidence/credential-scan.json'), JSON.stringify(report, null, 2))
console.log(JSON.stringify(report))
if (leaks.length) process.exitCode = 1
