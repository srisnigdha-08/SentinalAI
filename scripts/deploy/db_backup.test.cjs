'use strict'
// Safety rules of the backup tool, without Docker or age. Run: node --test scripts/deploy/db_backup.test.cjs
const test = require('node:test')
const assert = require('node:assert')
const crypto = require('crypto')
const fs = require('fs')
const os = require('os')
const path = require('path')
const { spawnSync } = require('child_process')
const b = require('./db_backup.cjs')

const TOOL = path.join(__dirname, 'db_backup.cjs')
const tempDir = (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-backup-test-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  return dir
}
const RECIPIENT = 'age1' + 'q'.repeat(58)

test('only an age public key is accepted for encryption', () => {
  assert.equal(b.recipientProblem(RECIPIENT), null)
  assert.ok(b.recipientProblem('AGE-SECRET-KEY-1' + 'Q'.repeat(58)))
  assert.ok(b.recipientProblem('age1short'))
  assert.ok(b.recipientProblem(''))
})

test('the recovery key must not sit with the backups', (t) => {
  const dir = tempDir(t)
  const backups = path.join(dir, 'backups')
  const keys = path.join(dir, 'keys')
  fs.mkdirSync(backups)
  fs.mkdirSync(path.join(backups, 'nested'))
  fs.mkdirSync(keys)
  const file = path.join(backups, 'x.age')
  assert.equal(b.keySeparationProblem(file, path.join(keys, 'key.txt')), null)
  assert.ok(b.keySeparationProblem(file, path.join(backups, 'key.txt')))
  assert.ok(b.keySeparationProblem(file, path.join(backups, 'nested', 'key.txt')))
  assert.equal(b.keySeparationProblem(file, path.join(dir, 'backups-keys', 'key.txt')), null, 'a shared name prefix is not containment')
})

test('backup names are recognised, and retention removes only the oldest of them', () => {
  const name = (n) => `sentinel-backup-2026110${n}T000000Z.archive.gz.age`
  const names = [name(3), 'notes.txt', name(1), name(2), name(4), `${name(1)}.sha256`]
  assert.deepEqual(b.selectExpired(names, 2), [name(1), name(2)])
  assert.deepEqual(b.selectExpired(names, 10), [])
  assert.throws(() => b.selectExpired(names, 0), /keep/)
  assert.match(b.backupName(new Date('2026-11-09T01:02:03.456Z')), /^sentinel-backup-20261109T010203Z\.archive\.gz\.age$/)
})

test('a changed backup fails its checksum before anything is decrypted', async (t) => {
  const dir = tempDir(t)
  const file = path.join(dir, 'sentinel-backup-20261109T000000Z.archive.gz.age')
  fs.writeFileSync(file, crypto.randomBytes(4096))
  await b.writeChecksum(file)
  assert.equal(await b.verifyChecksum(file), true)
  const bytes = fs.readFileSync(file)
  bytes[100] ^= 1
  fs.writeFileSync(file, bytes)
  await assert.rejects(b.verifyChecksum(file), /checksum does not match/)
  fs.rmSync(`${file}.sha256`)
  await assert.rejects(b.verifyChecksum(file), /no checksum/)
})

test('the database commands stay consistent, least-privileged and free of plaintext files', () => {
  assert.match(b.DUMP_COMMAND, /-u sentinel_backup/)
  assert.match(b.DUMP_COMMAND, /--oplog/)
  assert.match(b.DUMP_COMMAND, /--archive/)
  assert.doesNotMatch(b.DUMP_COMMAND, /--archive=|--out/, 'plaintext must only ever travel through the pipe')
  assert.match(b.RESTORE_COMMAND, /--oplogReplay/)
  assert.doesNotMatch(b.RESTORE_COMMAND, /--drop/, 'with authentication on, --drop invalidates the restore login and leaves a partial restore')
  assert.match(b.EMPTY_TARGET_COMMAND, /listDatabases/, 'without --drop, a non-empty target would silently keep old documents')
  assert.match(b.EMPTY_TARGET_COMMAND, /quit\(used\.length \? 3 : 0\)/)
  assert.doesNotMatch(b.RESTORE_COMMAND, /--nsInclude|--nsExclude/, 'mongorestore refuses --oplogReplay with a namespace filter')
})

for (const [label, argv, message] of [
  ['an unknown command', ['bogus'], /Usage/],
  ['a backup with no project', ['backup', '--out', 'x', '--recipient', RECIPIENT], /--project/],
  ['a backup to a secret key', ['backup', '--project', 'p', '--compose-file', 'a', '--compose-env', 'e', '--out', 'x', '--recipient', 'AGE-SECRET-KEY-1' + 'Q'.repeat(58)], /public key/],
  ['a restore without confirmation', ['restore', '--project', 'p', '--compose-file', 'a', '--compose-env', 'e', '--backup', 'x', '--identity', 'k'], /--confirm-restore/],
  ['a restore confirmed for another project', ['restore', '--project', 'p', '--compose-file', 'a', '--compose-env', 'e', '--backup', 'x', '--identity', 'k', '--confirm-restore', 'other'], /--confirm-restore/],
]) {
  test(`refuses ${label}`, () => {
    const r = spawnSync(process.execPath, [TOOL, ...argv], { encoding: 'utf8' })
    assert.equal(r.status, 2)
    assert.match(r.stderr, message)
  })
}
