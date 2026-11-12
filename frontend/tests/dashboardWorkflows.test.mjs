import test from 'node:test'
import assert from 'node:assert/strict'
import { filenameFromDisposition, blobErrorMessage, saveBlob } from '../src/utils/download.js'
import {
  profileSourceLabel, closedDecisionSummary, learningCountsSummary, shadowSummary, deceptionSignature, requestErrorMessage,
} from '../src/utils/deceptionStatus.js'
import { validateUserEdit, changedUserFields, isLastActiveAdmin, userEditErrorMessage } from '../src/utils/userEdit.js'

// ── Export Report download helpers ──
test('report file name comes from Content-Disposition, falls back, and is sanitised', () => {
  assert.equal(filenameFromDisposition('attachment; filename="sentinelai-security-report-7d.pdf"', 'x.pdf'), 'sentinelai-security-report-7d.pdf')
  assert.equal(filenameFromDisposition("attachment; filename*=UTF-8''r%C3%A9port.csv", 'x.csv'), 'réport.csv')
  assert.equal(filenameFromDisposition(undefined, 'fallback.pdf'), 'fallback.pdf')
  assert.equal(filenameFromDisposition('attachment; filename="../../etc/passwd"', 'f.pdf'), '.._.._etc_passwd')
  assert.equal(filenameFromDisposition("attachment; filename*=UTF-8''%E0%A4%A", 'f.pdf'), 'f.pdf')
})

test('blob error messages read the JSON error from a Blob body and cover network/auth failures', async () => {
  const blob = new Blob([JSON.stringify({ success: false, error: 'days must be one of 1, 7, 30, 90' })], { type: 'application/json' })
  assert.equal(await blobErrorMessage({ response: { status: 400, data: blob } }), 'days must be one of 1, 7, 30, 90')
  assert.match(await blobErrorMessage({ response: { status: 500, data: new Blob(['<html>']) } }, 'Report export failed'), /HTTP 500/)
  assert.match(await blobErrorMessage({ code: 'ERR_NETWORK' }), /could not be reached/)
  assert.match(await blobErrorMessage({ code: 'ECONNABORTED' }), /timed out/)
  assert.match(await blobErrorMessage({ response: { status: 401 } }), /expired/)
  assert.match(await blobErrorMessage({ response: { status: 403 } }), /permission/)
})

test('saveBlob clicks a temporary download link and revokes the object URL', async () => {
  const clicked = []
  const revoked = []
  const anchor = { style: {}, click() { clicked.push(this.download) }, remove() {} }
  const doc = { createElement: () => anchor, body: { appendChild: () => {} } }
  const urlApi = { createObjectURL: () => 'blob:1', revokeObjectURL: (u) => revoked.push(u) }
  saveBlob(new Blob(['%PDF-1.4']), 'report.pdf', doc, urlApi)
  assert.deepEqual(clicked, ['report.pdf'])
  assert.equal(anchor.href, 'blob:1')
  await new Promise((r) => setTimeout(r, 1100))
  assert.deepEqual(revoked, ['blob:1'])
})

// ── Adaptive Deception panel ──
test('serving persona source is described as recorded, never as a probe', () => {
  assert.match(profileSourceLabel('setting'), /recorded deception setting/)
  assert.match(profileSourceLabel('default'), /built-in default/)
  assert.match(profileSourceLabel('weird'), /weird/)
})

test('closed decision summary distinguishes applied, failed and expired decisions', () => {
  assert.match(closedDecisionSummary(null), /No earlier decision/)
  const base = { decisionId: 'abcdef0123456789', state: 'centos_7', action: 'ubuntu_22' }
  assert.match(closedDecisionSummary({ ...base, status: 'APPLIED' }), /APPLIED.*centos_7 → ubuntu_22/)
  assert.match(closedDecisionSummary({ ...base, status: 'FAILED', failureReason: 'restart failed' }), /FAILED.*restart failed/)
  assert.match(closedDecisionSummary({ ...base, status: 'SUPERSEDED' }), /EXPIRED or superseded/)
  assert.match(closedDecisionSummary({ ...base, action: 'centos_7', status: 'APPLIED' }), /keep centos_7/)
})

test('learning and shadow summaries report real versus synthetic and shadow-only evidence', () => {
  assert.match(learningCountsSummary({ scoredRealSessions: 1, syntheticSessionsSkipped: 3, sessionsAwaitingScoring: 0 }),
    /1 real session scored; 3 synthetic demo sessions skipped; 0 awaiting/)
  assert.match(learningCountsSummary(null), /unavailable/)
  assert.match(shadowSummary({ sessionsWithEvidence: 0 }), /no evidence/)
  assert.match(shadowSummary({ sessionsWithEvidence: 4, agreementsWithActivePolicy: 3, latest: { recommendation: 'debian_11', version: 'persona-ducb-v2' } }),
    /never applied.*debian_11 \(persona-ducb-v2\).*3 of 4/)
})

test('deception signature changes only when displayed state changes', () => {
  const p = { profile: 'centos_7', source: 'setting' }
  const r = { decisionId: 'd1', nextProfile: 'ubuntu_22', policy: 'q_learning', provenance: { sessionEpisodes: 5 } }
  const st = { lastClosedDecision: { decisionId: 'd0', status: 'APPLIED' }, learning: { scoredRealSessions: 5 }, shadow: { sessionsWithEvidence: 2 } }
  assert.equal(deceptionSignature(p, r, st), deceptionSignature({ ...p }, { ...r }, JSON.parse(JSON.stringify(st))))
  assert.notEqual(deceptionSignature(p, r, st), deceptionSignature(p, { ...r, decisionId: 'd2' }, st))
  assert.notEqual(deceptionSignature(p, r, st), deceptionSignature(p, r, { ...st, learning: { scoredRealSessions: 6 } }))
})

test('request errors are readable', () => {
  assert.match(requestErrorMessage({}, 'X'), /could not be reached/)
  assert.equal(requestErrorMessage({ response: { status: 503 } }, 'Recommendation unavailable'), 'Recommendation unavailable: AI engine unreachable.')
  assert.match(requestErrorMessage({ response: { status: 403 } }, 'X'), /role cannot/)
  assert.match(requestErrorMessage({ response: { status: 500, data: { error: 'boom' } } }, 'X'), /X: boom/)
})

// ── Edit User ──
test('edit form validation mirrors the server rules', () => {
  assert.deepEqual(validateUserEdit({ name: 'Ana Lyst', department: 'SOC', role: 'analyst', status: 'active' }), {})
  const e = validateUserEdit({ name: ' a ', department: '', role: 'root', status: 'gone' })
  assert.deepEqual(Object.keys(e).sort(), ['department', 'name', 'role', 'status'])
  assert.ok(validateUserEdit({ name: 'x'.repeat(51), department: 'SOC', role: 'viewer', status: 'active' }).name)
})

test('only changed, trimmed fields are sent; email and credentials never are', () => {
  const user = { name: 'Ana', department: 'SOC', role: 'viewer', status: 'active', email: 'a@x.test' }
  assert.deepEqual(changedUserFields(user, { ...user }), {})
  assert.deepEqual(changedUserFields(user, { ...user, name: ' Ana B ', role: 'analyst', email: 'evil@x.test', password: 'p' }),
    { name: 'Ana B', role: 'analyst' })
})

test('last active administrator detection', () => {
  const admin = { _id: '1', role: 'admin', status: 'active' }
  assert.equal(isLastActiveAdmin(admin, [admin, { role: 'admin', status: 'inactive' }]), true)
  assert.equal(isLastActiveAdmin(admin, [admin, { _id: '2', role: 'admin', status: 'active' }]), false)
  assert.equal(isLastActiveAdmin({ role: 'viewer', status: 'active' }, [admin]), false)
})

test('edit error messages cover auth, permission, stale and missing users', () => {
  assert.match(userEditErrorMessage({}), /not saved/)
  assert.match(userEditErrorMessage({ response: { status: 401 } }), /expired/)
  assert.match(userEditErrorMessage({ response: { status: 403 } }), /administrators/)
  assert.match(userEditErrorMessage({ response: { status: 404 } }), /no longer exists/)
  assert.match(userEditErrorMessage({ response: { status: 409, data: {} } }), /changed by someone else/)
  assert.equal(userEditErrorMessage({ response: { status: 400, data: { error: 'Administrators cannot demote their own account' } } }),
    'Administrators cannot demote their own account')
})
