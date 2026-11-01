#!/usr/bin/env node
'use strict'
/**
 * Dependency-free secret scanner (SEC-001 follow-up). Reports commit, file, line, rule and the value's length —
 * never any part of a value, so its output is safe for public CI logs.
 *
 *   node scripts/security/secret_scan.cjs                 tracked files in the working tree
 *   node scripts/security/secret_scan.cjs --staged        staged changes only (pre-commit hook)
 *   node scripts/security/secret_scan.cjs --range A..B    lines added by the commits in A..B (CI: the pushed commits)
 *   node scripts/security/secret_scan.cjs --history       lines added by every commit reachable from any ref
 *   node scripts/security/secret_scan.cjs --history --write-baseline   record current history findings as accepted
 *
 * Commit scans (--range, --history) look at every added line of every commit, so a secret that a later commit
 * deletes is still reported. Findings listed in scripts/security/secret_scan_baseline.txt (commit + file + rule
 * keys, no values; already-remediated history) are not reported again.
 * Exit 1 when anything is found. Exceptions: a line carrying `secret-scan: allow (<reason>)` (a reason is required),
 * or a path in scripts/security/secret_scan_allow.txt (exact file path, or a directory ending in `/`).
 * Rules: secret-named variables assigned a literal, credentials in URIs, private keys, well-known token formats.
 * Placeholders, environment references and values that are visibly test data are ignored.
 */
const { execFileSync } = require('child_process')
const fs = require('fs')
const path = require('path')

const root = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim()
const git = (...a) => execFileSync('git', ['-C', root, ...a], { encoding: 'utf8', maxBuffer: 256 << 20 })
const here = path.join(root, 'scripts', 'security')

const SECRET_NAME = /(?:api[_-]?key|secret|token|passw(?:or)?d|passwd|pwd|private[_-]?key|access[_-]?key)/i
// Environment-style *_KEY names (SENTINEL_KEY, HMAC_KEY); camelCase fooKey is usually an identifier, not a secret
const ENV_KEY_NAME = /(?:^|[^a-z])[A-Z0-9_]*_KEY$/
const isSecretName = (name) => SECRET_NAME.test(name) || ENV_KEY_NAME.test(name)
// NAME = 'value' | NAME: "value" | NAME=value (env files, PowerShell $env:NAME = "value")
const ASSIGN = /([A-Za-z_$][\w$.:-]*)["']?\s*[:=]\s*(?:["'`]([^"'`\s]{8,256})["'`]|([^\s"'`#;,)]{8,256})\s*(?:#.*)?$)/g
const PLACEHOLDER =
  /^(?:your|\[|\$\{|\$[A-Z_]|<|%|process\.env|os\.environ|getenv|env\.|import\.meta|CHANGE_?ME|REPLACE|YOUR_|your-|xxx|\*{3}|changeme|placeholder|example|redacted|<redacted>|null|undefined|none|true|false)/i
// Test data is recognised by whole words, so "Contest2026!" or "LatestKey" are still findings
const TESTY = /(?:^|[^a-z])(?:test|tests|example|dummy|fake|sample|mock|unit|offline|fixture|integration|e2e|placeholder|redacted)(?:[^a-z]|$)/i
const RULES = [
  { id: 'private-key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----/ },
  { id: 'aws-access-key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: 'github-token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/ },
  { id: 'slack-token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
]
// user:password@ in any URI scheme (mongodb, postgres, redis, amqp, https, ...)
const URI_CRED = /\b[a-z][a-z0-9+.-]*:\/\/([^:/\s"'`@]+):([^@\s"'`/]+)@/gi
// Unquoted values only count where they are plain config (env files, shell, YAML, INI); in code they are
// expressions such as `{"X-API-Key": api_key}`.
const UNQUOTED_OK = /\.(?:env|ps1|sh|bash|cfg|conf|ini|toml|service|ya?ml|example|md)$|(?:^|\/)\.env[^/]*$/i
const TEXT_EXT = /\.(?:js|cjs|mjs|jsx|ts|tsx|py|ps1|sh|bash|json|ya?ml|env|cfg|conf|ini|toml|txt|md|html|example|service)$|(?:^|\/)(?:\.env[^/]*|Dockerfile)$/i
const ALLOW_MARKER = /secret-scan: allow \(\s*\S[^)]*\)/

const listFile = (name) => {
  const f = path.join(here, name)
  if (!fs.existsSync(f)) return []
  return fs.readFileSync(f, 'utf8').split(/\r?\n/).map((l) => l.replace(/#.*/, '').trim()).filter(Boolean)
}
const allowList = listFile('secret_scan_allow.txt')
const allowedFile = (file) => {
  const f = file.replace(/\\/g, '/')
  return allowList.some((p) => (p.endsWith('/') ? f.startsWith(p) : f === p))
}
const describe = (v) => `(${v.length} chars)`

function scanText(file, text) {
  const out = []
  // Backup copies (x.js.bak, server.js.bak-phase6, x.py.orig) are scanned as the type they copy
  const typed = file.replace(/\.(?:bak|orig|old|save|swp)(?:[-.][\w-]+)?$/i, '')
  if (!TEXT_EXT.test(typed) || allowedFile(file)) return out
  const testFile = /(^|\/)(tests?|e2e|__tests__|fixtures?)\//.test(file) || /\.(test|spec)\.[cm]?[jt]sx?$|^test_|\/test_[^/]+\.py$/.test(file)
  text.split(/\r?\n/).forEach((line, i) => {
    if (ALLOW_MARKER.test(line) || line.length > 2000) return
    for (const r of RULES) if (r.re.test(line)) out.push({ file, line: i + 1, rule: r.id, hint: 'pattern match' })
    for (const m of testFile ? [] : line.matchAll(URI_CRED)) {
      const pw = m[2]
      if (!PLACEHOLDER.test(pw) && !pw.startsWith('$') && !TESTY.test(pw)) out.push({ file, line: i + 1, rule: 'uri-password', hint: describe(pw) })
    }
    for (const m of line.matchAll(ASSIGN)) {
      const name = m[1]
      const value = m[2] ?? m[3]
      if (m[3] && (!UNQUOTED_OK.test(file) || /^[./~]|[{}()[\]]/.test(value))) continue
      if (!value || !isSecretName(name) || /[_-](?:file|path|url|uri|name|header|env|len|length|min|max|ttl|expires?(?:_in)?|hash|sha256|cookie|field|type|id)$/i.test(name)) continue
      if (PLACEHOLDER.test(value) || /^[A-Z_]+$/.test(value) || /^\(?[\w.]+\)?$/.test(value) && !/\d/.test(value)) continue // identifiers, env names
      if (/^[\w.]+\(|=>|\$\(|\bnew\b|\.[a-z]+\(/.test(value)) continue // code, not a literal
      if (testFile || TESTY.test(value)) continue
      out.push({ file, line: i + 1, rule: 'secret-assignment', hint: `${name} = ${describe(value)}` })
    }
  })
  return out
}

function scanTree() {
  return git('ls-files', '-z').split('\0').filter(Boolean).flatMap((f) => {
    const p = path.join(root, f)
    let st
    try {
      st = fs.statSync(p)
    } catch {
      return []
    }
    return !st.isFile() || st.size > 2 << 20 ? [] : scanText(f, fs.readFileSync(p, 'utf8'))
  })
}

function scanStaged() {
  return git('diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z').split('\0').filter(Boolean).flatMap((f) => {
    let text
    try {
      text = git('show', ':' + f)
    } catch {
      return []
    }
    return text.length > 2 << 20 ? [] : scanText(f, text)
  })
}

const baselineKey = (h) => `${h.commit} ${h.file} ${h.rule}`

// Every line added by each commit in `revs` (an argument list for git rev-list)
function scanCommits(revs) {
  const baseline = new Set(listFile('secret_scan_baseline.txt'))
  const found = new Map()
  for (const c of git('rev-list', ...revs).split('\n').filter(Boolean)) {
    const diff = git('show', '--format=', '--unified=0', '--no-color', '--no-renames', c)
    let file = null
    let n = 0
    for (const line of diff.split('\n')) {
      if (line.startsWith('+++ ')) file = line.startsWith('+++ b/') ? line.slice(6) : null
      else if (line.startsWith('@@')) n = parseInt((line.match(/\+(\d+)/) || [0, 0])[1], 10) - 1
      else if (line.startsWith('+') && file) {
        n++
        for (const hit of scanText(file, line.slice(1))) {
          const h = { ...hit, line: n, commit: c.slice(0, 7) }
          const key = `${h.commit} ${file}:${n} ${hit.rule}`
          if (!baseline.has(baselineKey(h)) && !found.has(key)) found.set(key, h)
        }
      }
    }
  }
  return [...found.values()]
}

if (require.main === module) {
  const argv = process.argv.slice(2)
  const rangeArg = argv.includes('--range') ? argv[argv.indexOf('--range') + 1] : null
  const mode = argv.includes('--history') ? 'history' : rangeArg ? 'range' : argv.includes('--staged') ? 'staged' : 'tree'
  if (mode === 'range' && !/^[\w./~^-]+\.\.[\w./~^-]+$/.test(rangeArg)) {
    console.error('--range needs <from>..<to>')
    process.exit(2)
  }
  if (argv.includes('--write-baseline')) {
    if (mode !== 'history') {
      console.error('--write-baseline only with --history')
      process.exit(2)
    }
    fs.writeFileSync(path.join(here, 'secret_scan_baseline.txt'), '')
    const keys = [...new Set(scanCommits(['--all']).map(baselineKey))].sort()
    fs.writeFileSync(
      path.join(here, 'secret_scan_baseline.txt'),
      '# Accepted history findings: <commit> <file> <rule>. No values. Listed so CI judges new commits only; the\n' +
        '# secrets behind them must be rotated or proven non-secret (SEC-001: audit/SEC001_REMEDIATION.md).\n' +
        keys.join('\n') + '\n'
    )
    console.log(`baseline written: ${keys.length} key(s)`)
    process.exit(0)
  }
  const hits = mode === 'history' ? scanCommits(['--all']) : mode === 'range' ? scanCommits([rangeArg]) : mode === 'staged' ? scanStaged() : scanTree()
  for (const h of hits) console.log(`${h.commit ? h.commit + ' ' : ''}${h.file}:${h.line}  [${h.rule}]  ${h.hint}`)
  console.log(`secret-scan (${mode}${rangeArg ? ' ' + rangeArg : ''}): ${hits.length} finding(s)`)
  process.exit(hits.length ? 1 : 0)
}

module.exports = { scanText }
