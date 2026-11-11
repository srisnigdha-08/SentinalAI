import { createElement } from 'react'

// Attacker-controlled text (commands, outputs, usernames) rendered strictly as text: React escapes it, and it is
// never passed to an HTML sink, a link, or anything that runs it. Plain JS (no JSX) so tests can render it in Node.
export default function EvidenceText({ text, block = false, maxLength = 4000, testId }) {
  const value = typeof text === 'string' ? text : text === null || text === undefined ? '' : String(text)
  const clipped = value.length > maxLength ? value.slice(0, maxLength) + ' … [truncated for display]' : value
  return createElement(
    block ? 'pre' : 'code',
    {
      'data-testid': testId,
      translate: 'no',
      style: {
        fontFamily: 'Share Tech Mono,monospace',
        fontSize: 12,
        color: '#c8e6f5',
        background: 'rgba(2,11,24,.7)',
        border: '1px solid #0d3352',
        borderRadius: 2,
        padding: block ? '8px 10px' : '1px 6px',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-all',
        margin: 0,
        display: block ? 'block' : 'inline',
        maxHeight: block ? 220 : undefined,
        overflow: block ? 'auto' : undefined,
      },
    },
    clipped
  )
}
