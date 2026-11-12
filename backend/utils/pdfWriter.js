'use strict'
/**
 * Minimal, dependency-free PDF 1.4 writer for text reports (Dashboard "Export Report").
 * Uses only the standard Type1 fonts (Helvetica, Helvetica-Bold, Courier), so nothing is embedded and no
 * third-party package is pulled into the backend. Text outside Latin-1 is replaced with '?'.
 */

const PAGE_W = 595.28 // A4 portrait, points
const PAGE_H = 841.89
const MARGIN = 48
const FONTS = { regular: 'F1', bold: 'F2', mono: 'F3' }

// Latin-1 only (WinAnsi covers it for the characters reports use); escape PDF string delimiters.
function pdfText(value) {
  return String(value ?? '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/[^\x20-\x7e\xa0-\xff]/g, '?')
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)')
}

// Approximate width for wrapping: Helvetica averages ~0.5em, Courier is exactly 0.6em.
const charWidth = (font, size) => (font === 'mono' ? 0.6 : 0.52) * size

class PdfDocument {
  constructor({ title = 'Report' } = {}) {
    this.title = title
    this.pages = []
    this.newPage()
  }

  newPage() {
    this.current = { ops: [] }
    this.pages.push(this.current)
    this.y = PAGE_H - MARGIN
  }

  ensure(height) {
    if (this.y - height < MARGIN + 20) this.newPage()
  }

  /** Writes one line (wrapped to the page width) and advances the cursor. */
  text(value, { font = 'regular', size = 10, color = [0.1, 0.1, 0.12], indent = 0, gap = 4 } = {}) {
    const maxChars = Math.max(10, Math.floor((PAGE_W - 2 * MARGIN - indent) / charWidth(font, size)))
    const words = String(value ?? '').split(/\s+/)
    const lines = []
    let line = ''
    for (const word of words) {
      const candidate = line ? `${line} ${word}` : word
      if (candidate.length > maxChars && line) {
        lines.push(line)
        line = word
      } else line = candidate
    }
    lines.push(line)
    for (const l of lines) {
      this.ensure(size + gap)
      this.y -= size
      this.current.ops.push(
        `${color.map((c) => c.toFixed(3)).join(' ')} rg BT /${FONTS[font]} ${size} Tf ` +
          `${(MARGIN + indent).toFixed(2)} ${this.y.toFixed(2)} Td (${pdfText(l)}) Tj ET`
      )
      this.y -= gap
    }
  }

  heading(value) {
    this.ensure(40)
    this.y -= 8
    this.text(value, { font: 'bold', size: 13, color: [0.0, 0.35, 0.55], gap: 3 })
    this.rule()
  }

  rule() {
    this.current.ops.push(
      `0.75 0.8 0.85 RG 0.6 w ${MARGIN} ${this.y.toFixed(2)} m ${(PAGE_W - MARGIN).toFixed(2)} ${this.y.toFixed(2)} l S`
    )
    this.y -= 8
  }

  space(points = 6) {
    this.y -= points
  }

  /** Fixed-width table: columns are padded/truncated to their widths (in characters). */
  table(columns, rows, { size = 8.5 } = {}) {
    const fmt = (cells) =>
      cells
        .map((cell, i) => {
          const w = columns[i].width
          const s = String(cell ?? '')
          return s.length > w ? `${s.slice(0, w - 1)}~` : s.padEnd(w)
        })
        .join('  ')
    this.text(fmt(columns.map((c) => c.label)), { font: 'mono', size, color: [0.0, 0.35, 0.55], gap: 2 })
    this.text(fmt(columns.map((c) => '-'.repeat(c.width))), { font: 'mono', size, color: [0.6, 0.65, 0.7], gap: 2 })
    if (!rows.length) this.text('(no records in this period)', { font: 'mono', size, color: [0.45, 0.45, 0.5] })
    for (const row of rows) this.text(fmt(row), { font: 'mono', size, gap: 2.5 })
  }

  /** Serialises the document. Returns a Buffer (Latin-1 bytes). */
  toBuffer({ footer } = {}) {
    const total = this.pages.length
    this.pages.forEach((page, i) => {
      const label = `${footer ? `${footer}  |  ` : ''}Page ${i + 1} of ${total}`
      page.ops.push(`0.45 0.45 0.5 rg BT /F1 7.5 Tf ${MARGIN} ${(MARGIN - 18).toFixed(2)} Td (${pdfText(label)}) Tj ET`)
    })

    const objects = [] // index i holds object number i+1
    const add = (body) => {
      objects.push(body)
      return objects.length
    }
    const catalog = add(null)
    const pagesObj = add(null)
    const fontObjs = {
      F1: add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'),
      F2: add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>'),
      F3: add('<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>'),
    }
    const fontDict = Object.entries(fontObjs)
      .map(([k, n]) => `/${k} ${n} 0 R`)
      .join(' ')
    const pageNums = this.pages.map((page) => {
      const stream = page.ops.join('\n')
      const content = add(`<< /Length ${Buffer.byteLength(stream, 'latin1')} >>\nstream\n${stream}\nendstream`)
      return add(
        `<< /Type /Page /Parent ${pagesObj} 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] ` +
          `/Resources << /Font << ${fontDict} >> >> /Contents ${content} 0 R >>`
      )
    })
    objects[catalog - 1] = `<< /Type /Catalog /Pages ${pagesObj} 0 R >>`
    objects[pagesObj - 1] = `<< /Type /Pages /Kids [${pageNums.map((n) => `${n} 0 R`).join(' ')}] /Count ${total} >>`
    const info = add(`<< /Title (${pdfText(this.title)}) /Producer (SentinelAI) >>`)

    let out = '%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'
    const offsets = []
    objects.forEach((body, i) => {
      offsets.push(Buffer.byteLength(out, 'latin1'))
      out += `${i + 1} 0 obj\n${body}\nendobj\n`
    })
    const xref = Buffer.byteLength(out, 'latin1')
    out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`
    out += offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')
    out += `trailer\n<< /Size ${objects.length + 1} /Root ${catalog} 0 R /Info ${info} 0 R >>\nstartxref\n${xref}\n%%EOF\n`
    return Buffer.from(out, 'latin1')
  }
}

module.exports = { PdfDocument, pdfText }
