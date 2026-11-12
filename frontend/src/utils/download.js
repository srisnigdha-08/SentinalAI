// Helpers for file downloads fetched through the authenticated API client (Dashboard "Export Report").

const UNSAFE_FILENAME_CHARS = String.raw`\/:*?"<>|`

/** File name from a Content-Disposition header, or the fallback. Path separators and quotes are stripped. */
export function filenameFromDisposition(header, fallback) {
  const value = String(header || '')
  const star = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(value)
  const plain = /filename\s*=\s*"?([^";]+)"?/i.exec(value)
  let name = null
  try {
    name = star ? decodeURIComponent(star[1].trim()) : plain ? plain[1].trim() : null
  } catch {
    name = plain ? plain[1].trim() : null
  }
  const safe = name
    ? Array.from(name, (ch) => (ch.charCodeAt(0) < 32 || UNSAFE_FILENAME_CHARS.includes(ch) ? '_' : ch)).join('').slice(0, 150)
    : ''
  return safe || fallback
}

/** Error text for a failed blob request: the API's JSON { error } when present, else a status-based message. */
export async function blobErrorMessage(error, fallback = 'Request failed') {
  if (!error?.response) {
    return error?.code === 'ECONNABORTED'
      ? 'The request timed out. Try again.'
      : 'The server could not be reached. Check your connection and try again.'
  }
  const { status, data } = error.response
  if (status === 401) return 'Your session has expired. Sign in again.'
  if (status === 403) return 'You do not have permission to do this.'
  try {
    const text = typeof data?.text === 'function' ? await data.text() : typeof data === 'string' ? data : null
    const parsed = text ? JSON.parse(text) : data
    if (parsed?.error) return String(parsed.error)
  } catch {
    /* not JSON */
  }
  return `${fallback} (HTTP ${status}).`
}

/** Saves a Blob as a file via a temporary object URL. */
export function saveBlob(blob, filename, doc = globalThis.document, urlApi = globalThis.URL) {
  const url = urlApi.createObjectURL(blob)
  const a = doc.createElement('a')
  a.href = url
  a.download = filename
  a.rel = 'noopener'
  a.style.display = 'none'
  doc.body.appendChild(a)
  a.click()
  a.remove()
  // Revoke after the click has been handled, so the download is not cancelled
  setTimeout(() => urlApi.revokeObjectURL(url), 1000)
}
