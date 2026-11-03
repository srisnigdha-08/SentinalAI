// TEST-009: when page.goto replaces a page, WebKit refuses the requests that page still had open or had just created
// (pollers, Socket.IO long-polls) and Playwright delivers each refusal as a page error: "XMLHttpRequest cannot load
// <url> due to access control checks.", raised where the request was created. Many of these requests never reached
// the network, so no request event exists to match them against. They are not exceptions in the app: the page itself
// sees no 'error' or 'unhandledrejection' event, and the app's pollers catch their rejections.
// A same-origin request cannot fail a CORS check, so such a refusal for a same-origin URL is a cancellation and is
// ignored; a cross-origin one may be a real CORS failure and, like every other page error, still fails the test.
//
// Genuine failures look different in every engine (measured): a refused connection or a broken Socket.IO transport is
// never a page error; it is a failed request (net::ERR_CONNECTION_REFUSED, NS_ERROR_CONNECTION_REFUSED, ...). The
// tracker therefore also reports same-origin API and Socket.IO requests that fail for any reason other than a
// navigation cancellation. HTTP error statuses are answers the app handles; functional tests cover those.

const CANNOT_LOAD = /^(?:XMLHttpRequest|Fetch API) cannot load (\S+) due to access control checks\.$/
const CANCELLED = /^(?:Load request cancelled|NS_BINDING_ABORTED|net::ERR_ABORTED)$/
const WATCHED_PATH = /^\/(?:api|socket\.io)\//

/** The URL a WebKit "cannot load" page error refers to, or null for any other error. */
export function cannotLoadUrl({ name = '', message = '', stack = '' }) {
  const text = (stack.split('\n')[0] || '').trim() || `${name}: ${message}`
  return text.match(CANNOT_LOAD)?.[1] ?? null
}

export function isNavigationCancellation(error, pageOrigin) {
  const url = cannotLoadUrl(error)
  if (url === null) return false
  try {
    return new URL(url).origin === pageOrigin
  } catch {
    return false
  }
}

/** True when a failed request is a genuine failure the tests must see (not a cancellation by navigation). */
export function isGenuineRequestFailure(url, errorText, pageOrigin) {
  if (CANCELLED.test(errorText || '')) return false
  try {
    const u = new URL(url)
    return u.origin === pageOrigin && WATCHED_PATH.test(u.pathname)
  } catch {
    return false
  }
}

/** Collects page errors and failed requests; fatal() returns everything that is not a navigation cancellation. */
export function trackPageErrors(page) {
  const errors = []
  const failures = []
  page.on('pageerror', (e) => errors.push({ url: page.url(), name: e.name, message: e.message, stack: e.stack || '' }))
  page.on('requestfailed', (r) => {
    const errorText = r.failure()?.errorText || ''
    if (isGenuineRequestFailure(r.url(), errorText, safeOrigin(page.url()))) {
      failures.push({ url: page.url(), error: `request failed: ${r.method()} ${r.url()} (${errorText})` })
    }
  })
  return {
    fatal: () => [
      ...errors
        .filter((e) => !isNavigationCancellation(e, safeOrigin(e.url)))
        .map(({ url, name, message }) => ({ url, error: `${name}: ${message}` })),
      ...failures,
    ],
  }
}

function safeOrigin(url) {
  try {
    return new URL(url).origin
  } catch {
    return null
  }
}
