// Content-Security-Policy for the dashboard. nginx.conf sends the same string (tests/csp.test.mjs keeps them equal);
// `vite preview` sends it too, so a production build can be checked locally. Not applied to `vite dev`, whose
// React refresh runtime needs an inline script.
//   script-src 'self'        the build has only same-origin module scripts, no inline or eval
//   style-src 'unsafe-inline' index.html's base <style> and the style="" attributes React/Recharts render
//   fonts.googleapis/gstatic  the three web fonts index.html loads
//   connect-src 'self'       API and Socket.IO are same-origin (nginx / the preview proxy forward them)
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ')
