const express = require('express')
const router = express.Router()
const {
  register,
  login,
  getMe,
  updatePassword,
  refreshToken,
  logout,
  logoutAll,
} = require('../controllers/authController')
const { protect, restrictTo } = require('../middleware/auth')
const { provisionUser } = require('../controllers/userController')
const { validateRegister, validateLogin } = require('../middleware/validate')
const { getCsrf, protectMutation } = require('../middleware/authCookies')
/**
 * @openapi
 * /auth/csrf:
 *   get:
 *     tags: [Auth]
 *     summary: Obtain signed CSRF proof and auth-scoped HttpOnly nonce cookie
 *     responses:
 *       200: { description: data.csrfToken is used in X-CSRF-Token; response must not be cached }
 * /auth/login:
 *   post:
 *     tags: [Auth]
 *     summary: Create a new server session and set its HttpOnly refresh cookie
 *     description: Requires trusted Origin and X-CSRF-Token from /auth/csrf with its nonce cookie. JSON returns data.token and data.user; no refresh token is returned in JSON.
 *     parameters:
 *       - { in: header, name: X-CSRF-Token, required: true, schema: { type: string } }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email: { type: string, format: email }
 *               password: { type: string, format: password }
 *     responses:
 *       200: { description: Access token expires in 15 minutes; cookie session has a 30-day absolute expiry }
 *       401: { description: Invalid credentials }
 *       403: { description: Origin/CSRF rejected or inactive account }
 *       503: { description: Authentication dependency unavailable }
 * /auth/register:
 *   post:
 *     tags: [Auth]
 *     summary: Public registration is disabled
 *     description: Never creates an account or session. Existing Origin/CSRF safeguards remain in force. Contact an administrator for access.
 *     parameters:
 *       - { in: header, name: X-CSRF-Token, required: true, schema: { type: string } }
 *     responses:
 *       403: { description: Public registration disabled or Origin/CSRF rejected }
 * /auth/provision:
 *   post:
 *     tags: [Auth, Users]
 *     summary: Administrator provisions an operator account
 *     description: Requires an active administrator session, trusted Origin and signed CSRF proof/nonce. Defaults to viewer; admin/analyst require explicit selection. Issues no session/token and preserves the administrator session. Unknown fields are rejected.
 *     security: [{ BearerAuth: [] }]
 *     parameters:
 *       - { in: header, name: X-CSRF-Token, required: true, schema: { type: string } }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             additionalProperties: false
 *             required: [name, email, password]
 *             properties:
 *               name: { type: string, minLength: 2, maxLength: 50 }
 *               email: { type: string, format: email, maxLength: 100 }
 *               password: { type: string, format: password, minLength: 8, maxLength: 128 }
 *               role: { type: string, enum: [viewer, analyst, admin], default: viewer }
 *               department: { type: string, minLength: 1, maxLength: 100, default: SOC }
 *     responses:
 *       201: { description: Public user only; no password/token/refresh cookie }
 *       401: { description: Active authenticated session required }
 *       403: { description: Administrator required or Origin/CSRF rejected }
 *       409: { description: Email already exists }
 *       422: { description: Invalid or unsupported account fields }
 *       503: { description: Authentication or account store unavailable }
 * /auth/refresh-token:
 *   post:
 *     tags: [Auth]
 *     summary: Atomically consume and rotate the HttpOnly refresh cookie
 *     description: Requires trusted Origin and CSRF proof/cookie. Refresh token body input is not accepted. Reuse revokes the session family; absolute expiry never extends.
 *     parameters:
 *       - { in: header, name: X-CSRF-Token, required: true, schema: { type: string } }
 *     responses:
 *       200: { description: New data.token/data.user and successor refresh cookie }
 *       401: { description: "Expired, replayed, revoked or legacy token" }
 *       503: { description: Authentication dependency unavailable }
 * /auth/logout:
 *   post:
 *     tags: [Auth]
 *     summary: Revoke current session and clear auth cookies
 *     description: Requires trusted Origin and CSRF. A valid refresh cookie permits logout after access expiry. Repeated logout is idempotent; persistence failure is not reported as success.
 *     parameters:
 *       - { in: header, name: X-CSRF-Token, required: true, schema: { type: string } }
 *     responses:
 *       200: { description: Current family revoked or no remaining credential }
 * /auth/logout-all:
 *   post:
 *     tags: [Auth]
 *     summary: Increment authenticated user version and revoke all their sessions
 *     security: [{ BearerAuth: [] }]
 *     parameters:
 *       - { in: header, name: X-CSRF-Token, required: true, schema: { type: string } }
 *     responses:
 *       200: { description: "All user sessions revoked, cookies cleared" }
 * /auth/me:
 *   get:
 *     tags: [Auth]
 *     summary: Read current active session's public user
 *     security: [{ BearerAuth: [] }]
 *     responses:
 *       200: { description: Public user }
 *       401: { description: Session required }
 * /auth/update-password:
 *   put:
 *     tags: [Auth]
 *     summary: Verify current password, increment user version and issue replacement session
 *     description: Send currentPassword/newPassword with trusted Origin and CSRF proof/cookie. Existing bcrypt cost and role checks are preserved.
 *     security: [{ BearerAuth: [] }]
 *     parameters:
 *       - { in: header, name: X-CSRF-Token, required: true, schema: { type: string } }
 *     responses:
 *       200: { description: New access/user and refresh cookie; all prior versions rejected }
 */
router.get('/csrf', getCsrf)
router.use((req, res, next) =>
  ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) ? protectMutation(req, res, next) : next()
)
router.post('/register', register)
router.post('/provision', protect, restrictTo('admin'), validateRegister, provisionUser)
router.post('/login', validateLogin, login)
router.post('/refresh-token', refreshToken)
router.post('/logout', logout)
router.post('/logout-all', protect, logoutAll)
router.get('/me', protect, getMe)
router.put('/update-password', protect, updatePassword)
module.exports = router
