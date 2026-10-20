# Administrator-only SentinelAI enrollment

The owner selected this policy on 15 October 2026. It supersedes earlier public analyst registration descriptions; historical reports/evidence remain unchanged.

- Public POST `/api/auth/register` never creates accounts or sessions. A valid protected request returns sanitized 403: Public registration is disabled. Contact an administrator for access. Invalid transport, Origin, CSRF, parsing or rate limits may reject earlier.
- An active authenticated administrator uses POST `/api/auth/provision`. It shares `/api/auth` nonce-cookie Path, signed CSRF/Origin controls, the browser Web Lock, production transport checks and authentication rate limits. Other roles cannot create accounts or modify roles through the user-management API.
- Required fields: name, email, password. Optional role defaults to viewer; explicitly authorized admins may choose viewer, analyst or admin. Department defaults to SOC. Unknown fields, invalid roles and invalid values are rejected. Status is active and authVersion is zero at creation; callers cannot mass-assign them.
- Email is trimmed/lowercased. Existing emails and unique-index races return sanitized 409. Store failure returns sanitized 503. Account passwords use the existing User save middleware, bcrypt cost 12. No password, token or refresh cookie is returned and the administrator session is unchanged.
- The admin Users page provisions accounts through the actual endpoint. The old fake Invite sent toast is removed. No invitation email or one-time delivery mechanism is claimed. Deliver initial credentials through an approved private channel. Provisioned accounts are created with `mustChangePassword: true` (`backend/controllers/userController.js`), and `protect` / the Socket.IO handshake refuse all other platform access until the password is changed. Temporary-password expiry is not implemented.

## Initial administrator

Existing `backend/config/db.js` bootstrap requires an explicitly supplied nonempty ADMIN_INITIAL_PASSWORD. There is no built-in password. In a reviewed fresh environment, inject ADMIN_EMAIL, ADMIN_NAME and a new strong ADMIN_INITIAL_PASSWORD through a private temporary process/service secret channel, with the normal required signing/service secrets and the reviewed MONGO_URI. Start the backend normally using `node server.js`; the existing bootstrap creates the configured admin only when that email is absent. Remove the bootstrap password from later startup environments. Do not edit existing .env files or use the destructive/demo `npm run seed` or `utils/clean.js`.

If the configured email already belongs to a non-admin, bootstrap does not promote it. An authorized operator must review the conflict; do not change existing roles automatically. This bootstrap is a trusted operator action, not a public route. Never expose bootstrap credentials in command arguments, logs, reports, images or source control. No actual administrator or account was provisioned in a persistent database during this task.

## Existing-account review — pending actual database availability

No eligible database/backend is running. No database was started and no retained acceptance database was queried. Current account identities, counts and roles therefore remain **unverified**, rather than inferred from old acceptance fixtures. Existing public-registration accounts may already have analyst privileges; disabling enrollment does not revoke them.

An authorized administrator must use GET `/api/users/stats` and paginated GET `/api/users?limit=100&page=N` on an independently approved database. Review every analyst/admin's identity, approval, department, status and need for captured-forensic-data access; include dormant accounts, unexpected admins, duplicate identities and accounts created during the former public-registration period. Keep the roster in a private admin workspace, not public test logs. Report only approved identifiers/counts outside that workspace. No deletion, demotion or session revocation occurs automatically; any reviewed role/status change follows the existing version/session-revocation path.

Unit/HTTP tests use mocked stores; the real bcrypt middleware test mocks collection.insertOne. Native/container persistence acceptance of this new endpoint remains pending. Historical native runners that call public registration are incompatible with this deliberate cutover and must be reviewed/adapted before reuse; they were not executed here.
