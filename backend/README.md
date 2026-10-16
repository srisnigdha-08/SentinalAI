# SentinelAI — Phase 2: Backend API

## Quick Start

```bash
cd backend

# 1. Install dependencies
npm ci --ignore-scripts

# 2. Setup environment
# Preserve existing .env; create from .env.example only if missing
# Edit .env with your MongoDB URI and secrets

# 3. Configure a fresh MongoDB database and start the AI service
# Follow ../docs/NATIVE_DEVELOPMENT.md; do not seed production data.

# 4. Start development server
npm run dev
# Server runs at http://localhost:5000
```

## Prerequisites

- Node.js 24
- MongoDB running locally (or MongoDB Atlas URI)

Start MongoDB locally:

```bash
# macOS (Homebrew)
brew services start mongodb-community

# Ubuntu/Linux
sudo systemctl start mongod

# Windows
net start MongoDB
```

---

## Project Structure

```
backend/
├── server.js              ← Entry point. Express + Socket.IO server.
├── config/
│   ├── db.js              ← MongoDB connection
│   └── swagger.js         ← OpenAPI 3.0 & Swagger UI config
├── controllers/
│   ├── authController.js  ← Register, login, JWT
│   ├── threatController.js← Threat CRUD + analytics + settings
│   ├── honeypotController.js ← Session management
│   ├── alertController.js ← Alert CRUD
│   └── userController.js  ← User management (admin)
├── routes/
│   ├── auth.js            ← Auth & token lifecycle
│   ├── threats.js         ← Threat intelligence & blocklist
│   ├── honeypot.js        ← Honeypot sessions
│   ├── honeypotIngest.js  ← Collector ingestion & block checks
│   ├── campaigns.js       ← Campaign clustering
│   ├── alerts.js          ← Alert dispatch & triage
│   ├── users.js           ← User administration
│   └── aiEngine.js        ← AI inference & prediction storage
├── middleware/
│   ├── auth.js            ← JWT verify + RBAC
│   ├── errorHandler.js    ← Global error handling
│   └── validate.js        ← Input validation
├── models/
│   ├── User.js            ← bcrypt password hashing
│   ├── ThreatLog.js       ← Threat events
│   ├── HoneypotSession.js ← Attacker sessions
│   ├── Campaign.js        ← Clustered threat campaigns
│   ├── BlockedIP.js       ← Automated and manual IP blocklist
│   ├── SystemSetting.js   ← Configuration settings
│   ├── Alert.js           ← Notifications
│   └── AIPrediction.js    ← AI inference results
├── services/              ← Business logic and AI engine integration
├── utils/
│   ├── logger.js          ← Winston structured logging
│   ├── apiResponse.js     ← Standardised responses
│   ├── mitreMapping.js    ← MITRE ATT&CK technique mapping
│   └── seed.js            ← Database seeder
└── logs/                  ← Generated log files
```

> **Interactive API Documentation**: OpenAPI 3.0 Swagger UI is available at `http://localhost:5000/api/docs` and raw spec at `/api/docs.json`.

---

## API Reference

### Authentication

| Method | Endpoint                    | Auth | Description           |
| ------ | --------------------------- | ---- | --------------------- |
| POST   | `/api/auth/register`        | Disabled | Always rejects; no public accounts |
| POST   | `/api/auth/provision`       | Active admin + Origin/CSRF | Provision account; viewer default; no session issued |
| POST   | `/api/auth/login`           | ❌   | Login, get JWT        |
| GET    | `/api/auth/me`              | ✅   | Get own profile       |
| PUT    | `/api/auth/update-password` | ✅   | Change password       |
| POST   | `/api/auth/refresh-token`   | ❌   | Refresh expired token |
| GET    | `/api/auth/csrf`            | ❌   | Signed CSRF proof and nonce cookie |
| POST   | `/api/auth/logout`          | Cookie/access | Revoke current session |
| POST   | `/api/auth/logout-all`      | ✅   | Revoke all user sessions |

All auth mutations require the configured Origin and X-CSRF-Token from GET
/api/auth/csrf, including its HttpOnly nonce cookie. Send cookies with credentials.
Refresh accepts only the HttpOnly refresh cookie, not JSON body tokens. Access
tokens stay in browser memory. Legacy tokens require sign-in again. HTTPS is
required in production; HTTP transport is limited to loopback development.
Logout supports a valid refresh cookie after access expiry; a failed server
revocation is reported as unconfirmed, not successful logout. See
[implementation details](../docs/AUTH_TIMEZONE_IMPLEMENTATION.md).

**Login Request:**

```json
POST /api/auth/login
{ "email": "admin@sentinel.io", "password": "<configured-admin-password>" }
```

**Login Response:**

```json
{
  "success": true,
  "data": {
    "token": "eyJhbGci...",
    "user": { "id": "...", "name": "Admin User", "email": "...", "role": "admin" }
  }
}
```

---

### Threats

| Method | Endpoint                         | Auth | Role     | Description              |
| ------ | -------------------------------- | ---- | -------- | ------------------------ |
| GET    | `/api/threats`                   | ✅   | Any      | List threats (paginated) |
| GET    | `/api/threats/:id`               | ✅   | Any      | Get single threat        |
| POST   | `/api/threats`                   | ✅   | analyst+ | Create threat            |
| PUT    | `/api/threats/:id`               | ✅   | analyst+ | Update threat            |
| DELETE | `/api/threats/:id`               | ✅   | admin    | Delete threat            |
| POST   | `/api/threats/:id/block`         | ✅   | analyst+ | Block IP                 |
| GET    | `/api/threats/analytics/summary` | ✅   | Any      | Dashboard stats          |

**Query Parameters (GET /api/threats):**

- `?page=1&limit=20` — Pagination
- `?severity=CRITICAL` — Filter by severity
- `?status=BLOCKED` — Filter by status
- `?type=SQL+Injection` — Filter by attack type
- `?search=185.220` — Search by IP
- `?startDate=2024-01-01&endDate=2024-01-31` — Date range

---

### Honeypot

| Method | Endpoint                              | Auth | Description             |
| ------ | ------------------------------------- | ---- | ----------------------- |
| GET    | `/api/honeypot/sessions`              | ✅   | List sessions           |
| POST   | `/api/honeypot/sessions`              | ✅   | Create session (Cowrie) |
| GET    | `/api/honeypot/sessions/:id`          | ✅   | Get session detail      |
| POST   | `/api/honeypot/sessions/:id/commands` | ✅   | Add commands            |
| PUT    | `/api/honeypot/sessions/:id/close`    | ✅   | Close session           |
| GET    | `/api/honeypot/analytics`             | ✅   | Analytics summary       |
| GET    | `/api/honeypot/nodes`                 | ✅   | Node status             |

---

### Alerts

| Method | Endpoint                    | Auth     | Description   |
| ------ | --------------------------- | -------- | ------------- |
| GET    | `/api/alerts`               | ✅       | List alerts   |
| GET    | `/api/alerts/unread-count`  | ✅       | Unread count  |
| PUT    | `/api/alerts/:id/read`      | ✅       | Mark as read  |
| PUT    | `/api/alerts/mark-all-read` | ✅       | Mark all read |
| DELETE | `/api/alerts/:id`           | ✅ admin | Delete alert  |

---

### Users (Admin only)

| Method | Endpoint           | Auth     | Description     |
| ------ | ------------------ | -------- | --------------- |
| GET    | `/api/users`       | ✅ admin | List all users  |
| GET    | `/api/users/:id`   | ✅ admin | Get user        |
| PUT    | `/api/users/:id`   | ✅ admin | Update user     |
| DELETE | `/api/users/:id`   | ✅ admin | Delete user     |
| GET    | `/api/users/stats` | ✅ admin | User statistics |

---

### AI Engine

| Method | Endpoint                         | Auth        | Description       |
| ------ | -------------------------------- | ----------- | ----------------- |
| GET    | `/api/ai/predictions`            | ✅          | List predictions  |
| POST   | `/api/ai/predictions`            | ✅ analyst+ | Store prediction  |
| GET    | `/api/ai/stats`                  | ✅          | Model performance |
| PUT    | `/api/ai/predictions/:id/verify` | ✅ analyst+ | Verify prediction |

---

## Security Features

| Feature             | Implementation                          |
| ------------------- | --------------------------------------- |
| Password hashing    | bcrypt (12 rounds)                      |
| JWT authentication  | 15-minute access; 30-day absolute session; atomic refresh rotation and revocation |
| Role-based access   | admin / analyst / viewer                |
| Rate limiting       | 100 req/15min global, 20/15min for auth |
| NoSQL injection     | express-mongo-sanitize                  |
| Security headers    | helmet.js                               |
| Request compression | compression.js                          |
| Structured logging  | winston                                 |
| Graceful shutdown   | SIGTERM/SIGINT handlers                 |

---

## Test with cURL

```bash
# Public registration is disabled. Use the administrator Users workflow.
# Account provisioning requires active admin bearer + signed CSRF nonce/proof.
# See docs/ENROLLMENT_POLICY_20261015.md for private bootstrap and account review.

# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@sentinel.io","password":"<your-admin-password>"}'

# Get threats (replace TOKEN)
curl http://localhost:5000/api/threats \
  -H "Authorization: Bearer TOKEN"

# Get analytics
curl http://localhost:5000/api/threats/analytics/summary \
  -H "Authorization: Bearer TOKEN"

# Health check
curl http://localhost:5000/health
```

---

## Administrator Account Provisioning

The initial administrator account is provisioned dynamically via environment variables during database bootstrap:

- `ADMIN_EMAIL`: Email for the administrator (defaults to `admin@sentinel.io`)
- `ADMIN_INITIAL_PASSWORD`: Secure initial password (minimum 8 characters)

If `ADMIN_INITIAL_PASSWORD` is not configured in the environment, automatic admin account creation is skipped safely to ensure no default credentials exist.

---

## Frontend integration

The frontend already uses the real API and authenticated Socket.IO.
See [native development](../docs/NATIVE_DEVELOPMENT.md),
[validation](../docs/VALIDATION.md). Docker deployment is postponed.
