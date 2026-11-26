# Git-Agent

An agentic RAG platform for ingesting public GitHub repositories, answering codebase questions with hybrid search, and proposing/reviewing code changes with human-in-the-loop approvals.

---

## Backend Authentication Implementation

Implemented under `backend-server/` using **FastAPI**, **Supabase Postgres**, **Redis**, **JWT (`httpOnly` cookies + CSRF protection)**, **Email OTP verification**, and **Google OAuth 2.0**, aligned with [Git-Agent_Technical_Requirements_Document_v0.2.docx](docs/Git-Agent_Technical_Requirements_Document_v0.2.docx).

### Directory Structure

```text
backend-server/
├── main.py                      # FastAPI app, CORS (credentials enabled), and router registration
├── requirements.txt             # Backend Python dependencies
├── core/
│   ├── config.py                # Environment configuration (JWT, cookies, OTP, rate limits, Google OAuth, SMTP)
│   ├── database.py              # Supabase and Redis client initialization
│   └── security.py              # Password/OTP hashing, JWT creation/decoding, cookies, CSRF, RBAC dependencies
├── common/
│   ├── models.py                # Pydantic request/response schemas and Role/AuthProvider enums
│   └── email_service.py         # SMTP email sender for signup and password-reset OTPs
└── service/
    └── auth/
        ├── endpoint.py          # /api/v1/auth/* FastAPI routes
        └── helper.py            # OTP flows, rate limiting, session blacklisting, audit logging, Google OAuth
```

### Security & Auth Design

- **Roles (`Role`):** `user` and `admin` (enforced via `RoleChecker`, `require_user`, and `require_admin` in `backend-server/core/security.py`).
- **Password Hashing:** `bcrypt` via `passlib.context.CryptContext` (`bcrypt==3.2.2`).
- **Session Cookies:** Access (`15` min default) and refresh (`7` days default) JWTs are issued in `httpOnly`, `SameSite=lax` cookies (`Secure` controlled by `COOKIE_SECURE`).
- **CSRF Protection:** Double-submit `csrf_token` cookie validated against the `X-CSRF-Token` request header (`verify_csrf`) on cookie-authenticated state-changing endpoints (`/api/v1/auth/refresh`, `/api/v1/auth/logout`).
- **Immediate Account Disable Check:** `get_current_user` checks both the Redis `blacklist:{user_id}` revocation key and `users.is_active` in Supabase on every authenticated request.
- **Email OTP & Abuse Controls:**
  - 6-digit numeric OTPs are stored in Redis as HMAC-SHA256 hashes (`hash_otp`), never plain text, with a `300s` TTL (`OTP_TTL_SECONDS`).
  - Unverified signups remain in Redis (`signup:{email}`) and are written to Supabase only after OTP verification.
  - Defaults in `backend-server/core/config.py`: max `3` verification attempts (`OTP_MAX_ATTEMPTS`), `50s` resend cooldown (`OTP_RESEND_COOLDOWN_SECONDS`), and fixed-window Redis rate limiting (`AUTH_RATE_LIMIT_MAX=8` per `AUTH_RATE_LIMIT_WINDOW_SECONDS=60`s, with stricter per-endpoint IP/email caps).
- **Google OAuth 2.0:** Authorization Code flow with single-use Redis `state` validation (`oauth_state:{state}`), verified email check (`email_verified`), and automatic user provisioning with `auth_provider="google"`.
- **Audit Logging:** Login and password-reset events are recorded in Supabase `audit_logs`.

### API Endpoints (`/api/v1/auth`)

| Method & Path | Access | Purpose |
| --- | --- | --- |
| `POST /api/v1/auth/signup` | Public | Validate signup (`email`, `username`, `password`), store pending record in Redis, send 6-digit OTP email |
| `POST /api/v1/auth/verify-otp` | Public | Verify signup OTP hash, create active `user` row in Supabase, delete pending Redis key |
| `POST /api/v1/auth/resend-otp` | Public | Re-send OTP for `signup` or `reset` (enforces cooldown & rate limits) |
| `POST /api/v1/auth/login` | Public | Authenticate email/password, set `access_token`, `refresh_token`, and `csrf_token` cookies, log audit event |
| `GET /api/v1/auth/google` | Public | Redirect to Google OAuth consent screen with Redis-backed CSRF `state` |
| `GET /api/v1/auth/google/callback` | Public | Exchange code, verify email, find/create user, set auth cookies, log audit event, redirect to frontend |
| `POST /api/v1/auth/refresh` | Refresh Cookie + CSRF | Verify `refresh_token` cookie, check blacklist & `is_active`, issue new `access_token` cookie |
| `POST /api/v1/auth/forgot-password` | Public | Send password-reset OTP email for active accounts |
| `POST /api/v1/auth/reset-password` | Public | Verify reset OTP hash, update password, blacklist existing JWTs, log audit event |
| `POST /api/v1/auth/logout` | Authenticated + CSRF | Blacklist user session in Redis and clear auth/CSRF cookies |

> **Note:** `/api/v1/auth/me` is intentionally omitted here and replaced by the `/api/v1/profile` service.

---

### Supabase Tables Required for Auth

```sql
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    username TEXT,
    password_hash TEXT,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    auth_provider TEXT NOT NULL DEFAULT 'email' CHECK (auth_provider IN ('email', 'google')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### Environment Variables (`backend-server/.env`)

```env
APP_NAME=Git-Agent
FRONTEND_URL=http://localhost:3000

# JWT & Cookies
JWT_SECRET_KEY=replace-with-strong-random-secret
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
COOKIE_SECURE=false          # Set true in HTTPS production
COOKIE_SAMESITE=lax

# OTP & Rate Limiting
OTP_TTL_SECONDS=300
OTP_MAX_ATTEMPTS=3
OTP_RESEND_COOLDOWN_SECONDS=50
AUTH_RATE_LIMIT_MAX=8
AUTH_RATE_LIMIT_WINDOW_SECONDS=60

# Supabase & Redis
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
REDIS_URL=redis://localhost:6379/0

# Google OAuth 2.0
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v1/auth/google/callback

# SMTP
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM_NAME=Git-Agent
SMTP_FROM_EMAIL=your-email@gmail.com
```

---

### Running Locally

```bash
cd backend-server
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Interactive API docs will be available at `http://localhost:8000/docs`.
