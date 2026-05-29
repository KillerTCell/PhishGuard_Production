# Invite Flow — Railway Deployment Changes

## 1. backend/app/routers/auth.py — Invite Link URL
Current (local):
  http://localhost:3000/PhishGuard.html?invite={token}

Change to (Railway):
  https://{RAILWAY_URL}/PhishGuard.html?invite={token}

How to make it dynamic — add to backend/app/core/config.py:
  FRONTEND_URL: str = "http://localhost:3000"

Then in auth.py use:
  f"{settings.FRONTEND_URL}/PhishGuard.html?invite={raw_token}"

Set in Railway environment variables:
  FRONTEND_URL=https://{your-railway-domain}

## 2. backend/app/routers/auth.py — Password Reset Link
Same change as invite link above.
Current:
  http://localhost:3000/PhishGuard.html?reset={token}
Change to:
  f"{settings.FRONTEND_URL}/PhishGuard.html?reset={token}"

## 3. PhishGuard.html — API_BASE URL
Current:
  const API_BASE = 'https://localhost/api/v1';
Change to Railway URL before deploying:
  const API_BASE = 'https://{RAILWAY_URL}/api/v1';

Or use dynamic detection:
  const API_BASE = window.location.hostname === 'localhost'
    ? 'https://localhost/api/v1'
    : `https://${window.location.hostname}/api/v1`;

This way the same file works in both local and Railway
without manual changes.

## 4. backend/app/main.py — CORS Origins
Current hardcoded dev origins include localhost:3000.
Before Railway deploy, add Railway URL to CORS list:
  "https://{RAILWAY_URL}"

Or add FRONTEND_URL to the allowed origins dynamically:
  allowed = baseline_origins + [settings.FRONTEND_URL]

## 5. Invite Token Expiry
Current: 48 hours (set in backend/app/routers/auth.py)
No change needed for Railway — 48 hours works in production.

## 6. Email FROM Address
Current: onboarding@resend.dev (Resend shared domain)
Works in production as-is — no change required.
Optional upgrade: verify your own domain in Resend dashboard
and change to: noreply@yourdomain.com

## 7. Registration Flow After Successful Account Creation
Current: redirects to dashboard at localhost
After Railway deploy: dashboard URL will be Railway URL.
The dynamic API_BASE fix in point 3 above handles this
automatically if implemented correctly.

## SUMMARY — Minimum changes before Railway deploy
| What | File | Change |
|---|---|---|
| Invite link URL | routers/auth.py | localhost:3000 → FRONTEND_URL env var |
| Reset link URL | routers/auth.py | localhost:3000 → FRONTEND_URL env var |
| API base URL | PhishGuard.html | Use dynamic hostname detection |
| CORS origins | app/main.py | Add Railway URL |
| FRONTEND_URL | config.py + Railway env | Add new env variable |
