"""Section 9 Phase 3C — live model verification test.

Steps:
1. Login → get JWT
2. Upload phishing .eml
3. Poll GET /analysis/{id}/status until status != 'pending' (timeout 120 s)
4. Assert status ∈ {quarantined, flagged, delivered}
5. Assert risk_score 0-100
6. Assert classification ∈ {safe, suspicious, phishing}
7. Assert explanation not empty
"""
import sys
import time
import httpx

BASE = "http://localhost:8000/api/v1"

# ── 1. Login ──────────────────────────────────────────────────────────────────
print("Step 1: Login")
r = httpx.post(f"{BASE}/auth/login", json={
    "email": "analyst@test.com",
    "password": "TestPass99!",
})
assert r.status_code == 200, f"Login failed: {r.status_code} {r.text}"
token = r.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}
print(f"  ✓ JWT obtained")

# ── 2. Upload phishing .eml ───────────────────────────────────────────────────
print("Step 2: Upload .eml")
EML = b"""\
From: security-alert@paypa1-secure.com\r
To: victim@example.com\r
Subject: Urgent: Your account has been suspended\r
Date: Wed, 27 May 2026 09:00:00 +0000\r
MIME-Version: 1.0\r
Content-Type: text/html; charset=utf-8\r
\r
<html><body>
<p>Dear Customer,</p>
<p>Your PayPal account has been <strong>suspended</strong> due to suspicious activity.</p>
<p>Click here immediately to verify your account:
<a href="http://paypa1-secure.com/login?token=abc123">Verify Now</a></p>
<p>Failure to verify within 24 hours will result in permanent account closure.</p>
<p>PayPal Security Team</p>
</body></html>
"""

r = httpx.post(
    f"{BASE}/emails/upload",
    headers=headers,
    files={"file": ("phishing.eml", EML, "message/rfc822")},
    timeout=30,
)
assert r.status_code == 202, f"Upload failed: {r.status_code} {r.text}"
upload_data = r.json()
email_id = upload_data["email_id"]
print(f"  ✓ Uploaded email_id={email_id}, initial status={upload_data['status']}")

# ── 3. Poll until non-pending (120 s timeout) ─────────────────────────────────
print("Step 3: Polling analysis status ...")
deadline = time.time() + 180
status_data: dict = {}
while time.time() < deadline:
    r = httpx.get(f"{BASE}/emails/{email_id}", headers=headers, timeout=10)
    if r.status_code == 200:
        status_data = r.json()
        current_status = status_data.get("status", "pending")
        print(f"  ... status={current_status}", flush=True)
        if current_status != "pending":
            break
    time.sleep(3)
else:
    print("FAIL: timed out waiting for analysis to complete", file=sys.stderr)
    sys.exit(1)

# ── 4-7. Assertions ───────────────────────────────────────────────────────────
print("\nStep 4-7: Asserting result fields")

status = status_data.get("status")
risk_score = status_data.get("risk_score")
classification = status_data.get("classification")
explanation = status_data.get("explanation")

VALID_STATUSES = {"quarantined", "flagged", "delivered", "failed"}
VALID_CLASSES = {"safe", "suspicious", "phishing"}

errors = []

if status not in VALID_STATUSES - {"failed"}:
    if status == "failed":
        errors.append(f"status=failed (pipeline error — check worker logs)")
    else:
        errors.append(f"status={status!r} not in {{quarantined, flagged, delivered}}")

if risk_score is None:
    errors.append("risk_score is None")
elif not (0 <= risk_score <= 100):
    errors.append(f"risk_score={risk_score} out of range [0, 100]")

if classification not in VALID_CLASSES:
    errors.append(f"classification={classification!r} not in {VALID_CLASSES}")

if not explanation:
    errors.append("explanation is empty/None")

if errors:
    print("\nFAIL — assertion errors:")
    for e in errors:
        print(f"  ✗ {e}")
    sys.exit(1)

print(f"  ✓ status={status}")
print(f"  ✓ risk_score={risk_score} (in [0, 100])")
print(f"  ✓ classification={classification}")
print(f"  ✓ explanation={explanation[:80]!r}...")
print("\n✓ All assertions passed — live model test PASS")
