"""Resend transactional email service (Section 5.2, FR-06, UC-05).

Public API:
    build_digest_html   -- sync; produce WCAG 2.1 AA-compliant digest HTML
    send_digest_email   -- async; dispatch via Resend SDK, return True/False

HTML template design (WCAG 2.1 AA):
  - Colour contrast: ≥ 4.5:1 for all text/background pairs
    · Red badge  #cc0000 on #ffffff  → 5.9:1  ✓
    · Amber badge #e6a817 uses dark text #1a1a1a → 7.6:1  ✓
    · Body text  #222222 on #ffffff   → 14.7:1 ✓
  - Semantic HTML: heading hierarchy h1/h2, role="main", aria-labels
  - Buttons have descriptive aria-label attributes
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import structlog

from app.core.config import settings

log = structlog.get_logger(__name__)

_FROM_ADDRESS = "PhishGuard <onboarding@resend.dev>"
_APP_BASE_URL = f"https://{settings.FORWARDING_DOMAIN}"


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------


def _esc(text: str) -> str:
    """Minimal HTML-escape to prevent XSS in digest content."""
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# build_digest_html
# ---------------------------------------------------------------------------


def build_digest_html(
    email: Any,          # Email ORM instance — typed Any to avoid circular import
    analysis: Any,       # AnalysisResult ORM instance or None
    signed_token: str,
    expires_at: datetime,
) -> str:
    """Build a WCAG 2.1 AA-compliant quarantine digest HTML email.

    The rendered email includes:
    - Risk badge (red for phishing, amber for suspicious, green otherwise)
    - From, Subject, and risk score metadata
    - Plain-English explanation from ``analysis_result.explanation``
    - Two signed action buttons (Release to Inbox / Report Phishing)
    - 72-hour expiry notice

    Action URL format (consumed by ``GET /digest/action``):
        ``{APP_BASE_URL}/api/v1/digest/action?token={signed_token}&action=...``

    Args:
        email:        Email ORM row (reads ``sender``, ``subject``).
        analysis:     AnalysisResult ORM row or ``None`` when still pending.
        signed_token: Full ``"{email_id}:{jti}:{hmac_hex}"`` token string.
        expires_at:   UTC ``datetime`` when the token expires (72 h from send).

    Returns:
        Complete HTML string, UTF-8 encoded, ready for the Resend ``html``
        parameter.
    """
    risk_score: int = analysis.risk_score if analysis else 0
    classification: str = (
        (analysis.classification if analysis else None) or "safe"
    )
    explanation: str = (
        (analysis.explanation if analysis else None)
        or "This email has been quarantined for security review."
    )

    # ── Risk badge colours (WCAG AA) ─────────────────────────────────────────
    if classification == "phishing":
        badge_bg = "#cc0000"
        badge_fg = "#ffffff"   # contrast 5.9:1 ✓
        badge_label = "PHISHING THREAT DETECTED"
        heading_colour = "#b71c1c"
    elif classification == "suspicious":
        badge_bg = "#e6a817"
        badge_fg = "#1a1a1a"   # dark text on amber → 7.6:1 ✓
        badge_label = "SUSPICIOUS EMAIL"
        heading_colour = "#7b5000"
    else:
        badge_bg = "#2e7d32"
        badge_fg = "#ffffff"   # contrast 5.1:1 ✓
        badge_label = "SECURITY REVIEW REQUIRED"
        heading_colour = "#1b5e20"

    sender = _esc(email.sender or "Unknown sender")
    subject = _esc(email.subject or "(No subject)")
    explanation_escaped = _esc(explanation)
    expires_str = expires_at.strftime("%d %b %Y at %H:%M UTC")

    release_url = (
        f"{_APP_BASE_URL}/api/v1/digest/action"
        f"?token={signed_token}&action=release"
    )
    confirm_url = (
        f"{_APP_BASE_URL}/api/v1/digest/action"
        f"?token={signed_token}&action=confirm"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PhishGuard Security Alert</title>
  <style>
    body {{
      font-family: system-ui, -apple-system, Segoe UI, Arial, sans-serif;
      font-size: 16px; line-height: 1.6; color: #222222;
      background-color: #f0f0f0; margin: 0; padding: 0;
    }}
    .wrapper {{ max-width: 600px; margin: 32px auto; padding: 0 16px; }}
    .card {{
      background: #ffffff; border-radius: 8px;
      border: 1px solid #dddddd; padding: 36px 40px;
    }}
    .logo {{
      font-size: 1.1rem; font-weight: 700; color: #1a237e;
      margin: 0 0 24px; letter-spacing: -0.01em;
    }}
    .badge {{
      display: inline-block; padding: 6px 14px; border-radius: 4px;
      background-color: {badge_bg}; color: {badge_fg};
      font-size: 0.78rem; font-weight: 700; letter-spacing: 0.06em;
      text-transform: uppercase; margin-bottom: 20px;
    }}
    h1 {{
      font-size: 1.3rem; color: {heading_colour};
      margin: 0 0 16px; font-weight: 700;
    }}
    .intro {{
      font-size: 0.95rem; color: #444444; margin: 0 0 24px;
    }}
    table.meta {{
      width: 100%; border-collapse: collapse; margin: 0 0 20px;
      font-size: 0.9rem;
    }}
    table.meta th {{
      text-align: left; padding: 5px 16px 5px 0;
      color: #555555; font-weight: 600;
      white-space: nowrap; vertical-align: top; width: 90px;
    }}
    table.meta td {{
      padding: 5px 0; color: #222222; word-break: break-word;
    }}
    .score {{ font-weight: 700; color: {badge_bg}; }}
    h2.section-heading {{
      font-size: 0.95rem; font-weight: 700; color: #333333;
      margin: 24px 0 8px;
    }}
    .explanation {{
      background-color: #f8f8f8;
      border-left: 4px solid {badge_bg};
      padding: 12px 16px; border-radius: 0 4px 4px 0;
      font-size: 0.93rem; color: #333333;
      margin: 0 0 28px;
    }}
    .actions-intro {{
      font-size: 0.9rem; color: #444444; margin: 0 0 16px;
    }}
    .btn {{
      display: inline-block; padding: 12px 22px;
      border-radius: 5px; font-size: 0.93rem; font-weight: 600;
      text-decoration: none; margin: 0 8px 8px 0;
      line-height: 1;
    }}
    .btn-release {{
      background-color: #1565c0; color: #ffffff;
    }}
    .btn-confirm {{
      background-color: #b71c1c; color: #ffffff;
    }}
    .expiry-notice {{
      font-size: 0.82rem; color: #666666; margin: 28px 0 0;
      padding-top: 20px; border-top: 1px solid #eeeeee;
    }}
    .footer {{
      font-size: 0.78rem; color: #888888;
      text-align: center; margin-top: 20px;
    }}
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="card" role="main">

      <p class="logo" aria-label="PhishGuard Security Platform">
        🛡 PhishGuard
      </p>

      <div class="badge"
           aria-label="Risk classification: {badge_label}">
        {badge_label}
      </div>

      <h1>Security Alert: Email Quarantined</h1>

      <p class="intro">
        An email addressed to you has been held in quarantine because our
        security system detected potential phishing indicators. Please review
        the details below and take action before the link expires.
      </p>

      <table class="meta" role="presentation"
             aria-label="Quarantined email details">
        <tr>
          <th scope="row">From</th>
          <td>{sender}</td>
        </tr>
        <tr>
          <th scope="row">Subject</th>
          <td>{subject}</td>
        </tr>
        <tr>
          <th scope="row">Risk Score</th>
          <td>
            <span class="score"
                  aria-label="Risk score: {risk_score} out of 100">
              {risk_score} / 100
            </span>
          </td>
        </tr>
      </table>

      <h2 class="section-heading">Why was this quarantined?</h2>
      <div class="explanation" role="note"
           aria-label="Security assessment explanation">
        {explanation_escaped}
      </div>

      <section aria-labelledby="action-heading">
        <h2 class="section-heading" id="action-heading">
          What would you like to do?
        </h2>
        <p class="actions-intro">
          If you were expecting this email and it is legitimate, click
          <strong>Release to Inbox</strong>. If it looks suspicious or
          unexpected, click <strong>Report Phishing</strong> to alert your
          security team.
        </p>
        <div role="group" aria-label="Action buttons">
          <a href="{release_url}"
             class="btn btn-release"
             role="button"
             aria-label="Release this email to your inbox — mark it as safe">
            ✓ Release to Inbox
          </a>
          <a href="{confirm_url}"
             class="btn btn-confirm"
             role="button"
             aria-label="Report this email as a phishing attempt">
            ✕ Report Phishing
          </a>
        </div>
      </section>

      <p class="expiry-notice" role="note">
        ⏱ These action links expire on
        <strong>{expires_str}</strong> (72 hours from when this notice was
        sent). After expiry, please contact your IT security team directly.
      </p>

    </div>
    <p class="footer">
      This security notice was generated by PhishGuard on behalf of your
      organisation. Do not forward this email — the action links are unique
      to you and will not work for anyone else.
    </p>
  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# build_help_request_html
# ---------------------------------------------------------------------------


def score_to_band(score: int) -> dict[str, str]:
    """Map a 0–100 risk score to its display band (label + badge colours).

    Thresholds mirror :func:`app.schemas.common.score_to_severity` and the
    frontend ``getRiskBand()`` helper — keep all three in sync.
    """
    if score <= 19:
        return {"label": "Safe", "color": "#16A34A", "bg": "#F0FDF4", "border": "#86EFAC"}
    if score <= 44:
        return {"label": "Low Risk", "color": "#65A30D", "bg": "#F7FEE7", "border": "#BEF264"}
    if score <= 64:
        return {"label": "Suspicious", "color": "#D97706", "bg": "#FFFBEB", "border": "#FDE68A"}
    if score <= 84:
        return {"label": "High Risk", "color": "#DC2626", "bg": "#FEF2F2", "border": "#FECACA"}
    return {"label": "Critical Threat", "color": "#7C3AED", "bg": "#F5F3FF", "border": "#C4B5FD"}


def build_help_request_html(
    recipient_name: str,
    requester_name: str,
    email: Any,           # Email ORM instance
    risk_score: int,
    band_label: str,
    note: str | None,
    deep_link: str,
) -> str:
    """Build the help-request notification email sent to workspace contributors.

    Args:
        recipient_name: Full name of the contributor being notified.
        requester_name: Full name of the user asking for help.
        email:          Email ORM row (reads ``sender``, ``subject``).
        risk_score:     0–100 risk score (0 when analysis is pending).
        band_label:     Display label for the risk band (e.g. "High Risk").
        note:           Optional message from the requester (block omitted if empty).
        deep_link:      Frontend URL that opens the email detail directly.

    Returns:
        Complete HTML string ready for the Resend ``html`` parameter.
    """
    sender = _esc(email.sender or "Unknown sender")
    subject = _esc(email.subject or "(No subject)")
    recipient = _esc(recipient_name)
    requester = _esc(requester_name)
    band = score_to_band(risk_score)

    note_section = ""
    if note and note.strip():
        note_section = f"""
        <div style="
          background:#EFF6FF;border-radius:8px;
          border:1px solid #BFDBFE;padding:14px 16px;
          margin-bottom:24px;
        ">
          <p style="font-size:12px;font-weight:600;color:#1D4ED8;
                    margin:0 0 6px">
            {requester}'s note:
          </p>
          <p style="font-size:14px;color:#1E40AF;
                    line-height:1.5;margin:0;font-style:italic">
            &quot;{_esc(note.strip())}&quot;
          </p>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PhishGuard Help Request</title>
</head>
<body style="
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  background:#F8FAFC;margin:0;padding:40px 20px;
">
  <div style="max-width:560px;margin:0 auto">

    <!-- Header -->
    <div style="text-align:center;margin-bottom:32px">
      <h1 style="font-size:24px;font-weight:700;
                 color:#4F46E5;margin:0">PhishGuard</h1>
      <p style="font-size:13px;color:#9CA3AF;margin:6px 0 0">
        Email Security Platform
      </p>
    </div>

    <!-- Card -->
    <div style="
      background:#ffffff;border-radius:14px;
      border:1px solid #E5E7EB;padding:32px;
      box-shadow:0 1px 3px rgba(0,0,0,0.06);
    " role="main">
      <h2 style="font-size:20px;font-weight:600;
                 color:#111827;margin:0 0 8px">
        Hi {recipient},
      </h2>
      <p style="font-size:15px;color:#374151;
                line-height:1.6;margin:0 0 24px">
        <strong>{requester}</strong> from your
        PhishGuard workspace has flagged an email and
        is asking for your analysis.
      </p>

      <!-- Email details table -->
      <div style="
        background:#F9FAFB;border-radius:10px;
        border:1px solid #E5E7EB;padding:16px;
        margin-bottom:24px;
      ">
        <p style="font-size:12px;font-weight:600;
                  color:#6B7280;text-transform:uppercase;
                  letter-spacing:0.05em;margin:0 0 12px">
          About the email
        </p>
        <table style="width:100%;border-collapse:collapse" role="presentation"
               aria-label="Email details">
          <tr>
            <td style="font-size:13px;color:#6B7280;
                       padding:6px 0;width:80px;
                       vertical-align:top">From</td>
            <td style="font-size:13px;color:#111827;
                       padding:6px 0;font-weight:500">
              {sender}
            </td>
          </tr>
          <tr>
            <td style="font-size:13px;color:#6B7280;
                       padding:6px 0;vertical-align:top">Subject</td>
            <td style="font-size:13px;color:#111827;
                       padding:6px 0;font-weight:500">
              {subject}
            </td>
          </tr>
          <tr>
            <td style="font-size:13px;color:#6B7280;
                       padding:6px 0">Risk</td>
            <td style="font-size:13px;padding:6px 0">
              <span style="
                background:{band['bg']};color:{band['color']};
                border:1px solid {band['border']};
                padding:2px 8px;border-radius:20px;
                font-size:12px;font-weight:600;
              ">
                {_esc(band_label)}
              </span>
              <span style="color:#9CA3AF;font-size:12px;
                            margin-left:6px">
                ({risk_score}/100)
              </span>
            </td>
          </tr>
        </table>
      </div>

      <!-- Note from requester (only if note provided) -->
      {note_section}

      <!-- CTA button -->
      <div style="text-align:center">
        <a href="{deep_link}" style="
          display:inline-block;background:#4F46E5;
          color:#ffffff;text-decoration:none;
          padding:13px 28px;border-radius:8px;
          font-size:15px;font-weight:600;
          font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
          letter-spacing:0.01em;
        " role="button"
           aria-label="View and analyse this email in PhishGuard">View and analyse this email &rarr;</a>
      </div>
    </div>

    <!-- Footer -->
    <div style="
      text-align:center;margin-top:24px;
      padding:0 16px;
    ">
      <p style="font-size:12px;color:#9CA3AF;
                line-height:1.6;margin:0">
        If you don't have a PhishGuard account,
        you'll be prompted to create one.<br>
        Ask <strong>{requester}</strong> to send
        you an invitation from workspace settings.
      </p>
      <p style="font-size:12px;color:#D1D5DB;margin:12px 0 0">
        — PhishGuard
      </p>
    </div>

  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# send_digest_email
# ---------------------------------------------------------------------------


async def send_digest_email(
    recipient: str,
    html: str,
    subject_prefix: str,
) -> bool:
    """Dispatch a digest HTML email via the Resend API.

    The synchronous Resend SDK call is wrapped in :func:`asyncio.to_thread`
    so the calling event loop is never blocked.

    Args:
        recipient:     Recipient email address string.
        html:          Fully rendered digest HTML from :func:`build_digest_html`.
        subject_prefix: Full email subject line (e.g.
                        ``"[PhishGuard] Quarantine Notice: Your invoice..."``)

    Returns:
        ``True`` when Resend accepts the message, ``False`` on any error.
        This function never raises — the caller decides whether to retry.
    """
    def _sync_send() -> bool:
        import resend  # noqa: PLC0415 — lazy import avoids startup cost

        resend.api_key = settings.RESEND_API_KEY
        resend.Emails.send(
            {
                "from": _FROM_ADDRESS,
                "to": [recipient],
                "subject": subject_prefix,
                "html": html,
            }
        )
        return True

    try:
        return await asyncio.to_thread(_sync_send)
    except Exception as exc:
        log.warning(
            "send_digest_email_failed",
            recipient=recipient,
            error=str(exc),
            exc_type=type(exc).__name__,
        )
        return False
