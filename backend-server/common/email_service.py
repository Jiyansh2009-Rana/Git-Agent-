import logging
from typing import Optional
import smtplib
from email.message import EmailMessage
from core.config import (
    APP_NAME,
    SMTP_FROM_EMAIL,
    SMTP_FROM_NAME,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USER,
)

logger = logging.getLogger(__name__)


def send_otp_email(to_email: str, otp: str, purpose: str) -> None:
    """Sends signup or password-reset OTP via SMTP."""
    if not SMTP_USER or not SMTP_PASSWORD:
        raise RuntimeError("SMTP credentials are not configured.")

    subjects = {
        "signup": f"{APP_NAME}: Verify your email address",
        "reset": f"{APP_NAME}: Password reset verification code",
    }
    subject = subjects.get(purpose, f"{APP_NAME}: Your verification code")

    text_body = (
        f"Your {APP_NAME} verification code is: {otp}\n"
        f"This code expires in 5 minutes. Do not share it with anyone."
    )
    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; background:#f4f4f5; padding:32px;">
        <div style="max-width:480px; margin:0 auto; background:#fff; border-radius:10px; padding:32px; text-align:center;">
          <h2 style="margin-top:0; color:#111827;">{APP_NAME}</h2>
          <p style="color:#374151;">Use the verification code below (valid for <strong>5 minutes</strong>):</p>
          <div style="margin:24px auto; padding:14px 20px; background:#f3f4f6; border-radius:8px; font-size:32px; font-weight:bold; letter-spacing:8px; color:#111827; max-width:240px;">
            {otp}
          </div>
          <p style="font-size:12px; color:#6b7280;">If you did not request this, you can safely ignore this email.</p>
        </div>
      </body>
    </html>
    """

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    msg["To"] = to_email
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)


def _send_email(to_email: str, subject: str, text_body: str, html_body: str) -> bool:
    if not SMTP_USER or not SMTP_PASSWORD:
        logger.warning("SMTP credentials not configured. Skipping email dispatch.")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    msg["To"] = to_email
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as exc:
        logger.error(f"Failed to send email to {to_email}: {exc}")
        return False


def send_account_disabled_email(to_email: str, username: Optional[str], reason: str) -> bool:
    """TRD §5: Notifies a user when an Admin disables their account."""
    display_name = username or to_email.split("@")[0]
    subject = f"{APP_NAME}: Your account has been disabled"
    text_body = (
        f"Hi {display_name},\n\n"
        f"Your {APP_NAME} account has been disabled by an administrator.\n"
        f"Reason: {reason}\n\n"
        f"If you believe this is a mistake, please contact your administrator."
    )
    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; background:#f4f4f5; padding:32px;">
        <div style="max-width:520px; margin:0 auto; background:#fff; border-radius:10px; padding:32px;">
          <h2 style="margin-top:0; color:#dc2626;">Account Disabled</h2>
          <p style="color:#374151;">Hi <strong>{display_name}</strong>,</p>
          <p style="color:#374151;">Your <strong>{APP_NAME}</strong> account has been disabled by an administrator.</p>
          <div style="margin:20px 0; padding:14px; background:#fef2f2; border-left:4px solid #dc2626; border-radius:6px;">
            <strong>Reason:</strong> {reason}
          </div>
          <p style="font-size:12px; color:#6b7280;">Active sessions have been revoked. Contact an administrator to request reactivation.</p>
        </div>
      </body>
    </html>
    """
    return _send_email(to_email, subject, text_body, html_body)


def send_repo_deleted_email(to_email: str, repo_url: str, reason: str) -> bool:
    """TRD §5: Notifies the uploader when an Admin deletes a repository with a mandatory reason."""
    subject = f"{APP_NAME}: Repository removed by administrator"
    text_body = (
        f"Your ingested repository ({repo_url}) has been deleted by an administrator.\n"
        f"Reason: {reason}\n\n"
        f"All indexed chunks and registry entries for this repository have been removed."
    )
    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; background:#f4f4f5; padding:32px;">
        <div style="max-width:520px; margin:0 auto; background:#fff; border-radius:10px; padding:32px;">
          <h2 style="margin-top:0; color:#dc2626;">Repository Removed</h2>
          <p style="color:#374151;">Your repository <strong>{repo_url}</strong> has been deleted from <strong>{APP_NAME}</strong> by an administrator.</p>
          <div style="margin:20px 0; padding:14px; background:#fef2f2; border-left:4px solid #dc2626; border-radius:6px;">
            <strong>Reason:</strong> {reason}
          </div>
          <p style="font-size:12px; color:#6b7280;">All chunks and embeddings for this repository have been removed. Existing chat history remains readable.</p>
        </div>
      </body>
    </html>
    """
    return _send_email(to_email, subject, text_body, html_body)