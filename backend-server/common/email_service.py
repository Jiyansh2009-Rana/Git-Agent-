import logging
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