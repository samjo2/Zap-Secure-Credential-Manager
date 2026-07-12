import smtplib
from email.message import EmailMessage

from flask import current_app


def send_reset_link(recipient: str, link: str):
    """Emails the reset link when SMTP is configured; otherwise logs it so
    local single-user setups still have a working reset path."""
    cfg = current_app.config
    if not cfg.get("SMTP_HOST"):
        current_app.logger.info("Password reset link for %s: %s", recipient, link)
        return
    msg = EmailMessage()
    msg["Subject"] = "Zap password reset"
    msg["From"] = cfg["SMTP_SENDER"]
    msg["To"] = recipient
    msg.set_content(
        "A password reset was requested for your Zap account.\n\n"
        f"Reset link (expires in {cfg['RESET_TOKEN_MINUTES']} minutes): {link}\n\n"
        "Resetting without your current master password permanently erases "
        "your stored credentials. If you did not request this, ignore this email."
    )
    with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"]) as smtp:
        smtp.starttls()
        if cfg.get("SMTP_USERNAME"):
            smtp.login(cfg["SMTP_USERNAME"], cfg["SMTP_PASSWORD"])
        smtp.send_message(msg)
