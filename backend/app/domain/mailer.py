"""Outgoing mail. 'console' mode writes to an outbox folder and the log - NO real email is sent.
'smtp' mode sends through your SMTP server. Delivery results are reported honestly."""
from __future__ import annotations

import logging
import smtplib
import time
from email.message import EmailMessage
from pathlib import Path

log = logging.getLogger("sentinelx.mail")


def send_mail(*, mode: str, to: str, subject: str, body: str, sender: str, 
              outbox_dir: str,
              smtp_host: str = "", smtp_port: int = 587, smtp_user: str = "", smtp_password: str = "",
              smtp_starttls: bool = True) -> dict:
    if mode == "smtp":
        if not smtp_host:
            return {"delivered": False, "mode": "smtp", "error": "SMTP_HOST is not configured"}
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = sender, to, subject
        msg.set_content(body)
        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as s:
                if smtp_starttls:
                    s.starttls()
                if smtp_user:
                    s.login(smtp_user, smtp_password)
                s.send_message(msg)
            return {"delivered": True, "mode": "smtp"}
        except (smtplib.SMTPException, OSError) as exc:
            log.warning("smtp delivery failed", extra={"error": type(exc).__name__})
            return {"delivered": False, "mode": "smtp", "error": type(exc).__name__}
    out = Path(outbox_dir)
    out.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() else "_" for c in to)[:40]
    path = out / f"{time.strftime('%Y%m%d-%H%M%S')}-{safe}.txt"
    path.write_text(f"[CONSOLE MAIL MODE - no real email was sent]\nTo: {to}\nSubject: {subject}\n\n{body}\n", encoding="utf-8")
    log.warning("console mail written (not sent): %s", path)
    return {"delivered": False, "mode": "console", "outbox_file": str(path)}
