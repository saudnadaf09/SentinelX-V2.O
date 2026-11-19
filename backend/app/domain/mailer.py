
"""Outgoing mail using Brevo API, SMTP, or console mode."""
from __future__ import annotations

import json
import logging
import smtplib
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from email.utils import parseaddr
from pathlib import Path

log = logging.getLogger("sentinelx.mail")


def send_mail(
    *,
    mode: str,
    to: str,
    subject: str,
    body: str,
    sender: str,
    outbox_dir: str,
    brevo_api_key: str = "",
    smtp_host: str = "",
    smtp_port: int = 587,
    smtp_user: str = "",
    smtp_password: str = "",
    smtp_starttls: bool = True,
) -> dict:

    if mode == "brevo":
        if not brevo_api_key:
            return {
                "delivered": False,
                "mode": "brevo",
                "error": "BREVO_API_KEY is not configured",
            }

        sender_name, sender_email = parseaddr(sender)
        if not sender_email:
            return {
                "delivered": False,
                "mode": "brevo",
                "error": "Invalid MAIL_FROM address",
            }

        payload = {
            "sender": {
                "name": sender_name or "SentinelX",
                "email": sender_email,
            },
            "to": [{"email": to}],
            "subject": subject,
            "textContent": body,
        }

        request = urllib.request.Request(
            "https://api.brevo.com/v3/smtp/email",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "accept": "application/json",
                "api-key": brevo_api_key,
                "content-type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                if response.status in (200, 201, 202):
                    log.info("Brevo accepted email")
                    return {"delivered": True, "mode": "brevo"}

                return {
                    "delivered": False,
                    "mode": "brevo",
                    "error": f"HTTP_{response.status}",
                }

        except urllib.error.HTTPError as exc:
            log.warning(
                "Brevo API rejected email",
                extra={"error": f"HTTP_{exc.code}"},
            )
            return {
                "delivered": False,
                "mode": "brevo",
                "error": f"HTTP_{exc.code}",
            }

        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.warning(
                "Brevo API connection failed",
                extra={"error": type(exc).__name__},
            )
            return {
                "delivered": False,
                "mode": "brevo",
                "error": type(exc).__name__,
            }

    if mode == "smtp":
        if not smtp_host:
            return {
                "delivered": False,
                "mode": "smtp",
                "error": "SMTP_HOST is not configured",
            }

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
            log.warning(
                "smtp delivery failed",
                extra={"error": type(exc).__name__},
            )
            return {
                "delivered": False,
                "mode": "smtp",
                "error": type(exc).__name__,
            }

    out = Path(outbox_dir)
    out.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() else "_" for c in to)[:40]
    path = out / f"{time.strftime('%Y%m%d-%H%M%S')}-{safe}.txt"

    path.write_text(
        f"[CONSOLE MAIL MODE - no real email was sent]\n"
        f"To: {to}\nSubject: {subject}\n\n{body}\n",
        encoding="utf-8",
    )

    log.warning("console mail written (not sent): %s", path)
    return {
        "delivered": False,
        "mode": "console",
        "outbox_file": str(path),
    }
