import sys
from app.core.config import get_settings
from app.domain.mailer import send_mail

s = get_settings()
r = send_mail(mode=s.mail_mode, to="saudnadaf09@gmail.com", subject="SentinelX SMTP test",
              body="Agar yeh mail mila to SMTP sahi chal raha hai.", sender=s.mail_from,
              outbox_dir=s.outbox_dir, smtp_host=s.smtp_host, smtp_port=587,
              smtp_user=s.smtp_user, smtp_password=s.smtp_password, smtp_starttls=s.smtp_starttls)
print(r)