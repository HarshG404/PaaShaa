"""SMTP over verified TLS (SMTPS 465 / STARTTLS 587)."""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

HOSTS = {"gmail.com": "smtp.gmail.com", "yahoo.com": "smtp.mail.yahoo.com",
         "icloud.com": "smtp.mail.me.com", "zoho.com": "smtp.zoho.com"}
STARTTLS_DOMAINS = {"outlook.com", "hotmail.com", "live.com"}


def send_mail(frm: str, app_password: str, to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = frm, to, subject
    msg.set_content(body)
    dom = frm.split("@")[-1].lower()
    ctx = ssl.create_default_context()
    if dom in STARTTLS_DOMAINS:
        with smtplib.SMTP("smtp-mail.outlook.com", 587, timeout=20) as s:
            s.starttls(context=ctx); s.login(frm, app_password); s.send_message(msg)
    else:
        with smtplib.SMTP_SSL(HOSTS.get(dom, "smtp." + dom), 465, context=ctx, timeout=20) as s:
            s.login(frm, app_password); s.send_message(msg)
