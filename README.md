# 🔐 PaaShaa

> A local desktop password vault that also **nags you to rotate passwords** — by email, on the schedule you choose.

![CI](https://github.com/HarshG404/PaaShaa/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features
- **Accounts:** sign-up (unique username, policy-checked password, app-password verification by OTP, captcha), password login, OTP login, forgot-password via OTP
- **Vault dashboard:** site, username, login email, sign-in method (email / OAuth), description, masked password, last-changed info; live search; edit / delete
- **OTP-gated secrets:** revealing a password requires an OTP (10-min validity, resend, 5-attempt limit)
- **Rotation reminders:** every N days / weeks / months / years (1 day = daily) at a chosen time; the email lists exactly which accounts (with login email) to change; per-site opt-in
- **Password policy:** ≥12 chars, upper, lower, digit, symbol — with a *Retry* / *Accept the risk* dialog
- **Suggester:** sentence-based or fully random passwords, custom length and character classes, "next suggestion"
- **Security audit:** finds weak, reused and stale passwords and gives a vault health score
- **Breach checks:** Have I Been Pwned email lookup (API key) and the free k-anonymity password check
- **Activity log:** audit trail of logins, reveals, edits, exports
- **Encrypted backups:** passphrase-protected `.psbak` export / import
- **Hardening:** scrypt, Fernet, parameterised SQL, TLS-only mail, lockout, auto-lock, clipboard auto-clear, optional OS-keyring key storage
- **Start on login** (Windows / Linux / macOS)

## Install
```bash
git clone https://github.com/HarshG404/PaaShaa.git
cd PaaShaa
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m paashaa
```
Linux may need Tk: `sudo apt install python3-tk`.

## Email setup
PaaShaa sends OTPs and reminders **from your own mailbox** using an *app password* (not your normal password).
Gmail: enable 2-Step Verification → Google Account → *App passwords*. Outlook, Yahoo, iCloud and Zoho are supported.

## Architecture
```
paashaa/
├── config.py      settings & paths (PAASHAA_HOME)      ├── otp.py        OTP state machine (pure)
├── crypto.py      scrypt, Fernet vault, sealed backups ├── scheduler.py  interval maths + reminder thread
├── db.py          SQLite layer + audit log             ├── analysis.py   vault health audit
├── policy.py      policy, entropy, generator           ├── breach.py     HIBP client
├── mailer.py      SMTP over TLS                        ├── backup.py     encrypted export/import
├── autostart.py   start-on-login                       └── gui/          Tkinter (dialogs.py, app.py)
tests/             pytest suite (no GUI / network needed)
```

## Development
```bash
pip install -r requirements-dev.txt
ruff check . && pytest
```

## Security
Read [SECURITY.md](SECURITY.md) for the threat model and known limitations. **PaaShaa has not been independently audited.**

## Roadmap
- [ ] Master-password-derived vault key (zero-knowledge mode)
- [ ] TOTP (authenticator app) as an alternative to email OTP
- [ ] Browser-extension autofill · CSV import from other managers · Packaged installers (PyInstaller)

## License
MIT — see [LICENSE](LICENSE).
