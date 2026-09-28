# Security Policy

## Reporting a vulnerability
Please **do not open a public issue**. Use GitHub's *Report a vulnerability* button (Security tab)
or email the maintainer. Expect an acknowledgement within 72 hours.

## Threat model
| Protects against | Mechanism |
|---|---|
| Stolen `vault.db` alone | Site passwords and app passwords are Fernet-encrypted; key is stored separately |
| Offline guessing of account passwords | scrypt (N=2^14, r=8, p=1), per-user random salt |
| Online brute force | 5-failure lockout, artificial delay, OTP single-use + attempt limit |
| SQL injection | Parameterised queries only (tested) |
| Network eavesdropping | Verified TLS for SMTP and HIBP |
| Shoulder-surfing / idle PC | Auto-lock (5 min), clipboard auto-clear (30 s), OTP to reveal passwords |
| Passwords in reminder mail | Never included |

## Known limitations (be honest with users)
- **Not independently audited.** Do not treat it as a replacement for a mature password manager.
- The vault key sits next to the DB (`secret.key`, mode 0600) unless `PAASHAA_USE_KEYRING=1`.
  Malware running as your user, or a full-disk copy of `~/.paashaa`, defeats encryption.
  This trade-off keeps "forgot password" recovery possible without data loss.
- OTP delivery relies on the security of your email account and app password.
- Python cannot reliably wipe secrets from memory.
