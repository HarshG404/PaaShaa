"""HaveIBeenPwned client (TLS-verified)."""
from __future__ import annotations

import hashlib
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

_CTX = ssl.create_default_context()
UA = "PaaShaa"


def check_email(email: str, api_key: str) -> dict:
    """-> {'status': 'clean'|'pwned'|'bad_key'|'limited'|'error', 'breaches': [...]}"""
    url = "https://haveibeenpwned.com/api/v3/breachedaccount/" + urllib.parse.quote(email) + "?truncateResponse=false"
    req = urllib.request.Request(url, headers={"hibp-api-key": api_key, "user-agent": UA})
    try:
        data = json.load(urllib.request.urlopen(req, timeout=15, context=_CTX))
        return {"status": "pwned", "breaches": data}
    except urllib.error.HTTPError as e:
        status = {404: "clean", 401: "bad_key", 429: "limited"}.get(e.code, "error")
        return {"status": status, "breaches": [], "code": e.code}
    except Exception as e:
        return {"status": "error", "breaches": [], "error": str(e)}


def pwned_count(password: str) -> int:
    """k-anonymity range query: only the first 5 hash chars leave the machine."""
    h = hashlib.sha1(password.encode()).hexdigest().upper()
    req = urllib.request.Request("https://api.pwnedpasswords.com/range/" + h[:5], headers={"user-agent": UA})
    text = urllib.request.urlopen(req, timeout=15, context=_CTX).read().decode()
    for line in text.splitlines():
        suffix, _, n = line.partition(":")
        if suffix == h[5:]:
            return int(n)
    return 0
