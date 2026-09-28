"""Vault health audit: weak, reused and stale passwords."""
from __future__ import annotations

from collections import Counter
from datetime import datetime

from .config import PASSWORD_MAX_AGE_DAYS
from .policy import missing


def analyze(items: list[dict], now: datetime | None = None):
    """items: dicts with site, username, pw (plaintext), changed_at, in_sched.
    Returns (score 0-100, [(item, [issues])])."""
    now = now or datetime.now()
    counts = Counter(i["pw"] for i in items)
    findings = []
    for i in items:
        issues = []
        if missing(i["pw"]): issues.append("does not meet the password policy")
        if counts[i["pw"]] > 1: issues.append(f"reused on {counts[i['pw']]} accounts")
        try:
            age = (now - datetime.strptime(i["changed_at"], "%Y-%m-%d %H:%M")).days
            if age > PASSWORD_MAX_AGE_DAYS: issues.append(f"not changed for {age} days")
        except (TypeError, ValueError):
            pass
        if not i.get("in_sched"): issues.append("not in reminder emails")
        findings.append((i, issues))
    score = round(100 * sum(1 for _, x in findings if not x) / len(findings)) if findings else 100
    return score, findings
