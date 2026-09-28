"""Reminder scheduling + background thread."""
from __future__ import annotations

import calendar
import json
import logging
import threading
from datetime import datetime, timedelta

from .config import SCHEDULER_POLL_SECS
from .mailer import send_mail

log = logging.getLogger(__name__)
UNITS = ("days", "weeks", "months", "years")


def add_months(d: datetime, n: int) -> datetime:
    y, m = divmod(d.month - 1 + n, 12)
    y, m = y + d.year, m + 1
    return d.replace(year=y, month=m, day=min(d.day, calendar.monthrange(y, m)[1]))


def calc_next(n: int, unit: str, hhmm: str, base: datetime | None = None) -> datetime:
    base = base or datetime.now()
    if unit == "days": d = base + timedelta(days=n)
    elif unit == "weeks": d = base + timedelta(weeks=n)
    elif unit == "months": d = add_months(base, n)
    elif unit == "years": d = add_months(base, 12 * n)
    else: raise ValueError(f"unknown unit {unit!r}")
    h, m = map(int, hhmm.split(":"))
    return d.replace(hour=h, minute=m, second=0, microsecond=0)


def build_reminder(username: str, rows) -> str:
    lines = [f"{i}. {r['site']}  |  username: {r['username']}  |  login email: {r['login_email']}  |  last changed: {r['changed_at']}"
             for i, r in enumerate(rows, 1)]
    return (f"Hello {username},\n\nIt is time to change the passwords of these accounts:\n\n" + "\n".join(lines) +
            "\n\nOpen PaaShaa to update them.\n(Passwords are never included in this email.)")


def send_reminder(db, vault, user) -> bool:
    rows = db.q("SELECT * FROM entries WHERE user_id=? AND in_sched=1", (user["id"],))
    if not rows:
        return False
    send_mail(user["email"], vault.decrypt(user["app_pw"]), user["email"],
              "PaaShaa: time to change your passwords", build_reminder(user["username"], rows))
    db.audit(user["id"], "reminder_sent", f"{len(rows)} accounts")
    return True


class ReminderScheduler(threading.Thread):
    """Runs a check immediately on start, then every SCHEDULER_POLL_SECS."""

    def __init__(self, db, vault, poll: int = SCHEDULER_POLL_SECS):
        super().__init__(daemon=True, name="paashaa-scheduler")
        self.db, self.vault, self.poll, self._stop_evt = db, vault, poll, threading.Event()

    def tick(self) -> None:
        for u in self.db.q("SELECT * FROM users WHERE next_due IS NOT NULL"):
            if datetime.fromisoformat(u["next_due"]) > datetime.now():
                continue
            try:
                send_reminder(self.db, self.vault, u)
                s = json.loads(u["sched"])
                nxt = calc_next(s["n"], s["unit"], s["time"])
            except Exception:
                log.exception("reminder failed for user %s; retrying in 1h", u["id"])
                nxt = datetime.now() + timedelta(hours=1)
            self.db.q("UPDATE users SET next_due=? WHERE id=?", (nxt.isoformat(), u["id"]), commit=True)

    def run(self) -> None:
        while True:
            try: self.tick()
            except Exception: log.exception("scheduler tick failed")
            if self._stop_evt.wait(self.poll): break

    def stop(self) -> None:
        self._stop_evt.set()
