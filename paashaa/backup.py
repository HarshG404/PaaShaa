"""Encrypted, portable backups (.psbak)."""
from __future__ import annotations

import json

from .crypto import seal, unseal

FIELDS = ("site", "username", "login_email", "method", "descr", "in_sched")


def export_entries(db, vault, user_id: int, path: str, passphrase: str) -> int:
    rows = db.q("SELECT * FROM entries WHERE user_id=?", (user_id,))
    data = [{**{k: r[k] for k in FIELDS}, "pw": vault.decrypt(r["pw"])} for r in rows]
    with open(path, "wb") as f:
        f.write(seal(json.dumps(data).encode(), passphrase))
    return len(data)


def import_entries(db, vault, user_id: int, path: str, passphrase: str, now: str) -> int:
    with open(path, "rb") as f:
        data = json.loads(unseal(f.read(), passphrase))
    added = 0
    for e in data:
        if db.q("SELECT 1 FROM entries WHERE user_id=? AND site=? AND username=?",
                (user_id, e["site"], e.get("username")), one=True):
            continue
        db.insert("INSERT INTO entries(user_id,site,username,login_email,method,descr,pw,changed_info,changed_at,in_sched)"
                  " VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (user_id, e["site"], e.get("username"), e.get("login_email"), e.get("method"), e.get("descr"),
                   vault.encrypt(e["pw"]), "Imported from backup", now, int(e.get("in_sched", 1))))
        added += 1
    return added
