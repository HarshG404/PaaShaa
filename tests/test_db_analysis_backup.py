from datetime import datetime

import pytest

pytest.importorskip("cryptography")
from paashaa import analysis, backup  # noqa: E402
from paashaa.crypto import Vault  # noqa: E402
from paashaa.db import Database  # noqa: E402


@pytest.fixture()
def env(tmp_path):
    db = Database(str(tmp_path / "t.db")); v = Vault(str(tmp_path / "k"))
    uid = db.insert("INSERT INTO users(username,email,pw_hash) VALUES('u','u@x.com','h')")
    return db, v, uid


def add(db, v, uid, site, pw, when="2025-01-01 10:00"):
    db.insert("INSERT INTO entries(user_id,site,username,pw,changed_at,in_sched) VALUES(?,?,?,?,?,1)", (uid, site, "me", v.encrypt(pw), when))


def test_audit_log(env):
    db, _, uid = env; db.audit(uid, "login_ok", "x")
    assert db.q("SELECT event FROM audit WHERE user_id=?", (uid,))[0]["event"] == "login_ok"


def test_cascade_delete(env):
    db, v, uid = env; add(db, v, uid, "a.com", "Aa1!aaaaaaaa")
    db.q("DELETE FROM users WHERE id=?", (uid,), commit=True)
    assert db.q("SELECT COUNT(*) c FROM entries")[0]["c"] == 0


def test_sql_injection_is_inert(env):
    db, v, uid = env
    assert db.q("SELECT * FROM users WHERE username=?", ("' OR 1=1 --",)) == []


def test_analysis_flags_reuse_weak_and_old():
    items = [{"site": "a", "username": "x", "pw": "Same!Passw0rd1", "changed_at": "2024-01-01 00:00", "in_sched": 1},
             {"site": "b", "username": "x", "pw": "Same!Passw0rd1", "changed_at": "2025-06-01 00:00", "in_sched": 1},
             {"site": "c", "username": "x", "pw": "weak", "changed_at": "2025-06-01 00:00", "in_sched": 0}]
    score, f = analysis.analyze(items, now=datetime(2025, 6, 10))
    issues = {i["site"]: x for i, x in f}
    assert any("reused" in s for s in issues["a"]) and any("days" in s for s in issues["a"])
    assert any("policy" in s for s in issues["c"]) and any("reminder" in s for s in issues["c"])
    assert score == 0 and analysis.analyze([])[0] == 100


def test_backup_roundtrip_skips_duplicates(env, tmp_path):
    db, v, uid = env; add(db, v, uid, "a.com", "Aa1!aaaaaaaa"); f = str(tmp_path / "b.psbak")
    assert backup.export_entries(db, v, uid, f, "Backup!Pass123") == 1
    assert backup.import_entries(db, v, uid, f, "Backup!Pass123", "now") == 0          # duplicate
    db.q("DELETE FROM entries", commit=True)
    assert backup.import_entries(db, v, uid, f, "Backup!Pass123", "now") == 1
    assert v.decrypt(db.q("SELECT pw FROM entries")[0]["pw"]) == "Aa1!aaaaaaaa"
    with pytest.raises(ValueError):
        backup.import_entries(db, v, uid, f, "wrong", "now")
