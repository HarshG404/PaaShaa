from datetime import datetime

import pytest

from paashaa.scheduler import add_months, build_reminder, calc_next


def test_add_months_clamps_month_end():
    assert add_months(datetime(2025, 1, 31), 1) == datetime(2025, 2, 28)
    assert add_months(datetime(2024, 1, 31), 1) == datetime(2024, 2, 29)
    assert add_months(datetime(2025, 11, 15), 3) == datetime(2026, 2, 15)


@pytest.mark.parametrize("unit,n,expected", [
    ("days", 1, datetime(2025, 1, 2, 9, 30)), ("weeks", 2, datetime(2025, 1, 15, 9, 30)),
    ("months", 1, datetime(2025, 2, 1, 9, 30)), ("years", 1, datetime(2026, 1, 1, 9, 30))])
def test_calc_next(unit, n, expected):
    assert calc_next(n, unit, "09:30", datetime(2025, 1, 1, 17, 45)) == expected


def test_calc_next_bad_unit():
    with pytest.raises(ValueError):
        calc_next(1, "fortnights", "09:00")


def test_reminder_lists_accounts_and_no_passwords():
    rows = [{"site": "github.com", "username": "me", "login_email": "me@x.com", "changed_at": "2025-01-01 10:00"}]
    body = build_reminder("alice", rows)
    assert "github.com" in body and "me@x.com" in body and "alice" in body
