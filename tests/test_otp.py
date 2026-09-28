from paashaa.otp import OTPManager


class Clock:
    t = 1000.0
    def __call__(self): return self.t


def test_ok_and_single_use():
    c = Clock(); m = OTPManager(clock=c); code = m.issue()
    assert m.verify(code) == "ok"
    assert m.verify(code) == "expired"          # single use


def test_expiry_after_ten_minutes():
    c = Clock(); m = OTPManager(clock=c); code = m.issue()
    c.t += 601
    assert m.verify(code) == "expired" and m.remaining() == 0


def test_locks_after_max_tries():
    m = OTPManager(max_tries=3, clock=Clock()); code = m.issue()
    bad = "000000" if code != "000000" else "111111"
    assert [m.verify(bad) for _ in range(3)] == ["wrong", "wrong", "locked"]
    assert m.verify(code) == "locked"


def test_reissue_resets_state():
    m = OTPManager(max_tries=2, clock=Clock()); m.issue(); m.verify("x")
    assert m.verify(m.issue()) == "ok"
