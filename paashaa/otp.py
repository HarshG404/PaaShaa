"""One-time-password state machine (pure logic; no UI, no email)."""
from __future__ import annotations

import hmac
import secrets
import string
import time

from .config import OTP_MAX_TRIES, OTP_TTL


class OTPManager:
    def __init__(self, ttl: int = OTP_TTL, max_tries: int = OTP_MAX_TRIES, clock=time.time):
        self.ttl, self.max_tries, self._clock = ttl, max_tries, clock
        self._code, self._exp, self._tries = "", 0.0, 0

    def issue(self) -> str:
        self._code = "".join(secrets.choice(string.digits) for _ in range(6))
        self._exp, self._tries = self._clock() + self.ttl, 0
        return self._code

    def remaining(self) -> int:
        return max(0, int(self._exp - self._clock()))

    def verify(self, code: str) -> str:
        """Returns 'ok' | 'expired' | 'wrong' | 'locked'. Codes are single-use."""
        if not self._code or self._clock() > self._exp: return "expired"
        if self._tries >= self.max_tries: return "locked"
        self._tries += 1
        if hmac.compare_digest(code.strip(), self._code):
            self._code = ""
            return "ok"
        return "locked" if self._tries >= self.max_tries else "wrong"
