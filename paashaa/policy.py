"""Password policy, strength estimation and generation."""
from __future__ import annotations

import math
import random
import re
import string

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
LEET = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}
_R = random.SystemRandom()


def missing(p: str) -> list[str]:
    """Return the policy rules the password violates (empty list = compliant)."""
    m = []
    if len(p) < 12: m.append(f"Minimum length of 12 characters (currently {len(p)})")
    if not re.search(r"[A-Z]", p): m.append("A capital letter")
    if not re.search(r"[a-z]", p): m.append("A small letter")
    if not re.search(r"\d", p): m.append("A number")
    if not re.search(r"[^A-Za-z0-9]", p): m.append("A symbol")
    return m


def entropy_bits(p: str) -> float:
    pool = sum(n for n, rx in ((26, r"[a-z]"), (26, r"[A-Z]"), (10, r"\d"), (32, r"[^A-Za-z0-9]")) if re.search(rx, p))
    return len(p) * math.log2(pool) if pool else 0.0


def strength_label(p: str) -> str:
    b = entropy_bits(p)
    return "Very weak" if b < 40 else "Weak" if b < 60 else "Fair" if b < 80 else "Strong" if b < 100 else "Excellent"


def generate(length: int = 16, up=True, low=True, num=True, sym=True, sentence: str = "") -> str:
    """Random password; optionally seeded from a sentence (leet-speak + random padding)."""
    length = max(4, length)
    pools = [p for on, p in ((up, string.ascii_uppercase), (low, string.ascii_lowercase),
                             (num, string.digits), (sym, SYMBOLS)) if on] or [string.ascii_letters]
    allc = "".join(pools)
    base: list[str] = []
    for w in re.findall(r"[A-Za-z0-9]+", sentence):
        for ch in w:
            if ch.lower() in LEET and _R.random() < .4: ch = LEET[ch.lower()]
            elif ch.isalpha(): ch = ch.upper() if _R.random() < .5 else ch.lower()
            base.append(ch)
        if _R.random() < .5: base.append(_R.choice(SYMBOLS + string.digits))
    base = [c if c in allc else _R.choice(allc) for c in base][:length]
    while len(base) < length: base.append(_R.choice(allc))
    # guarantee every enabled class, never overwriting the sole char of another class
    def pool_of(c): return next(i for i, pl in enumerate(pools) if c in pl)
    for pl in pools:
        if any(c in pl for c in base): continue
        counts = [sum(1 for c in base if c in q) for q in pools]
        spots = [i for i, c in enumerate(base) if counts[pool_of(c)] > 1]
        if spots: base[_R.choice(spots)] = _R.choice(pl)
    return "".join(base)
