"""Reusable modal dialogs: forms, OTP, policy warning, captcha."""
from __future__ import annotations

import random
import secrets
import tkinter as tk
from tkinter import messagebox, ttk

from .. import APP
from ..mailer import send_mail
from ..otp import OTPManager
from ..policy import missing

_R = random.SystemRandom()
SECRET_KEYS = {"pw", "npw", "cpw", "old", "app", "pass"}

try:
    from PIL import Image, ImageTk
except ImportError:  # Pillow optional
    Image = None


def modal(parent, title: str) -> tk.Toplevel:
    d = tk.Toplevel(parent)
    d.title(title); d.transient(parent); d.resizable(False, False); d.configure(bg="#f4f6fb"); d.grab_set()
    return d


def pwfield(parent, row: int, label: str) -> ttk.Entry:
    ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=5, padx=4)
    e = ttk.Entry(parent, show="•", width=32)
    e.grid(row=row, column=1, pady=5)
    v = tk.BooleanVar()
    ttk.Checkbutton(parent, text="Show", variable=v,
                    command=lambda: e.config(show="" if v.get() else "•")).grid(row=row, column=2, padx=4)
    return e


def form(parent, title: str, fields, note: str = ""):
    """fields: (label, key, secret). Returns dict of values, or None if cancelled."""
    d = modal(parent, title)
    f = ttk.Frame(d, padding=18); f.pack()
    res: dict = {}; ents: dict = {}; r = 0
    if note:
        ttk.Label(f, text=note, wraplength=380).grid(row=0, column=0, columnspan=3, pady=(0, 8)); r = 1
    for lab, key, sec in fields:
        if sec:
            ents[key] = pwfield(f, r, lab)
        else:
            ttk.Label(f, text=lab).grid(row=r, column=0, sticky="w", pady=5, padx=4)
            ents[key] = ttk.Entry(f, width=32); ents[key].grid(row=r, column=1, pady=5)
        r += 1

    def ok():
        res.update({k: (e.get() if k in SECRET_KEYS else e.get().strip()) for k, e in ents.items()})
        d.destroy()

    bf = ttk.Frame(f); bf.grid(row=r, column=0, columnspan=3, pady=(10, 0))
    ttk.Button(bf, text="Continue", command=ok).pack(side="left", padx=5)
    ttk.Button(bf, text="Cancel", command=d.destroy).pack(side="left", padx=5)
    parent.wait_window(d)
    return res or None


def ask_otp(parent, to: str, frm: str, app_pw: str, purpose: str = "verification") -> bool:
    """Email an OTP and block until verified/cancelled."""
    mgr = OTPManager(); done = {"ok": False}

    def send() -> bool:
        code = mgr.issue()
        try:
            parent.config(cursor="watch"); parent.update()
            send_mail(frm, app_pw, to, f"{APP} OTP",
                      f"Your {APP} OTP for {purpose} is {code}.\nIt is valid for 10 minutes. "
                      "If you did not request it, ignore this email.")
            return True
        except Exception as e:
            messagebox.showerror(APP, f"Could not send OTP email:\n{e}", parent=parent)
            return False
        finally:
            parent.config(cursor="")

    if not send():
        return False
    d = modal(parent, "Enter OTP")
    f = ttk.Frame(d, padding=20); f.pack()
    ttk.Label(f, text=f"An OTP was sent to\n{to}", justify="center").pack()
    e = ttk.Entry(f, width=12, font=("Segoe UI", 16), justify="center"); e.pack(pady=10); e.focus()
    tl = ttk.Label(f, text=""); tl.pack()

    def tick():
        if not d.winfo_exists(): return
        left = mgr.remaining()
        tl.config(text=f"Valid for {left // 60:02d}:{left % 60:02d}" if left else "OTP expired - resend")
        d.after(1000, tick)

    def verify():
        r = mgr.verify(e.get())
        if r == "ok": done["ok"] = True; d.destroy()
        elif r == "expired": messagebox.showerror(APP, "OTP expired. Please resend.", parent=d)
        elif r == "locked": messagebox.showerror(APP, "Too many wrong attempts. Resend a new OTP.", parent=d)
        else: messagebox.showerror(APP, "Incorrect OTP.", parent=d)

    def resend():
        if send():
            e.delete(0, "end"); messagebox.showinfo(APP, "A new OTP has been sent.", parent=d)

    ttk.Button(f, text="Verify OTP", command=verify).pack(pady=(8, 2))
    ttk.Button(f, text="Resend OTP", command=resend).pack(pady=2)
    ttk.Button(f, text="Didn't receive it? Send again", command=resend).pack(pady=2)
    tick(); parent.wait_window(d)
    return done["ok"]


def policy_ok(parent, pw: str) -> bool:
    """True if compliant, or the user explicitly accepts the risk."""
    m = missing(pw)
    if not m: return True
    d = modal(parent, "Weak password")
    f = ttk.Frame(d, padding=20); f.pack(); res = {"v": False}
    ttk.Label(f, text="This password does not meet the policy. Missing:", font=("Segoe UI", 10, "bold")).pack(anchor="w")
    for x in m: ttk.Label(f, text="  ✗ " + x, foreground="#b91c1c").pack(anchor="w")
    bf = ttk.Frame(f); bf.pack(pady=(14, 0))
    ttk.Button(bf, text="Retry another password", command=d.destroy).pack(side="left", padx=6)

    def risk(): res["v"] = True; d.destroy()

    ttk.Button(bf, text="Accept the risk", command=risk).pack(side="left", padx=6)
    parent.wait_window(d)
    return res["v"]


def captcha(parent) -> bool:
    d = modal(parent, "Captcha")
    f = ttk.Frame(d, padding=18); f.pack(); st = {"code": "", "ok": False}
    cv = tk.Canvas(f, width=220, height=70, bg="white", highlightthickness=1); cv.pack()

    def draw():
        cv.delete("all")
        st["code"] = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(6))
        for _ in range(9):
            cv.create_line(_R.randint(0, 220), _R.randint(0, 70), _R.randint(0, 220), _R.randint(0, 70),
                           fill=_R.choice(["#94a3b8", "#fca5a5", "#93c5fd"]))
        for i, ch in enumerate(st["code"]):
            cv.create_text(25 + i * 34, 35 + _R.randint(-10, 10), text=ch, font=("Courier", _R.randint(20, 28), "bold"),
                           fill=_R.choice(["#1e293b", "#7c3aed", "#0f766e", "#b45309"]))

    e = ttk.Entry(f, width=14, font=("Segoe UI", 13)); e.pack(pady=8)

    def chk():
        if e.get().strip().upper() == st["code"]: st["ok"] = True; d.destroy()
        else: messagebox.showerror(APP, "Wrong captcha.", parent=d); draw(); e.delete(0, "end")

    ttk.Button(f, text="Verify", command=chk).pack(side="left", padx=4)
    ttk.Button(f, text="Refresh", command=draw).pack(side="left", padx=4)
    draw(); parent.wait_window(d)
    return st["ok"]


def load_photo(path: str, size: int = 110):
    try:
        if Image:
            im = Image.open(path).convert("RGBA"); im.thumbnail((size, size))
            return ImageTk.PhotoImage(im)
        return tk.PhotoImage(file=path)
    except Exception:
        return None
