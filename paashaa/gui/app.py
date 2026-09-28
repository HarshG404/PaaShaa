"""PaaShaa main window: auth screens, dashboard, scheduler, tools, profile."""
from __future__ import annotations

import json
import os
import re
import shutil
import time
import tkinter as tk
import webbrowser
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

from .. import APP, __version__, analysis, autostart, backup, breach, policy
from ..config import AUTOLOCK_SECS, CLIPBOARD_CLEAR_SECS, DB_PATH, HOME, KEY_PATH, LOCKOUT_SECS, MAX_LOGIN_FAILS, USE_KEYRING
from ..crypto import Vault, hash_password, verify_password
from ..db import Database
from ..scheduler import UNITS, ReminderScheduler, calc_next, send_reminder
from .dialogs import ask_otp, captcha, form, load_photo, modal, policy_ok, pwfield

BG, SIDE = "#f4f6fb", "#1e293b"
METHODS = ["Email + Password", "Google OAuth", "Facebook OAuth", "GitHub OAuth", "Microsoft OAuth", "Apple OAuth", "Other"]
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USER_RE = re.compile(r"[A-Za-z0-9_.-]{3,32}")
now_s = lambda: datetime.now().strftime("%Y-%m-%d %H:%M")  # noqa: E731


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP} v{__version__} - Password Vault"); self.geometry("1180x720"); self.minsize(1020, 640)
        self.configure(bg=BG)
        self.db = Database(DB_PATH); self.vault = Vault(KEY_PATH, USE_KEYRING); self.q = self.db.q
        self.user = None; self.fails: dict = {}; self.photo = None; self.last_active = time.time()
        s = ttk.Style(); s.theme_use("clam")
        s.configure("TFrame", background=BG); s.configure("TLabel", background=BG, font=("Segoe UI", 10))
        s.configure("TCheckbutton", background=BG); s.configure("TRadiobutton", background=BG)
        s.configure("TButton", padding=6, font=("Segoe UI", 10)); s.configure("Treeview", rowheight=26)
        s.configure("H.TLabel", font=("Segoe UI", 20, "bold"), foreground="#1e293b")
        ReminderScheduler(self.db, self.vault).start()
        for ev in ("<Key>", "<Button>", "<Motion>"): self.bind_all(ev, self._touch, add="+")
        self.after(10_000, self._autolock)
        self.home()

    # ------------------------------------------------------------ helpers
    def _touch(self, _e=None): self.last_active = time.time()

    def _autolock(self):
        if self.user and time.time() - self.last_active > AUTOLOCK_SECS:
            self.db.audit(self.user["id"], "autolock"); self.logout(); messagebox.showinfo(APP, "Locked due to inactivity.")
        self.after(10_000, self._autolock)

    def clear(self, w=None):
        for c in (w or self).winfo_children(): c.destroy()

    def card(self):
        self.clear(); c = ttk.Frame(self, padding=30); c.place(relx=.5, rely=.5, anchor="center"); return c

    def reload(self): self.user = self.q("SELECT * FROM users WHERE id=?", (self.user["id"],), one=True)
    def uid(self): return self.user["id"]

    def otp_main(self, purpose: str) -> bool:
        u = self.user
        return ask_otp(self, u["email"], u["email"], self.vault.decrypt(u["app_pw"]), purpose)

    def copy_clip(self, text: str):
        self.clipboard_clear(); self.clipboard_append(text)
        self.after(CLIPBOARD_CLEAR_SECS * 1000, self.clipboard_clear)

    # ------------------------------------------------------------ auth
    def home(self):
        c = self.card()
        ttk.Label(c, text="🔐 PaaShaa", style="H.TLabel").pack(pady=(0, 4))
        ttk.Label(c, text="All your passwords. One vault. Timely reminders.").pack(pady=(0, 20))
        ttk.Button(c, text="Sign In", width=26, command=self.login_page).pack(pady=5)
        ttk.Button(c, text="Sign Up", width=26, command=self.signup_page).pack(pady=5)

    def find_user(self, ident: str):
        return self.q("SELECT * FROM users WHERE username=? OR lower(email)=?", (ident, ident.lower()), one=True)

    def login_page(self):
        c = self.card(); ttk.Label(c, text="Sign In", style="H.TLabel").grid(row=0, column=0, columnspan=3, pady=(0, 14))
        ttk.Label(c, text="Username / Email").grid(row=1, column=0, sticky="w", pady=5)
        ident = ttk.Entry(c, width=32); ident.grid(row=1, column=1, pady=5); ident.focus()
        pw = pwfield(c, 2, "Password")
        ttk.Button(c, text="Login", command=lambda: self.do_login(ident.get(), pw.get())).grid(row=3, column=0, columnspan=3, pady=(12, 4))
        ttk.Button(c, text="Login with OTP", command=lambda: self.otp_login(ident.get())).grid(row=4, column=0, columnspan=3, pady=2)
        ttk.Button(c, text="Forgot password?", command=lambda: self.forgot(ident.get())).grid(row=5, column=0, columnspan=3, pady=2)
        ttk.Button(c, text="← Back", command=self.home).grid(row=6, column=0, columnspan=3, pady=(8, 0))
        self.bind("<Return>", lambda e: self.do_login(ident.get(), pw.get()) if ident.winfo_exists() else None)

    def do_login(self, ident: str, pw: str):
        k = ident.strip().lower(); c, until = self.fails.get(k, (0, 0))
        if time.time() < until:
            return messagebox.showwarning(APP, f"Too many attempts. Try again in {int(until - time.time())}s.")
        u = self.find_user(ident.strip()); time.sleep(.4)
        if u and verify_password(pw, u["pw_hash"]):
            self.fails.pop(k, None); self.user = u; self.unbind("<Return>")
            self.db.audit(u["id"], "login_ok"); self.shell()
        else:
            c += 1; self.fails[k] = (0, time.time() + LOCKOUT_SECS) if c >= MAX_LOGIN_FAILS else (c, 0)
            if u: self.db.audit(u["id"], "login_fail", f"attempt {c}")
            messagebox.showerror(APP, "Invalid username/email or password.")

    def otp_login(self, ident: str):
        u = self.find_user(ident.strip())
        if not u: return messagebox.showerror(APP, "Enter your username or email first.")
        if ask_otp(self, u["email"], u["email"], self.vault.decrypt(u["app_pw"]), "login"):
            self.user = u; self.db.audit(u["id"], "login_otp"); self.shell()

    def forgot(self, ident: str):
        u = self.find_user(ident.strip())
        if not u: return messagebox.showerror(APP, "Enter your username or email first.")
        if not ask_otp(self, u["email"], u["email"], self.vault.decrypt(u["app_pw"]), "password reset"): return
        while True:
            r = form(self, "Reset password", [("New password", "npw", True), ("Confirm password", "cpw", True)])
            if not r: return
            if r["npw"] != r["cpw"]: messagebox.showerror(APP, "Passwords do not match."); continue
            if policy_ok(self, r["npw"]): break
        self.q("UPDATE users SET pw_hash=? WHERE id=?", (hash_password(r["npw"]), u["id"]), commit=True)
        self.db.audit(u["id"], "password_reset"); messagebox.showinfo(APP, "Password updated. Please sign in.")

    def signup_page(self):
        c = self.card(); ttk.Label(c, text="Create account", style="H.TLabel").grid(row=0, column=0, columnspan=3, pady=(0, 12))

        def txt(r, label):
            ttk.Label(c, text=label).grid(row=r, column=0, sticky="w", pady=4)
            e = ttk.Entry(c, width=32); e.grid(row=r, column=1, pady=4); return e

        un = txt(1, "Username"); pw = pwfield(c, 2, "Password"); cp = pwfield(c, 3, "Confirm password")
        em = txt(4, "Email address"); rc = txt(5, "Recovery email"); ap = pwfield(c, 6, "App password"); ca = pwfield(c, 7, "Confirm app password")
        ttk.Label(c, text="App password = the app-specific password from your email provider (used to send you mail).",
                  wraplength=460, foreground="#64748b").grid(row=8, column=0, columnspan=3)

        def go():
            u, e, r, a = un.get().strip(), em.get().strip(), rc.get().strip(), ap.get().replace(" ", "")
            if not USER_RE.fullmatch(u): return messagebox.showerror(APP, "Username: 3-32 chars (letters, digits, _ . -).")
            if self.q("SELECT 1 FROM users WHERE lower(username)=?", (u.lower(),), one=True): return messagebox.showerror(APP, "Username already exists.")
            if not (EMAIL_RE.match(e) and EMAIL_RE.match(r)): return messagebox.showerror(APP, "Enter valid email and recovery email.")
            if self.q("SELECT 1 FROM users WHERE lower(email)=?", (e.lower(),), one=True): return messagebox.showerror(APP, "Email already registered.")
            if pw.get() != cp.get(): return messagebox.showerror(APP, "Passwords do not match.")
            if not a or a != ca.get().replace(" ", ""): return messagebox.showerror(APP, "App passwords do not match.")
            if not policy_ok(self, pw.get()): return
            if not ask_otp(self, e, e, a, "sign-up verification"): return
            if not captcha(self): return
            uid = self.db.insert("INSERT INTO users(username,email,recovery,pw_hash,app_pw) VALUES(?,?,?,?,?)",
                                 (u, e, r, hash_password(pw.get()), self.vault.encrypt(a)))
            self.db.audit(uid, "signup"); messagebox.showinfo(APP, "Account created! Please sign in."); self.login_page()

        ttk.Button(c, text="Sign Up", command=go).grid(row=9, column=0, columnspan=3, pady=(12, 2))
        ttk.Button(c, text="← Back", command=self.home).grid(row=10, column=0, columnspan=3)

    # ------------------------------------------------------------ shell
    def shell(self):
        self.clear(); side = tk.Frame(self, bg=SIDE, width=210); side.pack(side="left", fill="y"); side.pack_propagate(False)
        tk.Label(side, text="🔐 PaaShaa", bg=SIDE, fg="white", font=("Segoe UI", 16, "bold")).pack(pady=20)
        for t, fn in [("📋  Dashboard", self.dashboard), ("➕  Add New", lambda: self.entry_form()),
                      ("⏰  Scheduler", self.sched_page), ("🎲  Suggester", self.suggester),
                      ("🛡  Security Audit", self.health), ("🕵  Pwned Check", self.pwned),
                      ("📜  Activity Log", self.activity), ("👤  Profile", self.profile)]:
            tk.Button(side, text=t, anchor="w", bg=SIDE, fg="white", activebackground="#334155", activeforeground="white",
                      relief="flat", font=("Segoe UI", 11), padx=18, pady=8, command=fn).pack(fill="x")
        tk.Button(side, text="⏻  Logout", anchor="w", bg=SIDE, fg="#fca5a5", relief="flat", font=("Segoe UI", 11),
                  padx=18, pady=8, command=self.logout).pack(side="bottom", fill="x", pady=10)
        self.body = ttk.Frame(self, padding=20); self.body.pack(side="left", fill="both", expand=True); self.dashboard()

    def logout(self):
        if self.user: self.db.audit(self.uid(), "logout")
        self.user = None; self.home()

    def page(self, title):
        self.clear(self.body); ttk.Label(self.body, text=title, style="H.TLabel").pack(anchor="w", pady=(0, 12)); return self.body

    # ------------------------------------------------------------ dashboard
    def dashboard(self):
        b = self.page("Dashboard")
        top = ttk.Frame(b); top.pack(fill="x", pady=(0, 8)); sv = tk.StringVar()
        ttk.Label(top, text="🔎 Search").pack(side="left"); ttk.Entry(top, textvariable=sv, width=32).pack(side="left", padx=6)
        cols = ("Website", "Username", "Login email", "Method", "Description", "Password", "Last changed", "What changed")
        t = ttk.Treeview(b, columns=cols, show="headings", selectmode="browse"); self.tree = t
        for c_, w in zip(cols, (140, 110, 160, 110, 160, 80, 110, 170)): t.heading(c_, text=c_); t.column(c_, width=w)
        rows = self.q("SELECT * FROM entries WHERE user_id=? ORDER BY site COLLATE NOCASE", (self.uid(),))

        def fill(*_):
            t.delete(*t.get_children()); f = sv.get().lower()
            for r in rows:
                if f in " ".join(str(r[k] or "") for k in ("site", "username", "login_email", "method", "descr")).lower():
                    t.insert("", "end", iid=str(r["id"]), values=(r["site"], r["username"], r["login_email"], r["method"],
                                                                 r["descr"], "••••••••", r["changed_at"], r["changed_info"]))

        sv.trace_add("write", fill); fill(); t.pack(fill="both", expand=True)
        bf = ttk.Frame(b); bf.pack(pady=10)
        for txt, fn in [("👁 Show password (OTP)", self.show_pw), ("✏ Edit", self.edit_sel), ("🗑 Delete", self.del_sel), ("➕ Add new", lambda: self.entry_form())]:
            ttk.Button(bf, text=txt, command=fn).pack(side="left", padx=5)

    def sel(self):
        s = self.tree.selection()
        if not s: messagebox.showinfo(APP, "Select a row first."); return None
        return int(s[0])

    def show_pw(self):
        i = self.sel()
        if not i or not self.otp_main("viewing a stored password"): return
        r = self.q("SELECT * FROM entries WHERE id=? AND user_id=?", (i, self.uid()), one=True)
        if not r: return
        self.db.audit(self.uid(), "view_password", r["site"]); secret = self.vault.decrypt(r["pw"])
        d = modal(self, r["site"]); f = ttk.Frame(d, padding=20); f.pack()
        ttk.Label(f, text=f"Password for {r['site']}").pack()
        e = ttk.Entry(f, width=34, font=("Consolas", 12)); e.insert(0, secret); e.config(state="readonly"); e.pack(pady=8)
        ttk.Label(f, text=f"Strength: {policy.strength_label(secret)}").pack()
        ttk.Button(f, text=f"Copy (clears in {CLIPBOARD_CLEAR_SECS}s)", command=lambda: self.copy_clip(secret)).pack(side="left", padx=4, pady=8)
        ttk.Button(f, text="Close", command=d.destroy).pack(side="left", padx=4)
        d.after(60_000, lambda: d.winfo_exists() and d.destroy())

    def edit_sel(self):
        i = self.sel()
        if i: self.entry_form(i)

    def del_sel(self):
        i = self.sel()
        if i and messagebox.askyesno(APP, "Delete this entry permanently?"):
            r = self.q("SELECT site FROM entries WHERE id=? AND user_id=?", (i, self.uid()), one=True)
            self.q("DELETE FROM entries WHERE id=? AND user_id=?", (i, self.uid()), commit=True)
            self.db.audit(self.uid(), "delete_entry", r["site"] if r else ""); self.dashboard()

    # ------------------------------------------------------------ add / edit
    def entry_form(self, eid=None):
        b = self.page("Edit entry" if eid else "Add new information")
        old = self.q("SELECT * FROM entries WHERE id=? AND user_id=?", (eid, self.uid()), one=True) if eid else None
        f = ttk.Frame(b); f.pack(anchor="w"); W = {}
        for r, (lab, key) in enumerate([("Website name / link", "site"), ("Username", "username"), ("Login email", "login_email"), ("Description", "descr")]):
            ttk.Label(f, text=lab).grid(row=r, column=0, sticky="w", pady=5)
            e = ttk.Entry(f, width=40); e.grid(row=r, column=1, pady=5, sticky="w")
            if old: e.insert(0, old[key] or "")
            W[key] = e
        ttk.Label(f, text="Signed in via").grid(row=4, column=0, sticky="w", pady=5)
        W["method"] = ttk.Combobox(f, values=METHODS, state="readonly", width=37); W["method"].grid(row=4, column=1, sticky="w")
        W["method"].set(old["method"] if old else METHODS[0])
        W["pw"] = pwfield(f, 5, "Password" + (" (blank = keep)" if old else "")); W["cpw"] = pwfield(f, 6, "Confirm password")
        meter = ttk.Label(f, text=""); meter.grid(row=5, column=3, sticky="w", padx=8)
        W["pw"].bind("<KeyRelease>", lambda e: meter.config(text=policy.strength_label(W["pw"].get()) if W["pw"].get() else ""))
        ins = tk.BooleanVar(value=bool(old["in_sched"]) if old else True)
        ttk.Checkbutton(f, text="Include in password-change reminder emails", variable=ins).grid(row=7, column=1, sticky="w", pady=8)

        def suggest():
            p = policy.generate(16)
            for k in ("pw", "cpw"): W[k].delete(0, "end"); W[k].insert(0, p)
            meter.config(text=policy.strength_label(p))

        ttk.Button(f, text="🎲 Suggest strong password", command=suggest).grid(row=6, column=3, padx=8)

        def save():
            v = {k: W[k].get().strip() for k in ("site", "username", "login_email", "descr", "method")}
            pw, cp = W["pw"].get(), W["cpw"].get()
            if not v["site"]: return messagebox.showerror(APP, "Website name/link is required.")
            if v["login_email"] and not EMAIL_RE.match(v["login_email"]): return messagebox.showerror(APP, "Invalid login email.")
            if pw or not old:
                if not pw: return messagebox.showerror(APP, "Password is required.")
                if pw != cp: return messagebox.showerror(APP, "Passwords do not match.")
                if not policy_ok(self, pw): return
            if old:
                ch = [k for k in v if (old[k] or "") != v[k]] + (["password"] if pw else []) + (["reminder"] if bool(old["in_sched"]) != ins.get() else [])
                if not ch: return messagebox.showinfo(APP, "Nothing changed.")
                self.q("UPDATE entries SET site=?,username=?,login_email=?,descr=?,method=?,in_sched=?,changed_info=?,changed_at=? WHERE id=? AND user_id=?",
                       (v["site"], v["username"], v["login_email"], v["descr"], v["method"], int(ins.get()), "Changed: " + ", ".join(ch), now_s(), eid, self.uid()), commit=True)
                if pw: self.q("UPDATE entries SET pw=? WHERE id=? AND user_id=?", (self.vault.encrypt(pw), eid, self.uid()), commit=True)
                self.db.audit(self.uid(), "edit_entry", f"{v['site']}: {', '.join(ch)}")
            else:
                self.db.insert("INSERT INTO entries(user_id,site,username,login_email,method,descr,pw,changed_info,changed_at,in_sched) VALUES(?,?,?,?,?,?,?,?,?,?)",
                               (self.uid(), v["site"], v["username"], v["login_email"], v["method"], v["descr"], self.vault.encrypt(pw), "Created", now_s(), int(ins.get())))
                self.db.audit(self.uid(), "add_entry", v["site"])
            self.dashboard()

        ttk.Button(f, text="Save", command=save).grid(row=8, column=1, sticky="w", pady=10)

    # ------------------------------------------------------------ scheduler
    def sched_page(self):
        b = self.page("Change-password scheduler"); u = self.user
        s = json.loads(u["sched"]) if u["sched"] else {"n": 1, "unit": "months", "time": "09:00"}
        f = ttk.Frame(b); f.pack(anchor="w")
        ttk.Label(f, text="Remind me every").grid(row=0, column=0, pady=6)
        n = ttk.Spinbox(f, from_=1, to=365, width=5); n.set(s["n"]); n.grid(row=0, column=1, padx=4)
        un = ttk.Combobox(f, values=list(UNITS), state="readonly", width=9); un.set(s["unit"]); un.grid(row=0, column=2)
        ttk.Label(f, text="at (HH:MM)").grid(row=0, column=3, padx=(12, 4)); tm = ttk.Entry(f, width=7); tm.insert(0, s["time"]); tm.grid(row=0, column=4)
        on = tk.BooleanVar(value=bool(u["next_due"])); ttk.Checkbutton(f, text="Enabled", variable=on).grid(row=0, column=5, padx=12)
        ttk.Label(b, text="Tip: choose 1 day for a daily reminder.", foreground="#64748b").pack(anchor="w")
        ttk.Label(b, text=("Next reminder: " + u["next_due"][:16].replace("T", " ")) if u["next_due"] else "Reminders are off.").pack(anchor="w", pady=8)

        def save():
            try:
                if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", tm.get()): raise ValueError("Time must be HH:MM (24h).")
                k = int(n.get())
                if k < 1: raise ValueError("Interval must be at least 1.")
            except ValueError as e: return messagebox.showerror(APP, str(e))
            nxt = calc_next(k, un.get(), tm.get()).isoformat() if on.get() else None
            self.q("UPDATE users SET sched=?, next_due=? WHERE id=?", (json.dumps({"n": k, "unit": un.get(), "time": tm.get()}), nxt, self.uid()), commit=True)
            self.db.audit(self.uid(), "schedule_saved", f"every {k} {un.get()} at {tm.get()}" if on.get() else "disabled")
            self.reload(); self.sched_page()
            messagebox.showinfo(APP, "Schedule saved. Reminders are sent while PaaShaa is running (enable start-on-login in Profile).")

        def now_():
            try:
                ok = send_reminder(self.db, self.vault, self.user)
                messagebox.showinfo(APP, ("Reminder sent to " + self.user["email"]) if ok else "No accounts are included in reminders yet.")
            except Exception as e: messagebox.showerror(APP, f"Failed: {e}")

        bf = ttk.Frame(b); bf.pack(anchor="w"); ttk.Button(bf, text="Save schedule", command=save).pack(side="left", padx=(0, 8))
        ttk.Button(bf, text="Send reminder now", command=now_).pack(side="left")
        ttk.Label(b, text="\nAccounts included in the reminder email:", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        lb = tk.Listbox(b, height=10)
        for r in self.q("SELECT * FROM entries WHERE user_id=? AND in_sched=1", (self.uid(),)): lb.insert("end", f"{r['site']}   ({r['login_email'] or r['username']})")
        lb.pack(fill="x")

    # ------------------------------------------------------------ suggester
    def suggester(self):
        b = self.page("Password suggester"); f = ttk.Frame(b); f.pack(anchor="w"); mode = tk.StringVar(value="random")
        ttk.Radiobutton(f, text="Based on my sentence", variable=mode, value="sentence").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(f, text="Fully random", variable=mode, value="random").grid(row=0, column=1, sticky="w")
        ttk.Label(f, text="Sentence").grid(row=1, column=0, sticky="w", pady=6); se = ttk.Entry(f, width=50); se.grid(row=1, column=1, columnspan=3, sticky="w")
        ttk.Label(f, text="Length").grid(row=2, column=0, sticky="w"); ln = ttk.Spinbox(f, from_=8, to=64, width=5); ln.set(16); ln.grid(row=2, column=1, sticky="w")
        vs = [tk.BooleanVar(value=True) for _ in range(4)]; cf = ttk.Frame(b); cf.pack(anchor="w", pady=8)
        for v, t in zip(vs, ("Capital letters", "Small letters", "Numbers", "Symbols")): ttk.Checkbutton(cf, text=t, variable=v).pack(side="left", padx=6)
        out = ttk.Entry(b, width=50, font=("Consolas", 14)); out.pack(anchor="w", pady=8); sc = ttk.Label(b, text=""); sc.pack(anchor="w")

        def make():
            if mode.get() == "sentence" and not se.get().strip(): return messagebox.showinfo(APP, "Type a sentence first.")
            try: length = int(ln.get())
            except ValueError: return messagebox.showerror(APP, "Length must be a number.")
            p = policy.generate(length, *[v.get() for v in vs], sentence=se.get() if mode.get() == "sentence" else "")
            out.delete(0, "end"); out.insert(0, p)
            sc.config(text=f"{policy.strength_label(p)} • " + ("meets policy ✓" if not policy.missing(p) else "missing: " + "; ".join(policy.missing(p))))

        bf = ttk.Frame(b); bf.pack(anchor="w")
        ttk.Button(bf, text="Generate / Next suggestion", command=make).pack(side="left", padx=(0, 8))
        ttk.Button(bf, text="Copy", command=lambda: self.copy_clip(out.get())).pack(side="left")

    # ------------------------------------------------------------ security audit
    def health(self):
        b = self.page("Security audit")
        rows = self.q("SELECT * FROM entries WHERE user_id=?", (self.uid(),))
        items = [{"id": r["id"], "site": r["site"], "username": r["username"], "pw": self.vault.decrypt(r["pw"]),
                  "changed_at": r["changed_at"], "in_sched": r["in_sched"]} for r in rows]
        score, findings = analysis.analyze(items); del items
        colour = "#15803d" if score >= 80 else "#b45309" if score >= 50 else "#b91c1c"
        ttk.Label(b, text=f"Vault health: {score}%", font=("Segoe UI", 16, "bold"), foreground=colour).pack(anchor="w")
        ttk.Label(b, text="Checks: policy compliance, reused passwords, age, reminder coverage. Passwords stay in memory only.").pack(anchor="w", pady=(0, 8))
        t = ttk.Treeview(b, columns=("Site", "Username", "Issues"), show="headings")
        for c_, w in zip(("Site", "Username", "Issues"), (200, 160, 600)): t.heading(c_, text=c_); t.column(c_, width=w)
        for i, issues in findings:
            if issues: t.insert("", "end", values=(i["site"], i["username"], "; ".join(issues)))
        t.pack(fill="both", expand=True)
        if not any(x for _, x in findings): ttk.Label(b, text="🎉 No issues found.").pack(pady=8)

    # ------------------------------------------------------------ pwned
    def pwned(self):
        b = self.page("Has my email been pwned?"); f = ttk.Frame(b); f.pack(anchor="w")
        ttk.Label(f, text="Email").grid(row=0, column=0, sticky="w", pady=5); em = ttk.Entry(f, width=36); em.insert(0, self.user["email"]); em.grid(row=0, column=1)
        ttk.Label(f, text="HIBP API key").grid(row=1, column=0, sticky="w"); key = ttk.Entry(f, width=36, show="•"); key.grid(row=1, column=1)
        ttk.Label(f, text="(haveibeenpwned.com requires a paid API key for email lookups)", foreground="#64748b").grid(row=2, column=1, sticky="w")
        out = tk.Text(b, height=18, wrap="word"); out.pack(fill="both", expand=True, pady=10)

        def show(t): out.config(state="normal"); out.delete("1.0", "end"); out.insert("end", t); out.config(state="disabled")

        def chk():
            if not key.get().strip():
                if messagebox.askyesno(APP, "No API key entered. Open haveibeenpwned.com in your browser instead?"): webbrowser.open("https://haveibeenpwned.com/")
                return
            r = breach.check_email(em.get().strip(), key.get().strip()); s = r["status"]
            if s == "pwned":
                show(f"⚠ Found in {len(r['breaches'])} breach(es):\n\n" + "\n".join(
                    f"• {d['Name']} ({d['BreachDate']})\n    Exposed: {', '.join(d['DataClasses'])}\n" for d in r["breaches"]) +
                    "\nChange the passwords of affected sites and enable 2FA.")
            else:
                show({"clean": "✅ Good news - no breaches found for this email.", "bad_key": "Invalid API key.",
                      "limited": "Rate-limited by HIBP. Try again shortly."}.get(s, f"Error: {r.get('error') or r.get('code')}"))
            self.db.audit(self.uid(), "pwned_email_check", s)

        def chk_pw():
            r = form(self, "Password breach check", [("Password (never sent in full)", "pw", True)],
                     "Uses k-anonymity: only the first 5 chars of the SHA-1 hash leave your PC.")
            if not r or not r["pw"]: return
            try: n = breach.pwned_count(r["pw"])
            except Exception as e: return show(f"Network error: {e}")
            show(f"⚠ This password appeared {n:,} times in breaches. Do not use it." if n else "✅ This password was not found in known breaches.")

        bf = ttk.Frame(b); bf.pack(anchor="w"); ttk.Button(bf, text="Check email", command=chk).pack(side="left", padx=(0, 8))
        ttk.Button(bf, text="Check a password (free)", command=chk_pw).pack(side="left")

    # ------------------------------------------------------------ activity log
    def activity(self):
        b = self.page("Activity log")
        t = ttk.Treeview(b, columns=("Time", "Event", "Detail"), show="headings")
        for c_, w in zip(("Time", "Event", "Detail"), (170, 170, 560)): t.heading(c_, text=c_); t.column(c_, width=w)
        for r in self.q("SELECT * FROM audit WHERE user_id=? ORDER BY id DESC LIMIT 300", (self.uid(),)):
            t.insert("", "end", values=(r["ts"], r["event"], r["detail"]))
        t.pack(fill="both", expand=True)

    # ------------------------------------------------------------ profile
    def profile(self):
        b = self.page("Profile"); u = self.user; top = ttk.Frame(b); top.pack(anchor="w")
        self.photo = load_photo(u["photo"]) if u["photo"] and os.path.exists(u["photo"]) else None
        lab = ttk.Label(top, image=self.photo) if self.photo else ttk.Label(top, text="👤", font=("Segoe UI", 54))
        lab.grid(row=0, column=0, rowspan=2, padx=(0, 20))
        ttk.Label(top, text=u["username"], font=("Segoe UI", 16, "bold")).grid(row=0, column=1, sticky="w")
        ttk.Button(top, text="Change photo", command=self.change_photo).grid(row=1, column=1, sticky="w")
        g = ttk.Frame(b); g.pack(anchor="w", pady=20)
        for r, (l, v, fn) in enumerate([("Username", u["username"], self.ch_username), ("Main email", u["email"], self.ch_email),
                                        ("Recovery email", u["recovery"], self.ch_recovery), ("Password", "••••••••••••", self.ch_password)]):
            ttk.Label(g, text=l, width=16).grid(row=r, column=0, pady=6, sticky="w"); ttk.Label(g, text=v, width=34).grid(row=r, column=1, sticky="w")
            ttk.Button(g, text="Change", command=fn).grid(row=r, column=2)
        av = tk.BooleanVar(value=autostart.is_enabled())

        def tog():
            try: autostart.set_enabled(av.get())
            except Exception as e: messagebox.showerror(APP, f"Could not change startup setting: {e}")

        ttk.Checkbutton(b, text="Start PaaShaa automatically at login (so reminders are never missed)", variable=av, command=tog).pack(anchor="w")
        bf = ttk.Frame(b); bf.pack(anchor="w", pady=14)
        ttk.Button(bf, text="⬇ Export encrypted backup", command=self.export_bak).pack(side="left", padx=(0, 8))
        ttk.Button(bf, text="⬆ Import backup", command=self.import_bak).pack(side="left")
        ttk.Label(b, text=f"Data folder: {HOME}", foreground="#64748b").pack(anchor="w")

    def export_bak(self):
        r = form(self, "Export backup", [("Backup passphrase", "pass", True), ("Confirm passphrase", "cpw", True)],
                 "Choose a strong passphrase (12+ chars). You need it to restore.")
        if not r: return
        if r["pass"] != r["cpw"] or policy.missing(r["pass"]): return messagebox.showerror(APP, "Passphrases must match and meet the password policy.")
        if not self.otp_main("exporting a backup"): return
        p = filedialog.asksaveasfilename(defaultextension=".psbak", filetypes=[("PaaShaa backup", "*.psbak")])
        if p:
            n = backup.export_entries(self.db, self.vault, self.uid(), p, r["pass"])
            self.db.audit(self.uid(), "backup_export", f"{n} entries"); messagebox.showinfo(APP, f"Exported {n} entries.")

    def import_bak(self):
        p = filedialog.askopenfilename(filetypes=[("PaaShaa backup", "*.psbak")])
        if not p: return
        r = form(self, "Import backup", [("Backup passphrase", "pass", True)])
        if not r: return
        try: n = backup.import_entries(self.db, self.vault, self.uid(), p, r["pass"], now_s())
        except Exception as e: return messagebox.showerror(APP, f"Import failed: {e}")
        self.db.audit(self.uid(), "backup_import", f"{n} entries"); messagebox.showinfo(APP, f"Imported {n} new entries.")

    def change_photo(self):
        p = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")])
        if not p: return
        dst = os.path.join(HOME, f"photo_{self.uid()}" + os.path.splitext(p)[1].lower()); shutil.copy(p, dst)
        self.q("UPDATE users SET photo=? WHERE id=?", (dst, self.uid()), commit=True); self.reload(); self.profile()

    def ch_username(self):
        if not self.otp_main("changing username"): return
        r = form(self, "New username", [("New username", "n", False)])
        if not r: return
        if not USER_RE.fullmatch(r["n"]): return messagebox.showerror(APP, "Invalid username.")
        if self.q("SELECT 1 FROM users WHERE lower(username)=? AND id<>?", (r["n"].lower(), self.uid()), one=True): return messagebox.showerror(APP, "Username already exists.")
        self.q("UPDATE users SET username=? WHERE id=?", (r["n"], self.uid()), commit=True)
        self.db.audit(self.uid(), "change_username"); self.reload(); self.profile()

    def ch_email(self):
        if not self.otp_main("changing main email"): return
        r = form(self, "New main email", [("New email", "e", False), ("App password", "app", True), ("New recovery email", "r", False)],
                 "An OTP will be sent to the new email and the new recovery email to confirm them.")
        if not r: return
        app = r["app"].replace(" ", "")
        if not (EMAIL_RE.match(r["e"]) and EMAIL_RE.match(r["r"]) and app): return messagebox.showerror(APP, "Fill all fields with valid values.")
        if not ask_otp(self, r["e"], r["e"], app, "confirming new main email"): return
        if not ask_otp(self, r["r"], r["e"], app, "confirming new recovery email"): return
        self.q("UPDATE users SET email=?, recovery=?, app_pw=? WHERE id=?", (r["e"], r["r"], self.vault.encrypt(app), self.uid()), commit=True)
        self.db.audit(self.uid(), "change_email"); self.reload(); self.profile()

    def ch_recovery(self):
        if not self.otp_main("changing recovery email"): return
        r = form(self, "New recovery email", [("New recovery email", "r", False)])
        if not r or not EMAIL_RE.match(r["r"]): return
        if not ask_otp(self, r["r"], self.user["email"], self.vault.decrypt(self.user["app_pw"]), "confirming new recovery email"): return
        self.q("UPDATE users SET recovery=? WHERE id=?", (r["r"], self.uid()), commit=True)
        self.db.audit(self.uid(), "change_recovery"); self.reload(); self.profile()

    def ch_password(self):
        while True:
            r = form(self, "Change password", [("Old password", "old", True), ("New password", "npw", True), ("Confirm new password", "cpw", True)])
            if not r: return
            if not verify_password(r["old"], self.user["pw_hash"]): messagebox.showerror(APP, "Old password is incorrect."); continue
            if r["npw"] != r["cpw"]: messagebox.showerror(APP, "Passwords do not match."); continue
            if policy_ok(self, r["npw"]): break
        if not self.otp_main("changing account password"): return
        self.q("UPDATE users SET pw_hash=? WHERE id=?", (hash_password(r["npw"]), self.uid()), commit=True)
        self.db.audit(self.uid(), "change_password"); self.reload(); messagebox.showinfo(APP, "Password changed.")
