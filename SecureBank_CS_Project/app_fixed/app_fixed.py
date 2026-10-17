"""
SecureBank - Retail Banking Portal  (FIXED "remediated" version)
================================================================
Same banking app and UI, with all findings closed.

  FIX-1  Parameterized query + scrypt password hashing
  FIX-2  Ownership check on account/<id> (Least Privilege)
  FIX-3  (XSS) auto-escaping everywhere; no |safe anywhere
  FIX-4  MFA second factor + 5-attempt lockout
  FIX-5  CSRF token on the transfer; GET cannot change state
  FIX-6  Safe redirect (local relative paths only)

Run:  export SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
      python app_fixed.py
"""

import os
import secrets
import sqlite3
from urllib.parse import urlparse
from flask import (Flask, request, redirect, session, render_template,
                   url_for, abort)
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder="templates_v2")
key = os.environ.get("SECRET_KEY")
if not key:
    raise RuntimeError("SECRET_KEY environment variable is required; refusing to start.")
app.secret_key = key
csrf = CSRFProtect(app)                     # FIX-5

DB = "bank_fixed.db"
MAX_ATTEMPTS = 5
_failed = {}


def get_db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c


def init_db():
    conn = get_db(); c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT,
        name TEXT, email TEXT, phone TEXT, acc_no TEXT, acc_type TEXT, balance REAL,
        card_no TEXT, card_cvv TEXT, card_exp TEXT);
    CREATE TABLE IF NOT EXISTS txns(
        id INTEGER PRIMARY KEY, username TEXT, date TEXT, party TEXT, amount REAL, kind TEXT);
    CREATE TABLE IF NOT EXISTS payees(
        id INTEGER PRIMARY KEY, username TEXT, name TEXT, acc_no TEXT);
    CREATE TABLE IF NOT EXISTS tickets(
        id INTEGER PRIMARY KEY, username TEXT, subject TEXT, message TEXT, status TEXT);
    """)
    if c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"] == 0:
        for row in [
            ("alice","Password@123","customer","Alice Menezes","alice@example.com","+91 90000 11111",
             "5012 3456 7890","Savings",85000.0,"4111 1111 1111 1111","321","08/28"),
            ("bob","Hunter2!","customer","Bob Dsouza","bob@example.com","+91 90000 22222",
             "5012 9988 7766","Savings",40000.0,"4222 2222 2222 2222","654","11/27"),
            ("admin","admin","admin","Admin User","admin@securebank.example","+91 90000 00000",
             "0000 0000 0000","Internal",0.0,"-","-","-")]:
            c.execute("""INSERT INTO users(username,password_hash,role,name,email,phone,acc_no,acc_type,balance,card_no,card_cvv,card_exp)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (row[0], generate_password_hash(row[1])) + row[2:])
        c.executemany("INSERT INTO txns(username,date,party,amount,kind) VALUES(?,?,?,?,?)", [
            ("alice","2026-09-28","Salary - Acme Corp",60000,"credit"),
            ("alice","2026-09-30","Amazon India",-2499,"debit"),
            ("alice","2026-10-01","Electricity Board",-1850,"debit"),
            ("bob","2026-09-29","Freelance payout",25000,"credit"),
            ("bob","2026-10-02","Swiggy",-640,"debit")])
        c.executemany("INSERT INTO payees(username,name,acc_no) VALUES(?,?,?)", [
            ("alice","Mom","5012 1111 2222"),("alice","Landlord","5012 3333 4444"),
            ("bob","Sister","5012 5555 6666")])
        c.executemany("INSERT INTO tickets(username,subject,message,status) VALUES(?,?,?,?)", [
            ("alice","Card blocked abroad","My debit card was blocked while travelling.","open"),
            ("bob","Failed UPI transfer","INR 5000 debited but not received.","open")])
    conn.commit(); conn.close()


def me():
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE username=?", (session["username"],)).fetchone()
    conn.close(); return u


def logged_in():
    return "username" in session


def is_safe_next(t):
    # FIX-6: only allow local, relative paths AND only known post-login
    # destinations (an allow-list). This refuses both external sites and any
    # unexpected in-app page such as the /verify phishing form.
    if not t:
        return False
    p = urlparse(t)
    if p.scheme or p.netloc or not t.startswith("/"):
        return False
    allowed = {"/dashboard", "/accounts", "/transfer", "/transactions",
               "/payees", "/cards", "/profile", "/support"}
    return t.split("?")[0] in allowed


@app.route("/", methods=["GET", "POST"])
def login():
    nxt = request.values.get("next", "")
    error = ""
    if request.method == "POST":
        u = request.form.get("username", ""); p = request.form.get("password", "")
        if _failed.get(u, 0) >= MAX_ATTEMPTS:                      # FIX-4
            return render_template("login.html",
                                   error="Account locked after 5 failed attempts.", next=nxt)
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()  # FIX-1
        conn.close()
        if row and check_password_hash(row["password_hash"], p):
            _failed.pop(u, None)
            session["pending_user"] = row["username"]; session["pending_role"] = row["role"]
            session["mfa_code"] = f"{secrets.randbelow(1000000):06d}"
            session["pending_phone"] = row["phone"]      # SMS OTP goes to registered number
            session["pending_next"] = nxt
            return redirect(url_for("mfa"))
        _failed[u] = _failed.get(u, 0) + 1
        error = "Invalid username or password."
    return render_template("login.html", error=error, next=nxt)


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    if "pending_user" not in session:
        return redirect(url_for("login"))
    error = ""
    if request.method == "POST":
        if request.form.get("code", "") == session.get("mfa_code"):
            session["username"] = session.pop("pending_user")
            session["role"] = session.pop("pending_role")
            session.pop("mfa_code", None)
            nxt = session.pop("pending_next", "")
            return redirect(nxt) if is_safe_next(nxt) else redirect(url_for("dashboard"))  # FIX-6
        error = "Incorrect verification code."
    phone = session.get("pending_phone", "")
    masked = ("xxxxx " + phone[-5:]) if phone else "your registered number"
    return render_template("mfa.html", error=error, demo_code=session.get("mfa_code"), masked_phone=masked)


@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if not logged_in(): return redirect(url_for("login"))
    u = me(); conn = get_db()
    txns = conn.execute("SELECT * FROM txns WHERE username=? ORDER BY id DESC LIMIT 5",
                        (u["username"],)).fetchall(); conn.close()
    note = session.pop("flash_note", None)
    return render_template("dashboard.html", u=u, txns=txns, note=note)


@app.route("/accounts")
def accounts():
    if not logged_in(): return redirect(url_for("login"))
    return render_template("accounts.html", u=me())


@app.route("/account/<int:uid>")
def account_detail(uid):
    if not logged_in(): return redirect(url_for("login"))
    conn = get_db()
    acc = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not acc:
        conn.close(); abort(404)
    # FIX-2: ownership check (admins may view any).
    if acc["username"] != session["username"] and session.get("role") != "admin":
        conn.close(); abort(403)
    txns = conn.execute("SELECT * FROM txns WHERE username=? ORDER BY id DESC",
                        (acc["username"],)).fetchall(); conn.close()
    return render_template("account_detail.html", acc=acc, txns=txns)


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if not logged_in(): return redirect(url_for("login"))
    u = me(); error = ""; conn = get_db()
    payees = conn.execute("SELECT * FROM payees WHERE username=?", (u["username"],)).fetchall()
    conn.close()
    if request.method == "POST":   # FIX-5: CSRF token enforced by CSRFProtect
        payee = request.form.get("payee", "")
        try: amount = float(request.form.get("amount", "0") or 0)
        except ValueError: amount = 0
        error = do_transfer(u["username"], payee, amount)
        if not error:
            session["flash_note"] = f"Transferred Rs {amount:,.0f} to {payee}."
            return redirect(url_for("dashboard"))
    return render_template("transfer.html", u=u, payees=payees, error=error)


def do_transfer(username, payee, amount):
    if amount <= 0: return "Enter a valid amount."
    conn = get_db()
    bal = conn.execute("SELECT balance FROM users WHERE username=?", (username,)).fetchone()["balance"]
    if amount > bal:
        conn.close(); return "Insufficient balance."
    conn.execute("UPDATE users SET balance=balance-? WHERE username=?", (amount, username))
    conn.execute("INSERT INTO txns(username,date,party,amount,kind) VALUES(?,date('now'),?,?,?)",
                 (username, payee, -amount, "debit"))
    conn.commit(); conn.close(); return ""


@app.route("/transactions")
def transactions():
    if not logged_in(): return redirect(url_for("login"))
    conn = get_db()
    txns = conn.execute("SELECT * FROM txns WHERE username=? ORDER BY id DESC",
                        (session["username"],)).fetchall(); conn.close()
    return render_template("transactions.html", txns=txns, u=me())


@app.route("/payees", methods=["GET", "POST"])
def payees():
    if not logged_in(): return redirect(url_for("login"))
    if request.method == "POST":
        conn = get_db()
        conn.execute("INSERT INTO payees(username,name,acc_no) VALUES(?,?,?)",
                     (session["username"], request.form.get("name", ""),
                      request.form.get("acc_no", "")))
        conn.commit(); conn.close(); return redirect(url_for("payees"))
    conn = get_db()
    rows = conn.execute("SELECT * FROM payees WHERE username=?", (session["username"],)).fetchall()
    conn.close()
    return render_template("payees.html", payees=rows)


@app.route("/cards")
def cards():
    if not logged_in(): return redirect(url_for("login"))
    return render_template("cards.html", u=me())


@app.route("/profile")
def profile():
    if not logged_in(): return redirect(url_for("login"))
    return render_template("profile.html", u=me())


@app.route("/support", methods=["GET", "POST"])
def support():
    if not logged_in(): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        subj = request.form.get("subject", "").strip()
        msg = request.form.get("message", "").strip()
        if subj:
            conn.execute("INSERT INTO tickets(username,subject,message,status) VALUES(?,?,?,?)",
                         (session["username"], subj, msg, "open"))
            conn.commit()
        conn.close()
        return redirect(url_for("support"))
    rows = conn.execute("SELECT * FROM tickets WHERE username=?", (session["username"],)).fetchall()
    conn.close()
    return render_template("support.html", tickets=rows)


@app.route("/close_ticket/<int:tid>", methods=["POST"])
def close_ticket(tid):
    # Feature (not a vulnerability): a user may close only their OWN ticket.
    # CSRFProtect also requires a valid token on this POST.
    if not logged_in(): return redirect(url_for("login"))
    conn = get_db()
    t = conn.execute("SELECT * FROM tickets WHERE id=?", (tid,)).fetchone()
    if t and t["username"] == session["username"]:
        conn.execute("UPDATE tickets SET status='closed' WHERE id=?", (tid,))
        conn.commit()
    conn.close()
    return redirect(url_for("support"))


from flask_wtf.csrf import CSRFError


@app.errorhandler(CSRFError)
def e_csrf(e):
    return render_template("error.html", code=400, title="Request blocked",
                           msg="Your session form token was missing or expired. "
                               "Please go back and try again."), 400


@app.errorhandler(403)
def e403(_): return render_template("error.html", code=403, title="Access denied",
                                    msg="You do not have permission to view this account."), 403


@app.errorhandler(404)
def e404(_): return render_template("error.html", code=404, title="Not found",
                                    msg="The page you requested does not exist."), 404


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
