"""
SecureBank - Retail Banking Portal  (VULNERABLE "as-built" version)
===================================================================
A realistic mini banking app: login -> dashboard with balance, accounts,
transfer money, transactions, payees, cards, profile, support tickets.

Five vulnerabilities are LIVE in this app, each triggered by an ordinary
user through the interface, tagged `# VULN-n:`. A sixth (stored XSS) was
found in review and is documented in the audit report but is NOT shipped
here (templates auto-escape).

  VULN-1  SQL injection (login)                 -> Secure Coding / Input Validation
  VULN-2  Broken Access Control / IDOR          -> IAM Authorization / Least Privilege
          (view any account + transactions by id)
  VULN-4  Single-factor login + no lockout      -> MFA / IAM Authentication
  VULN-5  CSRF on money transfer                -> Secure Coding / A01
  VULN-6  Open redirect -> card phishing         -> Phishing / Redirect

Do NOT deploy. Hardened version: ../v2/app_fixed.py
"""

import sqlite3
from flask import (Flask, request, redirect, session, render_template,
                   url_for, abort)

app = Flask(__name__, template_folder="templates_v1")
app.secret_key = "securebank-dev-key-123"   # hard-coded -> forgeable sessions
DB = "bank_vulnerable.db"
ATTACKER_PAYEE = "Unknown account transfer"


def get_db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c


def init_db():
    conn = get_db(); c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT,
        name TEXT, email TEXT, phone TEXT,
        acc_no TEXT, acc_type TEXT, balance REAL,
        card_no TEXT, card_cvv TEXT, card_exp TEXT);
    CREATE TABLE IF NOT EXISTS txns(
        id INTEGER PRIMARY KEY, username TEXT, date TEXT, party TEXT,
        amount REAL, kind TEXT);
    CREATE TABLE IF NOT EXISTS payees(
        id INTEGER PRIMARY KEY, username TEXT, name TEXT, acc_no TEXT);
    CREATE TABLE IF NOT EXISTS tickets(
        id INTEGER PRIMARY KEY, username TEXT, subject TEXT, message TEXT, status TEXT);
    """)
    if c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"] == 0:
        c.executemany("""INSERT INTO users
            (username,password,role,name,email,phone,acc_no,acc_type,balance,card_no,card_cvv,card_exp)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", [
            ("alice","Password@123","customer","Alice Menezes","alice@example.com","+91 90000 11111",
             "5012 3456 7890","Savings",85000.0,"4111 1111 1111 1111","321","08/28"),
            ("bob","Hunter2!","customer","Bob Dsouza","bob@example.com","+91 90000 22222",
             "5012 9988 7766","Savings",40000.0,"4222 2222 2222 2222","654","11/27"),
            ("admin","admin","admin","Admin User","admin@securebank.example","+91 90000 00000",
             "0000 0000 0000","Internal",0.0,"-","-","-")])
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


def require_login():
    return "username" in session


# ---------------------------------------------------------------- auth
@app.route("/", methods=["GET", "POST"])
def login():
    # VULN-6: 'next' trusted verbatim -> open redirect to a phishing page.
    nxt = request.values.get("next", "")
    error = ""
    attempts = session.get("fail_count", 0)
    if request.method == "POST":
        u = request.form.get("username", ""); p = request.form.get("password", "")
        conn = get_db()
        # VULN-1: SQL injection. VULN-4a: attempts counted, never blocked.
        q = "SELECT * FROM users WHERE username='%s' AND password='%s'" % (u, p)
        try: row = conn.execute(q).fetchone()
        except Exception: row = None
        conn.close()
        if row:
            session["fail_count"] = 0
            # VULN-4b: no MFA - password alone grants the session.
            session["username"] = row["username"]; session["role"] = row["role"]
            session["single_factor_warn"] = True
            if nxt:
                return redirect(nxt)                 # VULN-6
            return redirect(url_for("dashboard"))
        session["fail_count"] = attempts + 1; attempts = session["fail_count"]
        error = "Invalid username or password."
    return render_template("login.html", error=error, attempts=attempts, next=nxt)


@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))


# ---------------------------------------------------------------- dashboard
@app.route("/dashboard")
def dashboard():
    if not require_login(): return redirect(url_for("login"))
    u = me()
    conn = get_db()
    txns = conn.execute("SELECT * FROM txns WHERE username=? ORDER BY id DESC LIMIT 5",
                        (u["username"],)).fetchall()
    conn.close()
    warn = session.pop("single_factor_warn", False)
    note = session.pop("flash_note", None)
    return render_template("dashboard.html", u=u, txns=txns, single_factor_warn=warn, note=note)


@app.route("/accounts")
def accounts():
    if not require_login(): return redirect(url_for("login"))
    return render_template("accounts.html", u=me())


@app.route("/account/<int:uid>")
def account_detail(uid):
    if not require_login(): return redirect(url_for("login"))
    conn = get_db()
    acc = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    # VULN-2: IDOR - account fetched by id with NO ownership check; any user can
    # view any account's balance, number and transactions by changing the id.
    if not acc: abort(404)
    txns = conn.execute("SELECT * FROM txns WHERE username=? ORDER BY id DESC",
                        (acc["username"],)).fetchall()
    conn.close()
    not_mine = (acc["username"] != session["username"])
    return render_template("account_detail.html", acc=acc, txns=txns, not_mine=not_mine,
                           viewer=session["username"])


# ---------------------------------------------------------------- transfer
@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if not require_login(): return redirect(url_for("login"))
    u = me(); error = ""
    conn = get_db()
    payees = conn.execute("SELECT * FROM payees WHERE username=?", (u["username"],)).fetchall()
    conn.close()
    if request.method == "POST":
        payee = request.form.get("payee", ""); 
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


# ---------------------------------------------------------------- CSRF demo (#5)
@app.route("/do_transfer", methods=["POST"])
def do_transfer_route():
    # VULN-5: state-changing transfer with NO anti-CSRF token. The attacker page
    # auto-submits a cross-site POST form, so money moves using the victim's session.
    if not require_login(): return redirect(url_for("login"))
    amount = float(request.form.get("amount", "500") or 500)
    payee = request.form.get("payee", ATTACKER_PAYEE)
    err = do_transfer(session["username"], payee, amount)
    session["flash_note"] = (f"CSRF: Rs {amount:,.0f} was transferred to an unknown account by "
                             f"a request you never authorised.") if not err else err
    return redirect(url_for("dashboard"))


@app.route("/promo")
def promo():
    # In-app "attacker" page (clearly labelled) that auto-fires the forged transfer.
    if not require_login(): return redirect(url_for("login"))
    return render_template("promo.html")


# ---------------------------------------------------------------- phishing (#6)
@app.route("/claim-reward-verify")
def verify():
    # In-app "attacker" phishing page the open redirect lands on. Asks for card
    # details under a fake "account compromised" pretext.
    return render_template("verify.html")


# ---------------------------------------------------------------- other pages
@app.route("/transactions")
def transactions():
    if not require_login(): return redirect(url_for("login"))
    conn = get_db()
    txns = conn.execute("SELECT * FROM txns WHERE username=? ORDER BY id DESC",
                        (session["username"],)).fetchall()
    conn.close()
    return render_template("transactions.html", txns=txns, u=me())


@app.route("/payees", methods=["GET", "POST"])
def payees():
    if not require_login(): return redirect(url_for("login"))
    if request.method == "POST":
        conn = get_db()
        conn.execute("INSERT INTO payees(username,name,acc_no) VALUES(?,?,?)",
                     (session["username"], request.form.get("name", ""),
                      request.form.get("acc_no", "")))
        conn.commit(); conn.close()
        return redirect(url_for("payees"))
    conn = get_db()
    rows = conn.execute("SELECT * FROM payees WHERE username=?", (session["username"],)).fetchall()
    conn.close()
    return render_template("payees.html", payees=rows)


@app.route("/cards")
def cards():
    if not require_login(): return redirect(url_for("login"))
    return render_template("cards.html", u=me())


@app.route("/profile")
def profile():
    if not require_login(): return redirect(url_for("login"))
    return render_template("profile.html", u=me())


@app.route("/support", methods=["GET", "POST"])
def support():
    if not require_login(): return redirect(url_for("login"))
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
    if not require_login(): return redirect(url_for("login"))
    conn = get_db()
    t = conn.execute("SELECT * FROM tickets WHERE id=?", (tid,)).fetchone()
    if t and t["username"] == session["username"]:
        conn.execute("UPDATE tickets SET status='closed' WHERE id=?", (tid,))
        conn.commit()
    conn.close()
    return redirect(url_for("support"))


@app.errorhandler(404)
def e404(_): return render_template("error.html", code=404, title="Not found",
                                    msg="The page you requested does not exist."), 404


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
