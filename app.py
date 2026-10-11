from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, csv, io, re, hashlib, os
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-before-deployment")
ROOT = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(ROOT, "cybercrime.db")
DATA = os.path.join(ROOT, "data", "ncrb_national_cases.csv")

def connect():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con

def init_db():
    with connect() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst', created_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS incidents(
            id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
            category TEXT NOT NULL, state TEXT NOT NULL, amount REAL DEFAULT 0,
            status TEXT DEFAULT 'New', description TEXT NOT NULL, created_at TEXT NOT NULL,
            evidence_hash TEXT DEFAULT '', user_id INTEGER REFERENCES users(id))""")
        cols = [r["name"] for r in con.execute("PRAGMA table_info(incidents)").fetchall()]
        if "user_id" not in cols:
            con.execute("ALTER TABLE incidents ADD COLUMN user_id INTEGER REFERENCES users(id)")
        con.execute("""CREATE TABLE IF NOT EXISTS audit_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
            action TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL)""")
        count = con.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        if count == 0:
            demo = [
                ("UPI collect-request complaint", "Payment fraud", "Maharashtra", 12500, "Under review",
                 "SIMULATED TEACHING EXAMPLE: Caller claimed a refund was pending and asked the victim to approve a collect request."),
                ("Parcel delivery SMS link", "Phishing", "Karnataka", 0, "New",
                 "SIMULATED TEACHING EXAMPLE: Message asked the recipient to pay a small redelivery fee on an unfamiliar website."),
                ("Impersonation on social media", "Identity misuse", "Delhi", 0, "Escalated",
                 "SIMULATED TEACHING EXAMPLE: A newly created profile reused a public photograph and contacted the person's friends.")
            ]
            for title, category, state, amount, status, desc in demo:
                con.execute("""INSERT INTO incidents(title,category,state,amount,status,description,created_at,evidence_hash)
                    VALUES(?,?,?,?,?,?,?,?)""",
                    (title, category, state, amount, status, desc, datetime.now().strftime("%Y-%m-%d %H:%M"),
                     hashlib.sha256(desc.encode()).hexdigest()))

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to access the analyst workspace.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

def log_action(action, detail):
    if session.get("user_id"):
        with connect() as con:
            con.execute("INSERT INTO audit_logs(user_id,action,detail,created_at) VALUES(?,?,?,?)",
                (session["user_id"], action, detail[:250], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

def read_stats():
    with open(DATA, newline="", encoding="utf-8") as f:
        return [{"year": int(r["year"]), "cases": int(r["registered_cases"])} for r in csv.DictReader(f)]

def url_check(value):
    value=value.strip()
    if not value: return {"score":0,"level":"No input","findings":["Enter a URL to analyse."]}
    candidate=value if "://" in value else "http://" + value
    parsed=urlparse(candidate); host=(parsed.hostname or "").lower()
    findings=[]; score=0
    if parsed.scheme != "https":
        score += 18; findings.append("No HTTPS scheme detected. This alone does not prove a site is malicious.")
    if not host or "." not in host:
        score += 30; findings.append("The address does not look like a complete domain.")
    if re.search(r'(\d{1,3}\.){3}\d{1,3}',host):
        score += 20; findings.append("The hostname uses an IP address instead of a typical domain.")
    if "@" in value:
        score += 20; findings.append("The @ symbol can hide the destination in a URL.")
    if len(host) > 28:
        score += 10; findings.append("The domain name is unusually long.")
    if host.count("-") >= 2:
        score += 10; findings.append("Several hyphens appear in the hostname.")
    words=["login","verify","wallet","update","secure","gift","prize","banking","urgent","claim"]
    found=[word for word in words if word in value.lower()]
    if found:
        score += min(20,len(found)*5); findings.append("Keyword flag(s): "+", ".join(found)+". Check context carefully.")
    if not findings: findings.append("No simple heuristic flags were triggered. This is not a guarantee of safety.")
    score=min(score,100)
    return {"score":score,"level":"High review" if score>=55 else ("Caution" if score>=25 else "Lower heuristic risk"),
            "findings":findings,"host":host}

init_db()

@app.route("/signup", methods=["GET","POST"])
def signup():
    if session.get("user_id"): return redirect(url_for("dashboard"))
    if request.method == "POST":
        name=request.form.get("name","").strip()
        email=request.form.get("email","").strip().lower()
        password=request.form.get("password","")
        confirm=request.form.get("confirm_password","")
        if not name or len(name)>80 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email):
            flash("Enter a name and a valid email address.", "error")
        elif len(password)<10 or not re.search(r"[A-Za-z]",password) or not re.search(r"\d",password):
            flash("Use at least 10 characters, including letters and numbers.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            try:
                with connect() as con:
                    cur=con.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                        (name,email,generate_password_hash(password), "analyst", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                    # Attach starter teaching examples to the first account, never label them as real cases.
                    con.execute("UPDATE incidents SET user_id=? WHERE user_id IS NULL",(cur.lastrowid,))
                flash("Account created. Log in to open your workspace.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("An account with this email already exists.", "error")
    return render_template("signup.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if session.get("user_id"): return redirect(url_for("dashboard"))
    if request.method == "POST":
        email=request.form.get("email","").strip().lower()
        password=request.form.get("password","")
        with connect() as con:
            user=con.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
        if user and check_password_hash(user["password_hash"],password):
            session.clear()
            session["user_id"]=user["id"]; session["user_name"]=user["name"]; session["role"]=user["role"]
            log_action("LOGIN","Successful login")
            return redirect(url_for("dashboard"))
        flash("Email or password is incorrect.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    log_action("LOGOUT","User logged out")
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    stats=read_stats(); uid=session["user_id"]
    with connect() as con:
        incidents=con.execute("SELECT * FROM incidents WHERE user_id=? ORDER BY id DESC",(uid,)).fetchall()
        total=con.execute("SELECT COUNT(*) FROM incidents WHERE user_id=?",(uid,)).fetchone()[0]
        open_count=con.execute("SELECT COUNT(*) FROM incidents WHERE user_id=? AND status IN ('New','Under review')",(uid,)).fetchone()[0]
        amount=con.execute("SELECT COALESCE(SUM(amount),0) FROM incidents WHERE user_id=?",(uid,)).fetchone()[0]
    growth=round((stats[-1]["cases"]-stats[-2]["cases"])/stats[-2]["cases"]*100,1)
    return render_template("index.html",stats=stats,incidents=incidents[:6],total=total,open_count=open_count,amount=amount,growth=growth)

@app.route("/cases")
@login_required
def cases():
    q=request.args.get("q","").strip(); status=request.args.get("status",""); uid=session["user_id"]
    with connect() as con:
        sql="SELECT * FROM incidents WHERE user_id=?"; params=[uid]
        if q:
            sql+=" AND (title LIKE ? OR category LIKE ? OR state LIKE ? OR description LIKE ?)"
            params += [f"%{q}%"]*4
        if status: sql+=" AND status=?"; params.append(status)
        sql+=" ORDER BY id DESC"
        rows=con.execute(sql,params).fetchall()
    return render_template("cases.html",incidents=rows,q=q,selected_status=status)

@app.route("/report",methods=["GET","POST"])
@login_required
def report():
    if request.method=="POST":
        title=request.form.get("title","").strip(); category=request.form.get("category","").strip()
        state=request.form.get("state","").strip(); amount=request.form.get("amount","0").strip()
        status=request.form.get("status","New"); desc=request.form.get("description","").strip()
        evidence=request.form.get("evidence","").strip()
        if not title or not category or not state or not desc:
            flash("Please complete all required fields.","error"); return redirect(url_for("report"))
        try: amount=max(0,float(amount or 0))
        except ValueError: amount=0
        digest=hashlib.sha256(evidence.encode("utf-8")).hexdigest() if evidence else ""
        with connect() as con:
            con.execute("""INSERT INTO incidents(title,category,state,amount,status,description,created_at,evidence_hash,user_id)
                VALUES(?,?,?,?,?,?,?,?,?)""",(title,category,state,amount,status,desc,datetime.now().strftime("%Y-%m-%d %H:%M"),digest,session["user_id"]))
        log_action("INCIDENT_CREATED",title)
        flash("Incident saved to your account. This demo does not send a report to the police.","success")
        return redirect(url_for("cases"))
    return render_template("report.html")

@app.route("/analyzer",methods=["GET","POST"])
@login_required
def analyzer():
    result=None; value=""
    if request.method=="POST":
        value=request.form.get("url",""); result=url_check(value)
        log_action("URL_ANALYSED","Local heuristic URL check")
    return render_template("analyzer.html",result=result,value=value)

@app.route("/incident/<int:incident_id>/status",methods=["POST"])
@login_required
def update_status(incident_id):
    status=request.form.get("status","New")
    if status not in ["New","Under review","Escalated","Closed"]: status="New"
    with connect() as con:
        cur=con.execute("UPDATE incidents SET status=? WHERE id=? AND user_id=?",(status,incident_id,session["user_id"]))
    if cur.rowcount: log_action("STATUS_UPDATED",f"Incident TD-{incident_id:04d}: {status}")
    else: flash("Incident not found in your account.","error")
    flash("Case status updated.","success")
    return redirect(request.referrer or url_for("cases"))

@app.route("/export")
@login_required
def export():
    with connect() as con:
        rows=con.execute("SELECT id,title,category,state,amount,status,description,created_at,evidence_hash FROM incidents WHERE user_id=? ORDER BY id",(session["user_id"],)).fetchall()
    output=io.StringIO(); writer=csv.writer(output)
    writer.writerow(["id","title","category","state","amount_inr","status","description","created_at","evidence_sha256"])
    writer.writerows([tuple(r) for r in rows]); output.seek(0)
    log_action("CSV_EXPORTED",f"Exported {len(rows)} incident records")
    return send_file(io.BytesIO(output.getvalue().encode("utf-8-sig")),mimetype="text/csv",as_attachment=True,download_name="cybercrime_incidents.csv")

@app.route("/audit")
@login_required
def audit():
    with connect() as con:
        rows=con.execute("SELECT action,detail,created_at FROM audit_logs WHERE user_id=? ORDER BY id DESC LIMIT 100",(session["user_id"],)).fetchall()
    return render_template("audit.html",logs=rows)

@app.route("/data")
def data_page():
    return render_template("data.html",stats=read_stats())

if __name__=="__main__":
    app.run(debug=True)
