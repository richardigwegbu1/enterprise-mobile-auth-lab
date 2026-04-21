from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import jwt
import datetime
import random
import sqlite3
import os
import logging
from functools import wraps
import requests

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "app", "auth.db")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_PATH = os.path.join(LOG_DIR, "app.log")

SECRET_KEY = "ChangeThisFlaskSecretInProduction"
JWT_SECRET = "ChangeThisJWTSecretInProduction"
JWT_ALGO = "HS256"

os.makedirs(LOG_DIR, exist_ok=True)

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "app", "templates"),
    static_folder=os.path.join(BASE_DIR, "app", "static"),
)
app.secret_key = SECRET_KEY

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS otp_store (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            otp TEXT NOT NULL,
            created_at TEXT NOT NULL,
            verified INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            event TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()

    cur.execute("SELECT * FROM users WHERE username = ?", ("richard",))
    existing = cur.fetchone()
    if not existing:
        cur.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("richard", "Password123!", "admin")
        )
        conn.commit()

    conn.close()

def write_audit(username, event, details=""):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit_log (username, event, details, created_at) VALUES (?, ?, ?, ?)",
        (username, event, details, datetime.datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    logging.info(f"user={username} event={event} details={details}")

def generate_otp():
    return str(random.randint(100000, 999999))

def create_token(username, role):
    payload = {
        "sub": username,
        "role": role,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing bearer token"}), 401

        token = auth_header.split(" ", 1)[1]
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            request.user = decoded
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception as e:
            return jsonify({"error": f"Invalid token: {str(e)}"}), 401

        return f(*args, **kwargs)
    return decorated

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "enterprise-mobile-auth-lab"})

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, password, role FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()

    if not user or password != user[1]:
        write_audit(username, "LOGIN_FAILED", "Invalid username or password")
        return render_template("index.html", error="Invalid username or password")

    otp = generate_otp()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO otp_store (username, otp, created_at, verified) VALUES (?, ?, ?, ?)",
        (username, otp, datetime.datetime.utcnow().isoformat(), 0)
    )
    conn.commit()
    conn.close()

    session["username"] = username
    write_audit(username, "LOGIN_SUCCESS", f"OTP generated={otp}")
    return render_template("otp.html", username=username, otp=otp)

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    username = session.get("username")
    otp = request.form.get("otp")

    if not username:
        return redirect(url_for("index"))

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, otp, verified FROM otp_store WHERE username = ? ORDER BY id DESC LIMIT 1",
        (username,)
    )
    row = cur.fetchone()

    if not row:
        write_audit(username, "OTP_FAILED", "No OTP found")
        return render_template("otp.html", username=username, error="No OTP found")

    if otp != row[1]:
        write_audit(username, "OTP_FAILED", f"Entered OTP={otp}")
        return render_template("otp.html", username=username, otp=row[1], error="Invalid OTP")

    cur.execute("UPDATE otp_store SET verified = 1 WHERE id = ?", (row[0],))
    conn.commit()
    conn.close()

    session["otp_verified"] = True
    write_audit(username, "OTP_SUCCESS", "OTP verified")
    return render_template("biometric.html", username=username)

@app.route("/biometric", methods=["POST"])
def biometric():
    username = session.get("username")
    if not username or not session.get("otp_verified"):
        return redirect(url_for("index"))

    biometric_status = request.form.get("biometric_status")
    if biometric_status != "approved":
        write_audit(username, "BIOMETRIC_FAILED", "Biometric simulation denied")
        return render_template("biometric.html", username=username, error="Biometric verification failed")

    session["biometric_verified"] = True
    write_audit(username, "BIOMETRIC_SUCCESS", "Biometric verification approved")
    return render_template("voice.html", username=username)

@app.route("/voice", methods=["POST"])
def voice():
    username = session.get("username")
    if not username or not session.get("biometric_verified"):
        return redirect(url_for("index"))

    voice_status = request.form.get("voice_status")
    if voice_status != "approved":
        write_audit(username, "VOICE_FAILED", "Voice verification denied")
        return render_template("voice.html", username=username, error="Voice verification failed")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT role FROM users WHERE username = ?", (username,))
    result = cur.fetchone()
    conn.close()

    role = result[0] if result else "user"
    token = create_token(username, role)

    session["jwt"] = token
    write_audit(username, "VOICE_SUCCESS", "Voice verification approved")
    write_audit(username, "TOKEN_ISSUED", "JWT created")

    return render_template("success.html", username=username, token=token)

@app.route("/api/token")
def api_token():
    token = session.get("jwt")
    if not token:
        return jsonify({"error": "No token available"}), 401
    return jsonify({"token": token})

@app.route("/api/protected")
@token_required
def protected():
    return jsonify({
        "message": "Protected API access granted",
        "user": request.user["sub"],
        "role": request.user["role"]
    })

@app.route("/api/mobile-profile")
@token_required
def mobile_profile():
    return jsonify({
        "customer": request.user["sub"],
        "auth_methods": ["password", "otp", "biometric", "voice"],
        "status": "authenticated"
    })

@app.route("/api/tomcat-check")
@token_required
def tomcat_check():
    try:
        response = requests.get("http://127.0.0.1:8080/demo-auth/status.jsp", timeout=5)
        return jsonify({
            "flask_status": "ok",
            "tomcat_status_code": response.status_code,
            "tomcat_response": response.text.strip()
        })
    except Exception as e:
        return jsonify({
            "flask_status": "ok",
            "tomcat_error": str(e)
        }), 500

@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    write_audit(username, "LOGOUT", "User logged out")
    return redirect(url_for("index"))

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000)
