from flask import Flask, render_template, request, redirect
import sqlite3
import bcrypt
from datetime import datetime, timedelta
import json
import os

def log_event(username, event, risk):

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "event": event,
        "risk": risk
    }

    os.makedirs("logs", exist_ok=True)

    with open("logs/security_logs.json", "a") as f:
        f.write(json.dumps(log_entry) + "\n")
        print("LOG EVENT:", log_entry)

app = Flask(__name__)

DATABASE = "database.db"

# -----------------------
# Database Initialization
# -----------------------
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        lockout_time TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# -----------------------
# Home Route
# -----------------------
@app.route("/")
def home():
    return redirect("/register")


# -----------------------
# Registration Page
# -----------------------
@app.route("/register")
def register():
    return render_template("register.html")


# -----------------------
# Registration Logic
# -----------------------
@app.route("/register_user", methods=["POST"])
def register_user():

    username = request.form["username"]
    password = request.form["password"]

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hashed_password)
        )

        conn.commit()
        conn.close()

        return "User registered successfully!"

    except sqlite3.IntegrityError:
        return "Username already exists!"


# -----------------------
# Login Page
# -----------------------
@app.route("/login")
def login():
    return render_template("login.html")

# -----------------------
# Login Authentication
# -----------------------
@app.route("/login_user", methods=["POST"])
def login_user():

    username = request.form["username"]
    password = request.form["password"]

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password_hash, failed_attempts, lockout_time FROM users WHERE username = ?",
        (username,)
    )

    user = cursor.fetchone()

    if user is None:
        conn.close()
        return "User not found!"

    stored_hash, failed_attempts, lockout_time = user

    #Check if account is locked
    if lockout_time:
        unlock_time = datetime.fromisoformat(lockout_time)

        if datetime.now() < unlock_time:
            conn.close()
            return f"Account locked until {unlock_time}"

    # Verify password
    if bcrypt.checkpw(password.encode(), stored_hash):

        # Reset failed attempts on success
        cursor.execute(
            "UPDATE users SET failed_attempts = 0, lockout_time = NULL WHERE username = ?",
            (username,)
        )

        conn.commit()
        conn.close()

        log_event(username, "login_success", "low")

        return redirect("/dashboard")

    else:

        failed_attempts += 1
         
        log_event(username, "failed_login", "medium")

    if failed_attempts >= 5:

        lockout_until = datetime.now() + timedelta(minutes=5)

        cursor.execute(
            "UPDATE users SET failed_attempts = ?, lockout_time = ? WHERE username = ?",
            (failed_attempts, lockout_until.isoformat(), username)
        )

        conn.commit()
        conn.close()

        log_event(username, "account_lockout", "high")

        return "Account locked for 5 minutes due to too many failed attempts."

    else:

        cursor.execute(
            "UPDATE users SET failed_attempts = ? WHERE username = ?",
            (failed_attempts, username)
        )

    conn.commit()
    conn.close()

    return f"Invalid password! Failed attempts: {failed_attempts}"


@app.route("/dashboard")
def dashboard():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users WHERE lockout_time IS NOT NULL")
    locked_accounts = cursor.fetchone()[0]

    conn.close()

    failed_logins = 0
    lockouts = 0
    events = []

    try:
        with open("logs/security_logs.json", "r") as f:

            for line in f:
                log = json.loads(line)

                events.append(log)

                if log["event"] == "failed_login":
                    failed_logins += 1

                if log["event"] == "account_lockout":
                    lockouts += 1

    except FileNotFoundError:
        pass

    # Threat level calculation
    if failed_logins >= 8:
        threat_level = "HIGH"
    elif failed_logins >= 4:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    events = events[-10:]

    return render_template(
        "dashboard.html",
        total_users=total_users,
        failed_logins=failed_logins,
        lockouts=lockouts,
        locked_accounts=locked_accounts,
        threat_level=threat_level,
        events=events
    )


# -----------------------
# Run Flask Server
# -----------------------
if __name__ == "__main__":
    app.run(debug=True)