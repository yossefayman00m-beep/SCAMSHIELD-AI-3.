
import os
import re
import sqlite3
import ipaddress
from urllib.parse import urlparse
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, g, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY", "scamshield-development-key-change-before-production"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("RENDER") is not None,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024
)

# Database
os.makedirs(app.instance_path, exist_ok=True)

DATABASE = os.environ.get(
    "DATABASE_PATH",
    os.path.join(app.instance_path, "scamshield.db")
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co",
    "goo.gl", "is.gd", "ow.ly", "cutt.ly"
}

SUSPICIOUS_WORDS = {
    "login", "verify", "secure", "account", "update",
    "banking", "wallet", "password", "payment",
    "urgent", "claim", "free", "confirm"
}


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                url TEXT NOT NULL,
                score INTEGER NOT NULL,
                level TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)


init_db()


@app.before_request
def load_user():
    user_id = session.get("user_id")
    g.user = None

    if user_id:
        g.user = get_db().execute(
            "SELECT id, username FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return view(**kwargs)
    return wrapped_view


# Advanced URL risk assessment
def assess_url(raw_url):
    value = raw_url.strip()

    if not value:
        return {
            "score": 0,
            "level": "No result",
            "reasons": ["Enter a website address first."]
        }

    if len(value) > 2048:
        return {
            "score": 0,
            "level": "Invalid URL",
            "reasons": ["The address is too long."]
        }

    candidate = (
        value if re.match(r"^https?://", value, re.I)
        else "https://" + value
    )

    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        host = ""
        parsed = None

    if not parsed or not host:
        return {
            "score": 0,
            "level": "Invalid URL",
            "reasons": ["The address could not be parsed."]
        }

    if any(char.isspace() for char in host):
        return {
            "score": 0,
            "level": "Invalid URL",
            "reasons": ["The domain contains invalid spaces."]
        }

    score = 0
    reasons = []

    if parsed.scheme != "https":
        score += 15
        reasons.append("The address does not use HTTPS.")

    if parsed.username or parsed.password:
        score += 25
        reasons.append(
            "The address contains login information before the domain."
        )

    if host.startswith("xn--") or ".xn--" in host:
        score += 20
        reasons.append("The domain uses internationalized characters.")

    if host in SHORTENERS:
        score += 20
        reasons.append(
            "The address uses a URL shortener that hides its destination."
        )

    try:
        ipaddress.ip_address(host)
        score += 25
        reasons.append("The website uses an IP address as its host.")
    except ValueError:
        pass

    if len(host) > 30:
        score += 10
        reasons.append("The domain name is unusually long.")

    if host.count("-") >= 2:
        score += 10
        reasons.append("The domain contains several hyphens.")

    found = sorted(
        word for word in SUSPICIOUS_WORDS
        if word in (host + parsed.path).lower()
    )

    if found:
        score += min(20, 5 * len(found))
        reasons.append(
            "Potentially deceptive words found: " + ", ".join(found)
        )

    score = min(score, 100)

    if score >= 50:
        level = "High risk indicators"
    elif score >= 25:
        level = "Some risk indicators"
    else:
        level = "Few risk indicators detected"

    if not reasons:
        reasons.append(
            "No indicators from this checklist were detected."
        )

    reasons.append(
        "This is an educational heuristic check, not proof that a website "
        "is safe or malicious. Never enter private information on an "
        "untrusted website."
    )

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }


# Home and scanner
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    submitted = ""

    if request.method == "POST":
        submitted = request.form.get("url", "").strip()
        result = assess_url(submitted)

        if g.user and result["level"] != "Invalid URL":
            get_db().execute(
                """
                INSERT INTO scans (user_id, url, score, level)
                VALUES (?, ?, ?, ?)
                """,
                (
                    g.user["id"],
                    submitted,
                    result["score"],
                    result["level"]
                )
            )
            get_db().commit()

    return render_template(
        "index.html",
        result=result,
        submitted=submitted,
        user=g.user
    )


# Registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            flash("Username must be 3-30 letters, numbers or underscores.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))

        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password))
            )
            db.commit()
            flash("Account created. You can now log in.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("This username is already taken.")
            return redirect(url_for("register"))

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash("Welcome back!")
            return redirect(url_for("index"))

        flash("Incorrect username or password.")

    return render_template("login.html")


# Logout
@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out.")
    return redirect(url_for("index"))


# Scan history
@app.route("/history")
@login_required
def history():
    scans = get_db().execute(
        """
        SELECT * FROM scans
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 100
        """,
        (g.user["id"],)
    ).fetchall()

    return render_template(
        "history.html",
        scans=scans,
        user=g.user
    )


# Delete scan history
@app.route("/history/clear", methods=["POST"])
@login_required
def clear_history():
    get_db().execute(
        "DELETE FROM scans WHERE user_id = ?",
        (g.user["id"],)
    )
    get_db().commit()

    flash("Your scan history has been cleared.")
    return redirect(url_for("history"))


# Google Search Console verification
@app.route("/google05f32e3f870045f3.html")
def google_verification():
    return send_from_directory(
        app.root_path,
        "google05f32e3f870045f3.html"
    )


if __name__ == "__main__":
    app.run(debug=True)
