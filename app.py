
import os
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key-before-public-use"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Database
Path(app.instance_path).mkdir(parents=True, exist_ok=True)
DATABASE = os.path.join(app.instance_path, "scamshield.db")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"
}

SUSPICIOUS_WORDS = {
    "login", "verify", "secure", "account", "update",
    "banking", "wallet", "password", "payment",
    "urgent", "claim", "free"
}


def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with closing(get_db()) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                level TEXT NOT NULL,
                score INTEGER NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        """)
        db.commit()


init_db()


def assess_url(raw_url):
    value = raw_url.strip()

    if not value:
        return {
            "score": 0,
            "level": "No result",
            "reasons": ["Enter a website address first."]
        }

    candidate = (
        value if re.match(r"^https?://", value, re.I)
        else "https://" + value
    )

    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
    except ValueError:
        host = ""

    if not host or "." not in host:
        return {
            "score": 0,
            "level": "Invalid URL",
            "reasons": ["The address could not be parsed."]
        }

    score = 0
    reasons = []

    if parsed.scheme != "https":
        score += 15
        reasons.append("The address does not use HTTPS.")

    if "@" in parsed.netloc:
        score += 25
        reasons.append(
            "The address contains an @ symbol, which can hide the real destination."
        )

    if host.startswith("xn--") or ".xn--" in host:
        score += 20
        reasons.append(
            "The domain uses internationalized/punycode characters."
        )

    if host in SHORTENERS:
        score += 20
        reasons.append(
            "The domain is a URL-shortening service, so the final destination is hidden."
        )

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 25
        reasons.append(
            "The website uses an IP address instead of a typical domain name."
        )

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
            "The address contains words often used in deceptive messages: "
            + ", ".join(found) + "."
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
            "No indicators from this simple checklist were detected."
        )

    reasons.append(
        "This is a prototype heuristic check, not proof that a site is safe or malicious."
    )

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    submitted = ""

    if request.method == "POST":
        submitted = request.form.get("url", "").strip()
        result = assess_url(submitted)

        # Save scan for logged-in users
        if session.get("user_id") and submitted:
            with closing(get_db()) as db:
                db.execute(
                    """
                    INSERT INTO scans (user_id, url, level, score)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        session["user_id"],
                        submitted,
                        result["level"],
                        result["score"]
                    )
                )
                db.commit()

    return render_template(
        "index.html",
        result=result,
        submitted=submitted
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 30:
            flash("Username must be between 3 and 30 characters.")
            return render_template("register.html")

        if not re.fullmatch(r"[A-Za-z0-9_]+", username):
            flash("Username can contain only letters, numbers and underscores.")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return render_template("register.html")

        with closing(get_db()) as db:
            existing = db.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if existing:
                flash("This username is already taken.")
                return render_template("register.html")

            cursor = db.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
                """,
                (username, generate_password_hash(password))
            )
            db.commit()
            user_id = cursor.lastrowid

        session.clear()
        session["user_id"] = user_id
        session["username"] = username

        flash("Your account was created successfully!")
        return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with closing(get_db()) as db:
            user = db.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("You are now logged in.")
            return redirect(url_for("index"))

        flash("Incorrect username or password.")

    return render_template("login.html")


@app.route("/history")
def history():
    if not session.get("user_id"):
        flash("Please log in to view your scan history.")
        return redirect(url_for("login"))

    with closing(get_db()) as db:
        rows = db.execute(
            """
            SELECT url, level, score, created_at
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 100
            """,
            (session["user_id"],)
        ).fetchall()

    return render_template(
        "history.html",
        history=[dict(row) for row in rows]
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("index"))


@app.route("/google05f32e3f870045f3.html")
def google_verification():
    return send_from_directory(
        app.root_path,
        "google05f32e3f870045f3.html"
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
