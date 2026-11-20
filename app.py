from flask import Flask, render_template, request, send_from_directory
from urllib.parse import urlparse
import re

app = Flask(__name__)

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
SUSPICIOUS_WORDS = {"login", "verify", "secure", "account", "update", "banking",
                    "wallet", "password", "payment", "urgent", "claim", "free"}

def assess_url(raw_url):
    value = raw_url.strip()
    if not value:
        return {"score": 0, "level": "No result", "reasons": ["Enter a website address first."]}

    candidate = value if re.match(r"^https?://", value, re.I) else "https://" + value
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    if not host or "." not in host:
        return {"score": 0, "level": "Invalid URL", "reasons": ["The address could not be parsed."]}

    score, reasons = 0, []
    if parsed.scheme != "https":
        score += 15
        reasons.append("The address does not use HTTPS.")
    if "@" in parsed.netloc:
        score += 25
        reasons.append("The address contains an @ symbol, which can hide the real destination.")
    if host.startswith("xn--") or ".xn--" in host:
        score += 20
        reasons.append("The domain uses internationalized/punycode characters.")
    if host in SHORTENERS:
        score += 20
        reasons.append("The domain is a URL-shortening service, so the final destination is hidden.")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 25
        reasons.append("The website uses an IP address instead of a typical domain name.")
    if len(host) > 30:
        score += 10
        reasons.append("The domain name is unusually long.")
    if host.count("-") >= 2:
        score += 10
        reasons.append("The domain contains several hyphens.")
    found = sorted(word for word in SUSPICIOUS_WORDS if word in (host + parsed.path).lower())
    if found:
        score += min(20, 5 * len(found))
        reasons.append("The address contains words often used in deceptive messages: " + ", ".join(found) + ".")
    score = min(score, 100)
    if score >= 50:
        level = "High risk indicators"
    elif score >= 25:
        level = "Some risk indicators"
    else:
        level = "Few risk indicators detected"
    if not reasons:
        reasons.append("No indicators from this simple checklist were detected.")
    reasons.append("This is a prototype heuristic check, not proof that a site is safe or malicious.")
    return {"score": score, "level": level, "reasons": reasons}

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    submitted = ""
    if request.method == "POST":
        submitted = request.form.get("url", "")
        result = assess_url(submitted)
    return render_template("index.html", result=result, submitted=submitted)
@app.route("/google05f32e3f870045f3.html")
def google_verification():
    return send_from_directory(
        app.root_path,
        "google05f32e3f870045f3.html"
    )
if __name__ == "__main__":
    app.run(debug=True)
