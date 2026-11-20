# SCAMSHIELD AI — Link Risk Checker (MVP)

## Problem
People receive links in messages and search results that may lead to deceptive websites. It can be difficult to recognize warning signs before clicking.

## Solution
SCAMSHIELD is a small educational prototype. A user pastes a URL as text. The app checks for selected warning signs (for example, URL shorteners, unusual domain structure, an IP-address host, and suspicious terms) and explains the result.

## Important technical note
Despite the project name, this first MVP is **not a trained AI model**. It uses transparent, hand-written heuristic rules. The score is an indicator for demonstration only; it is not a probability, a verdict, or a guarantee of safety. A low score does not prove a site is safe. No website is opened and no external threat-intelligence service is queried.

## Architecture
- `app.py`: Flask web server and URL inspection rules.
- `templates/index.html`: user interface and result explanation.
- `static/style.css`: visual styling.
- `requirements.txt`: Python dependency list.

## Technology choices and trade-offs
- **Python + Flask:** lightweight and easy to run for a prototype.
- **Rule-based checks:** explainable and do not require collecting user data or training a model.
- **No external API:** avoids sending submitted URLs to a third party, but means the app cannot check live reputation databases.
- **No database:** keeps the MVP simple; scan history is not saved.
- **Future improvement:** add a properly evaluated machine-learning classifier and a reputable URL reputation feed, with privacy review, rate limiting, false-positive testing, and clear user consent.

## Build and run
1. Install Python 3.10 or newer.
2. Open a terminal in this folder.
3. Create and activate a virtual environment (optional but recommended):
   - Windows: `py -m venv .venv` then `.venv\\Scripts\\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Start the app: `python app.py`
6. Open `http://127.0.0.1:5000` in your browser.

## Test examples
Try typing these as text into the checker:
- `https://example.com`
- `http://secure-login-example.test/verify`
- `https://bit.ly/sample`

These are demonstration inputs only. Do not visit suspicious websites.

## Privacy design
- The app processes the submitted URL on the local server.
- It does not save scan history.
- It does not intentionally transmit the URL to an external service.
- Do not submit personal, private, or confidential URLs during demonstrations.

## Limitations
- Heuristic scores can produce false positives and false negatives.
- The app does not verify website ownership, certificates, page contents, or current threat reports.
- The app does not establish that a website is safe.
- The development server is for local demonstration, not production deployment.

## Team and submission checklist
- Confirm the event's team-size and age/consent rules with the organizers.
- Add the real team members and their contributions to the presentation.
- Test the project on the presentation computer.
- Push the complete project to the required GitHub branch (`master`, as stated in the event terms).
- Submit the GitHub repository link through the official submission web app before the deadline.
