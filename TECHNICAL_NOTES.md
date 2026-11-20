# Technical documentation

## Data flow
1. Participant types a URL into the browser form.
2. Flask receives the text via POST.
3. `assess_url()` parses the hostname and checks selected indicators.
4. The server returns a score, a descriptive band, and explanations.
5. The browser displays the result.

## Scoring
The score is a manually assigned sum of indicator weights, capped at 100. It is not statistically calibrated and must not be interpreted as a probability.

## Privacy and security
No scan database, analytics, third-party URL lookup, or user account is implemented. For a public deployment, disable Flask debug mode, use a production WSGI server, add input limits and abuse protections, and conduct a security review.

## Evaluation plan
A meaningful next evaluation should use a labeled, legally obtained dataset; split it into training/validation/test sets; measure precision, recall, and false-positive rate; document dataset limitations; and avoid claiming performance until measured.
