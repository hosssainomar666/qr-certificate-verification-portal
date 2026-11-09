# BSREA-style membership and QR certificate demo

A small working prototype of the workflow: online membership, certificates with QR codes, a NOC portal and public online verification. Built with Python, Flask and SQLite so it runs on any laptop with no database server.



## Run it (5 minutes)

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
flask --app app seed-demo         # optional: adds 3 sample applicants
python app.py                     # open http://127.0.0.1:5000
```

Admin login: user `admin`, password `admin123` (change with `ADMIN_PASSWORD=...` before first run).

Run the tests: `python test_app.py`

### Scan the QR with your phone
The QR encodes a web address, so your phone must reach your laptop (same Wi-Fi):

```bash
HOST=0.0.0.0 BASE_URL=http://YOUR-LAPTOP-IP:5000 python app.py
```
On Windows PowerShell: `$env:HOST="0.0.0.0"; $env:BASE_URL="http://YOUR-LAPTOP-IP:5000"; python app.py`

## Demo script (2 minutes)
1. Open /apply and submit a member.
2. Log in at /admin, click **Approve and issue certificate**.
3. Open **View and print**. Scan the QR with your phone: it shows VALID.
4. Issue a NOC to that member and verify it the same way.
5. Click **Revoke**, scan again: it shows REVOKED. The scan counter in the admin table goes up.
6. Type a wrong code in /verify: NOT FOUND.

## How it maps to the job ad

| Ad requirement | Where in the code |
|---|---|
| Online membership system | `/apply`, `members` table, approve/reject in `app.py` |
| Digital membership certificate with QR | `issue_document()`, `/qr/<token>.png`, `document.html` |
| NOC and certificate portal with online verification | `issue_noc()`, `/verify/<token>`, `verify.html` |
| Database management | `schema.sql` (3 main tables, constraints, indexes, foreign keys) |
| Secure web practice | see below |

## Design decisions to explain
- The QR holds only a URL with a random token (`secrets.token_urlsafe`). All trust lives in the database, so documents can be revoked and cannot be forged by printing a fake QR.
- The readable number (BSREA-2026-0001) is sequential and guessable, so it is never used for lookup.
- Approval and certificate creation happen in one transaction (`with db:`): both succeed or neither does.
- Public verify page shows only name, type, number, purpose and dates. No email or phone.
- Status is computed on every scan: valid, expired (past `expires_at`) or revoked.
- Every scan is logged in `verification_log` (audit trail, misuse detection).

## Security features included
Parameterized SQL everywhere (no string-built queries), Jinja auto-escaping against XSS, hashed admin password, CSRF token on every POST, session cookie flags, basic security headers, input validation, and a simple rate limit on the verify endpoint. Tests cover SQL-injection strings, XSS, CSRF and data leakage.

## Honest limitations (say these in an interview)
Single admin account, in-memory rate limit, no email notifications, no payment step, no PDF signing, default dev secret key. For real use: HTTPS, a strong `SECRET_KEY`, a proper database (MySQL/PostgreSQL), 2FA, backups.

## Moving this design to WordPress and MySQL
- Members and documents become custom post types (or custom tables) with the same fields.
- Membership roles: a membership plugin or a custom role.
- The verify page becomes a shortcode that runs a prepared query (`$wpdb->prepare`) and escapes output (`esc_html`). A sample is in the study guide.
- QR generation: PHP library `endroid/qr-code` inside a small plugin.
- The SQL in `schema.sql` ports directly; swap `INTEGER PRIMARY KEY AUTOINCREMENT` for `INT AUTO_INCREMENT PRIMARY KEY`, and `TEXT` dates for `DATETIME`.

## Files
- `app.py` routes, security helpers, business logic
- `schema.sql` database design
- `templates/` pages (base, apply, login, admin, document, verify)
- `test_app.py` automated tests
