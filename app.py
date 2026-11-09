"""Membership -> QR certificate / NOC -> public verification.

A small Flask + SQLite prototype built to learn the workflow of an
association's membership and certificate portal. Not production-ready.
"""
import hmac
import io
import os
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from datetime import date, timedelta
from functools import wraps

import qrcode
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MEMBER_TYPES = ('individual', 'corporate', 'student')

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-only-change-me'),
    DB_PATH=os.environ.get('DB_PATH', os.path.join(BASE_DIR, 'bsrea_demo.db')),
    BASE_URL=os.environ.get('BASE_URL', ''),  # public URL encoded in QR codes
    ADMIN_PASSWORD=os.environ.get('ADMIN_PASSWORD', 'admin123'),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)


# ---------- database ----------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DB_PATH'])
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    with open(os.path.join(BASE_DIR, 'schema.sql')) as f:
        db.executescript(f.read())
    if db.execute('SELECT COUNT(*) FROM admins').fetchone()[0] == 0:
        db.execute('INSERT INTO admins (username, password_hash) VALUES (?, ?)',
                   ('admin', generate_password_hash(app.config['ADMIN_PASSWORD'])))
        db.commit()


# ---------- security helpers ----------
def csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_urlsafe(24)
    return session['_csrf']


app.jinja_env.globals['csrf_token'] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == 'POST':
        sent = request.form.get('_csrf', '').encode()
        expected = session.get('_csrf', '').encode()
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, 'Invalid or missing CSRF token')


@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'same-origin'
    return resp


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


_hits = defaultdict(deque)


def rate_limited(key, limit=30, window=60):
    """Tiny in-memory limiter for the public verify endpoint (demo only)."""
    now = time.time()
    q = _hits[key]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


# ---------- domain logic ----------
def doc_state(doc):
    if doc['status'] == 'revoked':
        return 'revoked'
    if doc['expires_at'] and doc['expires_at'] < date.today().isoformat():
        return 'expired'
    return 'valid'


def issue_document(db, member_id, doc_type, purpose=None, days=365):
    """Insert a document row. Call inside `with db:` so it commits atomically."""
    year = date.today().year
    prefix = 'BSREA' if doc_type == 'CERT' else 'NOC'
    count = db.execute(
        'SELECT COUNT(*) FROM documents WHERE doc_type = ? AND doc_no LIKE ?',
        (doc_type, f'{prefix}-{year}-%')).fetchone()[0]
    doc_no = f'{prefix}-{year}-{count + 1:04d}'
    token = secrets.token_urlsafe(16)  # unguessable; this is what the QR carries
    expires = (date.today() + timedelta(days=days)).isoformat()
    db.execute(
        'INSERT INTO documents (member_id, doc_type, doc_no, token, purpose, expires_at) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (member_id, doc_type, doc_no, token, purpose, expires))
    return doc_no


def verify_url(token):
    base = app.config['BASE_URL'].rstrip('/') or request.url_root.rstrip('/')
    return base + url_for('verify', token=token)


# ---------- public pages ----------
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/apply', methods=['GET', 'POST'])
def apply():
    if request.method == 'POST':
        name = request.form.get('full_name', '').strip()
        org = request.form.get('organization', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        mtype = request.form.get('member_type', 'individual')
        errors = []
        if not (2 <= len(name) <= 120):
            errors.append('Enter your full name (2-120 characters).')
        if '@' not in email or '.' not in email.split('@')[-1] or len(email) > 120:
            errors.append('Enter a valid email address.')
        if mtype not in MEMBER_TYPES:
            errors.append('Choose a valid membership type.')
        if len(org) > 160 or len(phone) > 20:
            errors.append('Organization or phone is too long.')
        if errors:
            for e in errors:
                flash(e)
            return render_template('apply.html', types=MEMBER_TYPES), 400
        try:
            db = get_db()
            with db:
                db.execute(
                    'INSERT INTO members (full_name, organization, email, phone, member_type) '
                    'VALUES (?, ?, ?, ?, ?)', (name, org, email, phone, mtype))
        except sqlite3.IntegrityError:
            flash('This email has already applied.')
            return render_template('apply.html', types=MEMBER_TYPES), 400
        flash('Application received. You will be notified after review.')
        return redirect(url_for('home'))
    return render_template('apply.html', types=MEMBER_TYPES)


@app.route('/verify')
def verify_form():
    code = request.args.get('code', '').strip()
    if code:
        return redirect(url_for('verify', token=code))
    return render_template('verify.html', doc=None, state=None)


@app.route('/verify/<token>')
def verify(token):
    ip = request.remote_addr or 'unknown'
    if rate_limited(ip):
        abort(429)
    db = get_db()
    doc = db.execute(
        'SELECT d.*, m.full_name, m.organization, m.member_type '
        'FROM documents d JOIN members m ON m.id = d.member_id WHERE d.token = ?',
        (token,)).fetchone()
    if doc:
        with db:
            db.execute('INSERT INTO verification_log (document_id, ip) VALUES (?, ?)',
                       (doc['id'], ip))
    return render_template('verify.html', doc=doc,
                           state=doc_state(doc) if doc else 'not_found')


@app.route('/qr/<token>.png')
def qr_png(token):
    if not get_db().execute('SELECT 1 FROM documents WHERE token = ?', (token,)).fetchone():
        abort(404)
    img = qrcode.make(verify_url(token),
                      error_correction=qrcode.constants.ERROR_CORRECT_M,
                      box_size=8, border=4)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')


# ---------- admin ----------
@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        row = get_db().execute('SELECT * FROM admins WHERE username = ?',
                               (request.form.get('username', ''),)).fetchone()
        if row and check_password_hash(row['password_hash'], request.form.get('password', '')):
            session.clear()
            session['admin'] = True
            return redirect(url_for('admin'))
        flash('Wrong username or password.')
        return render_template('login.html'), 401
    return render_template('login.html')


@app.route('/admin/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/admin')
@login_required
def admin():
    db = get_db()
    members = db.execute('SELECT * FROM members ORDER BY id DESC').fetchall()
    rows = db.execute(
        'SELECT d.*, m.full_name, '
        '(SELECT COUNT(*) FROM verification_log v WHERE v.document_id = d.id) AS scans '
        'FROM documents d JOIN members m ON m.id = d.member_id ORDER BY d.id DESC').fetchall()
    docs = [dict(r, state=doc_state(r)) for r in rows]
    return render_template('admin.html', members=members, docs=docs)


@app.route('/admin/members/<int:member_id>/approve', methods=['POST'])
@login_required
def approve(member_id):
    db = get_db()
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member or member['status'] != 'pending':
        abort(400, 'Only pending members can be approved')
    with db:  # one transaction: approve + issue certificate, or neither
        db.execute("UPDATE members SET status = 'approved' WHERE id = ?", (member_id,))
        doc_no = issue_document(db, member_id, 'CERT', days=365)
    flash(f'Approved {member["full_name"]}. Certificate {doc_no} issued.')
    return redirect(url_for('admin'))


@app.route('/admin/members/<int:member_id>/reject', methods=['POST'])
@login_required
def reject(member_id):
    db = get_db()
    with db:
        db.execute("UPDATE members SET status = 'rejected' WHERE id = ? AND status = 'pending'",
                   (member_id,))
    flash('Application rejected.')
    return redirect(url_for('admin'))


@app.route('/admin/members/<int:member_id>/noc', methods=['POST'])
@login_required
def issue_noc(member_id):
    db = get_db()
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member or member['status'] != 'approved':
        abort(400, 'NOC can only be issued to approved members')
    purpose = request.form.get('purpose', '').strip()[:255]
    try:
        days = max(1, min(int(request.form.get('days', '90')), 730))
    except ValueError:
        days = 90
    if not purpose:
        flash('Enter the purpose of the NOC.')
        return redirect(url_for('admin'))
    with db:
        doc_no = issue_document(db, member_id, 'NOC', purpose=purpose, days=days)
    flash(f'NOC {doc_no} issued.')
    return redirect(url_for('admin'))


@app.route('/admin/documents/<int:doc_id>')
@login_required
def view_document(doc_id):
    doc = get_db().execute(
        'SELECT d.*, m.full_name, m.organization, m.member_type '
        'FROM documents d JOIN members m ON m.id = d.member_id WHERE d.id = ?',
        (doc_id,)).fetchone()
    if not doc:
        abort(404)
    return render_template('document.html', doc=doc, state=doc_state(doc))


@app.route('/admin/documents/<int:doc_id>/revoke', methods=['POST'])
@login_required
def revoke(doc_id):
    db = get_db()
    with db:
        db.execute("UPDATE documents SET status = 'revoked' WHERE id = ?", (doc_id,))
    flash('Document revoked. Its QR code will now show REVOKED.')
    return redirect(url_for('admin'))


# ---------- CLI ----------
@app.cli.command('seed-demo')
def seed_demo():
    """Add sample members so the admin page is not empty."""
    init_db()
    db = get_db()
    people = [('Nusrat Jahan', 'GreenGrid Ltd', 'nusrat@example.com', 'corporate'),
              ('Tanvir Hasan', '', 'tanvir@example.com', 'individual'),
              ('Farhana Akter', 'Dhaka University', 'farhana@example.com', 'student')]
    for name, org, email, mtype in people:
        try:
            with db:
                db.execute('INSERT INTO members (full_name, organization, email, member_type) '
                           'VALUES (?, ?, ?, ?)', (name, org, email, mtype))
        except sqlite3.IntegrityError:
            pass
    print('Seeded. Log in at /admin/login (user: admin).')


with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(host=os.environ.get('HOST', '127.0.0.1'),
            port=int(os.environ.get('PORT', '5000')), debug=False)
