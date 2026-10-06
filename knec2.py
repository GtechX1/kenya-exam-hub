# -*- coding: utf-8 -*-
"""
Kenya Exam Hub — Flask backend.
Accounts · year-based access · IntaSend M-Pesa · password reset
"""
import os, uuid, re, sqlite3, hmac, json, logging, secrets, smtplib
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import (Flask, request, jsonify, send_file, Response, g)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import jwt

try:
    from intasend import APIService
    INTASEND_OK = True
except ImportError:
    INTASEND_OK = False
    APIService = None

try:
    from pypdf import PdfReader, PdfWriter
    PYPDF_OK = True
except ImportError:
    PYPDF_OK = False

# ── Environment ─────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
load_dotenv(dotenv_path=BASE_DIR / '.env', override=True)


def _clean_env_value(v):
    if not isinstance(v, str):
        return v
    for ch in ('\u00A0', '\u200B', '\uFEFF', '\u2060'):
        v = v.replace(ch, '')
    v = v.strip()
    for open_q, close_q in (('"', '"'), ("'", "'"),
                            ('\u201C', '\u201D'), ('\u2018', '\u2019')):
        if len(v) >= 2 and v[0] == open_q and v[-1] == close_q:
            v = v[1:-1].strip()
            break
    return v


def _env(name, required=True, default=None):
    v = os.environ.get(name, default)
    if required and not v:
        raise RuntimeError(f'{name} is not set')
    return _clean_env_value(v)


SECRET_KEY   = _env('SECRET_KEY', default='dev-secret-change-me')
JWT_SECRET   = _env('JWT_SECRET', default='dev-jwt-change-me')
ADMIN_TOKEN  = _env('ADMIN_TOKEN', required=False, default='')
PUBLISHABLE  = _env('INTASEND_PUBLISHABLE_KEY', required=False, default='')
SECRET       = _env('INTASEND_SECRET_KEY', required=False, default='')
TEST_MODE    = _env('INTASEND_TEST', required=False, default='false').lower() == 'true'
WEBHOOK_CHALLENGE = _env('INTASEND_WEBHOOK_CHALLENGE', required=False, default='keh-2026')
BASE_URL     = _env('BASE_URL', required=False, default='http://localhost:5000')
MPESA_MAX    = int(_env('MPESA_STK_LIMIT_KES', required=False, default='50000'))

SINGLE_YEAR_PRICE  = int(_env('SINGLE_YEAR_PRICE',  required=False, default='999'))
EXAM_BUNDLE_PRICE  = int(_env('EXAM_BUNDLE_PRICE',  required=False, default='1499'))
MEGA_PRICE         = int(_env('MEGA_PRICE',         required=False, default='2999'))

# SMTP (for password reset emails)
SMTP_HOST     = _env('SMTP_HOST',     required=False, default='')
SMTP_PORT     = int(_env('SMTP_PORT', required=False, default='587'))
SMTP_USER     = _env('SMTP_USER',     required=False, default='')
SMTP_PASS     = _env('SMTP_PASS',     required=False, default='')
SMTP_FROM     = _env('SMTP_FROM',     required=False, default='no-reply@kenyaexamhub.co.ke')
SMTP_FROM_NAME= _env('SMTP_FROM_NAME',required=False, default='Kenya Exam Hub')
SMTP_USE_TLS  = _env('SMTP_USE_TLS',  required=False, default='true').lower() == 'true'

PASSWORD_RESET_TTL_MIN = int(_env('PASSWORD_RESET_TTL_MIN', required=False, default='60'))

if os.environ.get('RENDER'):
    DB_PATH = '/var/data/kenya_exam_hub.db'
    UPLOAD_DIR = Path('/var/data/uploads')
else:
    DB_PATH = _env('DB_PATH', required=False, default=str(BASE_DIR / 'kenya_exam_hub.db'))
    UPLOAD_DIR = BASE_DIR / 'uploads'

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

PREVIEW_FRACTION = 0.5

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('keh')

# ── Flask ───────────────────────────────────────────────────
app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path='')
app.secret_key = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# ── Schema ──────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE, phone TEXT UNIQUE, name TEXT,
    password_hash TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS papers (
    id TEXT PRIMARY KEY, exam TEXT NOT NULL, year TEXT, subject TEXT, paper TEXT,
    title TEXT NOT NULL, hook TEXT, type TEXT NOT NULL, pages INTEGER,
    premium INTEGER DEFAULT 1, filename TEXT NOT NULL, preview_filename TEXT,
    filesize INTEGER, created_at INTEGER
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    package TEXT, product_id TEXT,
    amount_kes INTEGER NOT NULL,
    checkout_id TEXT UNIQUE, invoice_id TEXT, api_ref TEXT UNIQUE,
    status TEXT DEFAULT 'pending', phone TEXT, mpesa_reference TEXT,
    created_at TEXT, completed_at TEXT
);
CREATE TABLE IF NOT EXISTS access_grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    exam TEXT NOT NULL, year TEXT NOT NULL,
    product_id TEXT, unlocked_at TEXT,
    UNIQUE(user_id, exam, year)
);
CREATE TABLE IF NOT EXISTS enrollments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    exam TEXT NOT NULL, package TEXT, unlocked_at TEXT,
    UNIQUE(user_id, exam)
);
CREATE TABLE IF NOT EXISTS password_resets (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_papers_exam ON papers(exam);
CREATE INDEX IF NOT EXISTS idx_papers_exam_year ON papers(exam, year);
CREATE INDEX IF NOT EXISTS idx_orders_checkout ON orders(checkout_id);
CREATE INDEX IF NOT EXISTS idx_grants_user ON access_grants(user_id);
CREATE INDEX IF NOT EXISTS idx_resets_user ON password_resets(user_id);
"""


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit(); conn.close()


def migrate_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        if 'password_hash' not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
            log.info('migrated: users.password_hash')

        ocols = [r[1] for r in conn.execute("PRAGMA table_info(orders)").fetchall()]
        if 'product_id' not in ocols:
            conn.execute("ALTER TABLE orders ADD COLUMN product_id TEXT")
            log.info('migrated: orders.product_id')

        conn.execute("""
            CREATE TABLE IF NOT EXISTS access_grants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                exam TEXT NOT NULL, year TEXT NOT NULL,
                product_id TEXT, unlocked_at TEXT,
                UNIQUE(user_id, exam, year)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL
            )
        """)

        try:
            for r in conn.execute("SELECT user_id, exam, package, unlocked_at FROM enrollments").fetchall():
                conn.execute(
                    "INSERT OR IGNORE INTO access_grants (user_id, exam, year, product_id, unlocked_at) VALUES (?,?,?,?,?)",
                    (r[0], r[1], '*', r[2], r[3])
                )
        except Exception as e:
            log.warning('enrollments backfill skipped: %s', e)

        conn.commit()
    finally:
        conn.close()


init_db()
migrate_db()


def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db


@app.teardown_appcontext
def close_db(e):
    conn = g.pop('db', None)
    if conn: conn.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ── Auth helpers ────────────────────────────────────────────
def issue_token(user_id):
    return jwt.encode({
        'uid': user_id,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(days=365),
    }, JWT_SECRET, algorithm='HS256')


def current_user():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        t = request.args.get('t')
        if t: auth = 'Bearer ' + t
        else: return None
    try:
        payload = jwt.decode(auth[7:], JWT_SECRET, algorithms=['HS256'])
    except Exception:
        return None
    return db().execute('SELECT * FROM users WHERE id = ?', (payload['uid'],)).fetchone()


def require_auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if u is None:
            return jsonify({'error': 'authentication required'}), 401
        g.user = u
        return fn(*a, **kw)
    return wrapper


def admin_ok():
    if not ADMIN_TOKEN:
        log.warning('admin_ok: ADMIN_TOKEN not configured')
        return False
    given = request.headers.get('X-Admin-Token', '')
    if not given:
        log.warning('admin_ok DENY: no header from %s', request.remote_addr)
        return False
    ok = hmac.compare_digest(given, ADMIN_TOKEN)
    if not ok:
        def fp(s): return f'{s!r}' if len(s) <= 6 else f'{s[:3]!r}…{s[-3:]!r}'
        log.warning('admin_ok DENY: given len=%d %s | expected len=%d %s',
                    len(given), fp(given), len(ADMIN_TOKEN), fp(ADMIN_TOKEN))
    return ok


def normalize_phone(raw):
    if not raw: return None
    p = re.sub(r'[\s\-\(\)]', '', str(raw).strip())
    if p.startswith('+'): p = p[1:]
    if p.startswith('0'): p = '254' + p[1:]
    if not p.startswith('254'): p = '254' + p
    return p if (len(p) == 12 and p.isdigit()) else None


def is_valid_email(e):
    return bool(e) and re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]{2,}$', e)


# ── Email ───────────────────────────────────────────────────
def send_email(to_addr, subject, html_body, text_body=None):
    """
    Send transactional email. If SMTP_HOST is not configured,
    the message is logged to the Flask console instead.
    """
    if not SMTP_HOST:
        log.warning('SMTP not configured — not sending email to %s', to_addr)
        log.info('EMAIL to=%s subject=%s\n---\n%s\n---',
                 to_addr, subject, text_body or html_body)
        return False
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f'{SMTP_FROM_NAME} <{SMTP_FROM}>'
        msg['To'] = to_addr
        if text_body:
            msg.attach(MIMEText(text_body, 'plain', 'utf-8'))
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            if SMTP_USE_TLS:
                s.starttls()
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        log.info('email sent: to=%s subject=%s', to_addr, subject)
        return True
    except Exception as e:
        log.exception('email send failed to %s: %s', to_addr, e)
        return False


def build_reset_email(name, link, minutes):
    safe_name = (name or 'there').split(' ')[0]
    text = (
        f"Hi {safe_name},\n\n"
        f"We received a request to reset your Kenya Exam Hub password.\n\n"
        f"Reset it here (valid for {minutes} minutes):\n{link}\n\n"
        f"If you didn't request this, you can safely ignore the email.\n\n"
        f"— Kenya Exam Hub"
    )
    html = f"""\
<!DOCTYPE html>
<html><body style="font-family:Inter,Arial,sans-serif;background:#050814;color:#fff;padding:32px 16px">
  <div style="max-width:520px;margin:0 auto;background:#0a1224;border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:32px">
    <div style="font-family:'Fraunces',Georgia,serif;font-size:22px;font-weight:600;color:#D4AF6E;margin-bottom:18px">Kenya Exam Hub</div>
    <p style="font-size:16px;margin:0 0 16px">Hi {safe_name},</p>
    <p style="font-size:14px;line-height:1.65;color:rgba(255,255,255,.75);margin:0 0 24px">
      We received a request to reset your password. Click below to set a new one.
      This link expires in {minutes} minutes.
    </p>
    <a href="{link}" style="display:inline-block;padding:14px 26px;border-radius:100px;background:linear-gradient(135deg,#D4AF6E,#B8935A);color:#050814;font-weight:600;text-decoration:none">
      Reset my password
    </a>
    <p style="font-size:12px;line-height:1.7;color:rgba(255,255,255,.45);margin:24px 0 0">
      If the button doesn't work, paste this into your browser:<br>
      <span style="color:#D4AF6E;word-break:break-all">{link}</span>
    </p>
    <p style="font-size:12px;line-height:1.7;color:rgba(255,255,255,.45);margin:16px 0 0">
      If you didn't request this, you can safely ignore this email.
    </p>
  </div>
</body></html>"""
    return text, html


# ── Access grant helpers ────────────────────────────────────
def user_has_access(user_id, exam, year):
    if not user_id:
        return False
    rows = db().execute(
        'SELECT exam, year FROM access_grants WHERE user_id=?', (user_id,)
    ).fetchall()
    for r in rows:
        exam_ok = (r['exam'] == exam) or (r['exam'] == '*')
        year_ok = (r['year'] == year) or (r['year'] == '*')
        if exam_ok and year_ok:
            return True
    return False


def _insert_grant(conn, user_id, product):
    exam, year = product['exam'], product['year']
    conn.execute(
        'INSERT OR IGNORE INTO access_grants (user_id, exam, year, product_id, unlocked_at) VALUES (?,?,?,?,?)',
        (user_id, exam, year, product['id'], now_iso())
    )
    if exam == '*' and year == '*':
        conn.execute('DELETE FROM access_grants WHERE user_id=? AND NOT (exam=? AND year=?)',
                     (user_id, '*', '*'))
    elif year == '*':
        conn.execute('DELETE FROM access_grants WHERE user_id=? AND exam=? AND year!=?',
                     (user_id, exam, '*'))


# ── Products ────────────────────────────────────────────────
def build_products(conn):
    rows = conn.execute(
        "SELECT DISTINCT exam, year FROM papers "
        "WHERE premium=1 AND year IS NOT NULL AND year != '' "
        "ORDER BY exam ASC, year DESC"
    ).fetchall()

    by_exam = {}
    for r in rows:
        by_exam.setdefault(r['exam'], []).append(r['year'])

    products = []
    for exam, years in by_exam.items():
        for year in years:
            products.append({
                'id': f'{exam}:{year}',
                'exam': exam, 'year': year,
                'label': f'{exam} {year} papers',
                'kes': SINGLE_YEAR_PRICE, 'kind': 'year',
            })
        if len(years) > 1:
            products.append({
                'id': f'{exam}:ALL',
                'exam': exam, 'year': '*',
                'label': f'{exam} — every year',
                'kes': EXAM_BUNDLE_PRICE, 'kind': 'exam_bundle',
            })

    products.append({
        'id': 'MEGA', 'exam': '*', 'year': '*',
        'label': 'MEGA PASS — all exams · all years',
        'kes': MEGA_PRICE, 'kind': 'mega',
    })
    return products


def get_product(conn, pid):
    for p in build_products(conn):
        if p['id'] == pid:
            return p
    return None


# ── PDF preview ─────────────────────────────────────────────
def make_preview(src_path, dst_path):
    if not PYPDF_OK:
        raise RuntimeError('pypdf not installed')
    reader = PdfReader(str(src_path))
    if not reader.pages:
        raise RuntimeError('empty PDF')
    page = reader.pages[0]
    mb = page.mediabox
    llx, lly = float(mb.left), float(mb.bottom)
    urx, ury = float(mb.right), float(mb.top)
    new_lly = ury - (ury - lly) * float(PREVIEW_FRACTION)
    page.cropbox.lower_left  = (llx, new_lly)
    page.cropbox.upper_right = (urx, ury)
    for box_name in ('trimbox', 'bleedbox', 'artbox'):
        try:
            b = getattr(page, box_name)
            b.lower_left  = (llx, new_lly)
            b.upper_right = (urx, ury)
        except Exception:
            pass
    w = PdfWriter()
    w.add_page(page)
    with open(str(dst_path), 'wb') as f:
        w.write(f)


_preview_mtime = {}


def ensure_preview(paper_id, src_path, dst_path):
    try:
        src_mtime = src_path.stat().st_mtime
    except OSError:
        return False
    cached = _preview_mtime.get(paper_id)
    if cached == src_mtime and dst_path.exists() and dst_path.stat().st_size > 0:
        return True
    try:
        make_preview(src_path, dst_path)
        _preview_mtime[paper_id] = src_mtime
        return True
    except Exception as e:
        log.exception('preview failed for %s: %s', paper_id, e)
        return False


# ── IntaSend ────────────────────────────────────────────────
_intasend = None
def intasend():
    global _intasend
    if not INTASEND_OK:
        raise RuntimeError('intasend-python not installed')
    if not PUBLISHABLE or not SECRET:
        raise RuntimeError('IntaSend keys missing')
    if _intasend is None:
        _intasend = APIService(token=SECRET, publishable_key=PUBLISHABLE, test=TEST_MODE)
    return _intasend


def parse_intasend_state(resp):
    if not isinstance(resp, dict): return ''
    s = (resp.get('state') or '').upper()
    if s: return s
    inv = resp.get('invoice') or {}
    if isinstance(inv, dict):
        s = (inv.get('state') or '').upper()
        if s: return s
    return (resp.get('payment_state') or '').upper()


def parse_intasend_invoice_id(resp):
    if not isinstance(resp, dict): return None
    inv = resp.get('invoice') or {}
    if isinstance(inv, dict):
        iid = inv.get('invoice_id') or inv.get('id')
        if iid: return iid
    return resp.get('invoice_id')


def parse_intasend_checkout_id(resp):
    if not isinstance(resp, dict): return None
    return resp.get('id') or resp.get('checkout_id')


# ═══════════════════════════════════════════════════════════
#  FRONTEND
# ═══════════════════════════════════════════════════════════
@app.route('/')
def index():
    path = BASE_DIR / 'knec2.html'
    if not path.exists():
        return '<h1>knec1000.html missing</h1>', 404
    with open(path, 'r', encoding='utf-8') as f:
        return Response(f.read(), mimetype='text/html; charset=utf-8')


@app.route('/health')
def health():
    return jsonify({'ok': True, 'ts': now_iso()})


# ═══════════════════════════════════════════════════════════
#  AUTH
# ═══════════════════════════════════════════════════════════
@app.route('/api/auth/register', methods=['POST'])
def api_register():
    d = request.get_json(silent=True) or {}
    name = (d.get('name') or '').strip()
    email = (d.get('email') or '').strip().lower()
    phone = normalize_phone(d.get('phone'))
    password = d.get('password') or ''

    if not name:
        return jsonify({'error': 'name required'}), 400
    if not is_valid_email(email):
        return jsonify({'error': 'valid email required'}), 400
    if not phone:
        return jsonify({'error': 'valid Safaricom phone required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'password must be at least 6 characters'}), 400

    conn = db()
    if conn.execute('SELECT 1 FROM users WHERE email=?', (email,)).fetchone():
        return jsonify({'error': 'email already registered'}), 409
    if conn.execute('SELECT 1 FROM users WHERE phone=?', (phone,)).fetchone():
        return jsonify({'error': 'phone number already registered'}), 409

    cur = conn.execute(
        'INSERT INTO users (email, phone, name, password_hash, created_at) VALUES (?,?,?,?,?)',
        (email, phone, name, generate_password_hash(password), now_iso())
    )
    conn.commit()
    uid = cur.lastrowid
    log.info('user registered: id=%s email=%s', uid, email)
    return jsonify({
        'token': issue_token(uid),
        'user': {'id': uid, 'name': name, 'email': email, 'phone': phone},
    })


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    d = request.get_json(silent=True) or {}
    ident = (d.get('identifier') or '').strip()
    password = d.get('password') or ''
    if not ident or not password:
        return jsonify({'error': 'identifier and password required'}), 400

    conn = db()
    user = None
    if '@' in ident:
        user = conn.execute('SELECT * FROM users WHERE email=?', (ident.lower(),)).fetchone()
    else:
        p = normalize_phone(ident)
        if p:
            user = conn.execute('SELECT * FROM users WHERE phone=?', (p,)).fetchone()

    if not user:
        return jsonify({'error': 'invalid credentials'}), 401
    if not user['password_hash']:
        return jsonify({
            'error': 'This account has no password set. Use "Forgot password?" to create one.',
        }), 401
    if not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'invalid credentials'}), 401

    return jsonify({
        'token': issue_token(user['id']),
        'user': {
            'id': user['id'], 'name': user['name'],
            'email': user['email'], 'phone': user['phone'],
        },
    })


@app.route('/api/auth/forgot', methods=['POST'])
def api_forgot():
    d = request.get_json(silent=True) or {}
    email = (d.get('email') or '').strip().lower()

    if not is_valid_email(email):
        return jsonify({'error': 'valid email required'}), 400

    # Never reveal whether the email exists.
    user = db().execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    if user:
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=PASSWORD_RESET_TTL_MIN)).isoformat()
        conn = db()
        conn.execute(
            'INSERT INTO password_resets (token, user_id, expires_at, created_at) VALUES (?,?,?,?)',
            (token, user['id'], expires_at, now_iso())
        )
        conn.commit()

        link = f'{BASE_URL.rstrip("/")}/#reset={token}'
        text, html = build_reset_email(user['name'] or 'there', link, PASSWORD_RESET_TTL_MIN)
        send_email(user['email'], 'Reset your Kenya Exam Hub password', html, text)

        # If SMTP isn't configured, log the link prominently so admins can find it
        if not SMTP_HOST:
            log.info('PASSWORD RESET LINK for %s → %s', email, link)

    return jsonify({'ok': True})


@app.route('/api/auth/reset', methods=['POST'])
def api_reset():
    d = request.get_json(silent=True) or {}
    token = (d.get('token') or '').strip()
    new_password = d.get('password') or ''

    if not token:
        return jsonify({'error': 'token required'}), 400
    if len(new_password) < 6:
        return jsonify({'error': 'password must be at least 6 characters'}), 400

    conn = db()
    row = conn.execute(
        'SELECT * FROM password_resets WHERE token=? AND used_at IS NULL', (token,)
    ).fetchone()
    if not row:
        return jsonify({'error': 'invalid or already-used reset link'}), 400

    try:
        expires = datetime.fromisoformat(row['expires_at'])
    except Exception:
        return jsonify({'error': 'invalid reset record'}), 400

    if expires < datetime.now(timezone.utc):
        return jsonify({'error': 'reset link has expired'}), 400

    conn.execute('UPDATE users SET password_hash=? WHERE id=?',
                 (generate_password_hash(new_password), row['user_id']))
    conn.execute('UPDATE password_resets SET used_at=? WHERE token=?', (now_iso(), token))
    conn.commit()

    user = conn.execute('SELECT * FROM users WHERE id=?', (row['user_id'],)).fetchone()
    log.info('password reset for user=%s', user['id'])
    return jsonify({
        'ok': True,
        'token': issue_token(user['id']),
        'user': {'id': user['id'], 'name': user['name'],
                 'email': user['email'], 'phone': user['phone']},
    })


@app.route('/api/me')
@require_auth
def api_me():
    u = g.user
    grants = db().execute(
        'SELECT exam, year, product_id, unlocked_at FROM access_grants WHERE user_id=?',
        (u['id'],)
    ).fetchall()
    return jsonify({
        'user': {'id': u['id'], 'email': u['email'], 'phone': u['phone'], 'name': u['name']},
        'grants': [dict(g) for g in grants],
    })


# ═══════════════════════════════════════════════════════════
#  PRODUCTS
# ═══════════════════════════════════════════════════════════
@app.route('/api/products')
def api_products():
    return jsonify({'products': build_products(db())})


# ═══════════════════════════════════════════════════════════
#  PAPERS
# ═══════════════════════════════════════════════════════════
@app.route('/api/papers')
def api_papers():
    exam = request.args.get('exam')
    ptype = request.args.get('type')
    year = request.args.get('year')
    q = ('SELECT id,exam,year,subject,paper,title,hook,type,pages,premium,filesize,created_at '
         'FROM papers')
    clauses, params = [], []
    if exam and exam != 'ALL':
        clauses.append('exam = ?'); params.append(exam)
    if year and year != 'ALL':
        clauses.append('year = ?'); params.append(year)
    if ptype and ptype != 'all':
        clauses.append('type = ?'); params.append(ptype)
    if clauses: q += ' WHERE ' + ' AND '.join(clauses)
    q += ' ORDER BY year DESC, created_at DESC'
    rows = db().execute(q, params).fetchall()
    return jsonify({'papers': [dict(r) for r in rows]})


@app.route('/api/papers/<paper_id>')
def api_paper(paper_id):
    row = db().execute(
        'SELECT id,exam,year,subject,paper,title,hook,type,pages,premium,filesize,created_at '
        'FROM papers WHERE id=?', (paper_id,)
    ).fetchone()
    if not row: return jsonify({'error': 'not found'}), 404
    return jsonify(dict(row))


@app.route('/api/papers/<paper_id>/file')
def api_paper_file(paper_id):
    row = db().execute('SELECT * FROM papers WHERE id=?', (paper_id,)).fetchone()
    if not row:
        return jsonify({'error': 'not found'}), 404

    premium = bool(row['premium'])
    unlocked = False
    if premium:
        u = current_user()
        if u:
            unlocked = user_has_access(u['id'], row['exam'], row['year'] or '')

    full_path = UPLOAD_DIR / row['filename']

    if premium and not unlocked:
        if not PYPDF_OK:
            return jsonify({'error': 'preview unavailable',
                            'enroll_required': True}), 402
        preview_name = row['preview_filename'] or f"{row['id']}-preview.pdf"
        preview_path = UPLOAD_DIR / preview_name
        if not ensure_preview(paper_id, full_path, preview_path):
            return jsonify({'error': 'preview unavailable',
                            'enroll_required': True}), 402
        resp = send_file(preview_path, mimetype='application/pdf')
        resp.headers['X-Preview'] = 'true'
        resp.headers['X-Unlocked'] = 'false'
        resp.headers['X-Preview-Kind'] = 'top-half'
        resp.headers['Access-Control-Expose-Headers'] = 'X-Preview, X-Unlocked, X-Preview-Kind'
        return resp

    resp = send_file(full_path, mimetype='application/pdf')
    resp.headers['X-Preview'] = 'false'
    resp.headers['X-Unlocked'] = 'true'
    resp.headers['Access-Control-Expose-Headers'] = 'X-Preview, X-Unlocked, X-Preview-Kind'
    return resp


# ═══════════════════════════════════════════════════════════
#  ADMIN
# ═══════════════════════════════════════════════════════════
ALLOWED_TYPES = {'past', 'scheme', 'mocks', 'predicted', 'revision'}


@app.route('/api/admin/papers', methods=['POST'])
def api_admin_upload():
    if not admin_ok():
        return jsonify({'error': 'admin token required'}), 403
    if 'file' not in request.files:
        return jsonify({'error': 'no file'}), 400
    f = request.files['file']
    if not f.filename.lower().endswith('.pdf'):
        return jsonify({'error': 'only PDFs accepted'}), 400

    meta = {
        'exam':    (request.form.get('exam') or '').strip().upper(),
        'year':    (request.form.get('year') or '').strip(),
        'subject': (request.form.get('subject') or '').strip(),
        'paper':   (request.form.get('paper') or '').strip(),
        'title':   (request.form.get('title') or '').strip(),
        'hook':    (request.form.get('hook') or '').strip(),
        'type':    (request.form.get('type') or 'past').strip().lower(),
        'premium': 1 if request.form.get('premium', 'true').lower() == 'true' else 0,
    }
    if meta['exam'] not in ('KCSE', 'KJSEA', 'KPSEA'):
        return jsonify({'error': 'exam must be KCSE, KJSEA or KPSEA'}), 400
    if not meta['year']:
        return jsonify({'error': 'year required'}), 400
    if meta['type'] not in ALLOWED_TYPES:
        meta['type'] = 'past'
    if not meta['title'] or not meta['hook']:
        return jsonify({'error': 'title and hook required'}), 400

    paper_id = 'doc-' + uuid.uuid4().hex[:12]
    stored_name = f'{paper_id}.pdf'
    preview_name = f'{paper_id}-preview.pdf'
    stored_path = UPLOAD_DIR / stored_name
    preview_path = UPLOAD_DIR / preview_name

    f.save(stored_path)
    size = stored_path.stat().st_size

    pages = None
    if PYPDF_OK:
        try: pages = len(PdfReader(stored_path).pages)
        except Exception: pages = None

    preview_ok = False
    if PYPDF_OK:
        try:
            make_preview(stored_path, preview_path)
            preview_ok = True
        except Exception as e:
            log.exception('preview failed: %s', e)
            preview_name = None
    else:
        preview_name = None

    db().execute(
        '''INSERT INTO papers (id,exam,year,subject,paper,title,hook,type,pages,premium,
            filename,preview_filename,filesize,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (paper_id, meta['exam'], meta['year'], meta['subject'], meta['paper'],
         meta['title'], meta['hook'], meta['type'], pages, meta['premium'],
         stored_name, preview_name, size, int(datetime.now().timestamp() * 1000))
    )
    db().commit()
    if preview_ok:
        try: _preview_mtime[paper_id] = stored_path.stat().st_mtime
        except OSError: pass
    log.info('paper uploaded: %s (%s)', paper_id, meta['title'])
    return jsonify({'id': paper_id, 'ok': True, 'pages': pages,
                    'preview': bool(preview_ok)})


@app.route('/api/admin/papers/<paper_id>', methods=['DELETE'])
def api_admin_delete(paper_id):
    if not admin_ok():
        return jsonify({'error': 'admin token required'}), 403
    row = db().execute('SELECT * FROM papers WHERE id=?', (paper_id,)).fetchone()
    if not row: return jsonify({'error': 'not found'}), 404
    for fname in [row['filename'], row['preview_filename']]:
        if fname:
            try: (UPLOAD_DIR / fname).unlink()
            except Exception: pass
    db().execute('DELETE FROM papers WHERE id=?', (paper_id,))
    db().commit()
    _preview_mtime.pop(paper_id, None)
    return jsonify({'ok': True})

@app.route('/api/admin/users')
def api_admin_users():
    """List all registered users with their grants and spend."""
    if not admin_ok():
        return jsonify({'error': 'admin token required'}), 403

    conn = db()
    rows = conn.execute('''
        SELECT u.id, u.name, u.email, u.phone, u.created_at,
               (SELECT COUNT(*) FROM access_grants g WHERE g.user_id = u.id) AS grants_count,
               (SELECT COALESCE(SUM(amount_kes),0) FROM orders o
                  WHERE o.user_id = u.id AND o.status='completed') AS total_paid,
               (SELECT COUNT(*) FROM orders o
                  WHERE o.user_id = u.id AND o.status='completed') AS paid_orders,
               (SELECT COUNT(*) FROM orders o
                  WHERE o.user_id = u.id AND o.status='pending')   AS pending_orders
        FROM users u
        ORDER BY u.created_at DESC
        LIMIT 1000
    ''').fetchall()

    users = []
    for u in rows:
        grants = conn.execute(
            'SELECT exam, year, product_id, unlocked_at FROM access_grants '
            'WHERE user_id=? ORDER BY unlocked_at DESC',
            (u['id'],)
        ).fetchall()
        d = dict(u)
        d['grants'] = [dict(g) for g in grants]
        users.append(d)

    return jsonify({'users': users, 'count': len(users)})

@app.route('/api/admin/orders')
def api_admin_orders():
    if not admin_ok(): return jsonify({'error': 'admin token required'}), 403
    rows = db().execute(
        '''SELECT o.*, u.email, u.name FROM orders o
           LEFT JOIN users u ON u.id=o.user_id
           ORDER BY o.created_at DESC LIMIT 200'''
    ).fetchall()
    return jsonify({'orders': [dict(r) for r in rows]})


@app.route('/api/admin/verify', methods=['POST'])
def api_admin_verify():
    """Frontend calls this with X-Admin-Token to check the token before opening the panel."""
    if not admin_ok():
        return jsonify({'ok': False, 'error': 'invalid admin token'}), 403
    return jsonify({'ok': True})


@app.route('/api/admin/whoami')
def api_admin_whoami():
    given = request.headers.get('X-Admin-Token', '')
    if not ADMIN_TOKEN:
        return jsonify({'server_has_token': False,
                        'header_present': bool(given), 'match': False})
    return jsonify({
        'server_has_token': True,
        'server_token_len': len(ADMIN_TOKEN),
        'header_present': bool(given),
        'header_token_len': len(given),
        'match': bool(given) and hmac.compare_digest(given, ADMIN_TOKEN),
    })


# ═══════════════════════════════════════════════════════════
#  CHECKOUT
# ═══════════════════════════════════════════════════════════
@app.route('/api/checkout/initiate', methods=['POST'])
def api_checkout():
    u = current_user()
    if not u:
        return jsonify({'error': 'sign in required'}), 401

    d = request.get_json(silent=True) or {}
    product_id = (d.get('product_id') or '').strip()
    phone = normalize_phone(d.get('phone'))

    product = get_product(db(), product_id)
    if not product:
        return jsonify({'error': 'invalid product'}), 400
    if not phone:
        return jsonify({'error': 'valid Safaricom phone required'}), 400

    amount = product['kes']
    if amount > MPESA_MAX:
        return jsonify({'error': f'amount exceeds KES {MPESA_MAX}'}), 400

    api_ref = 'KEH-2026-' + uuid.uuid4().hex[:8].upper()

    try:
        resp = intasend().collect.mpesa_stk_push(
            phone_number=phone,
            amount=amount,
            narrative=f"Kenya Exam Hub — {product['label']}",
            api_ref=api_ref,
        )
    except Exception as e:
        log.exception('IntaSend initiate failed')
        return jsonify({'error': 'payment initiation failed'}), 502

    log.info('IntaSend initiate response: %s', json.dumps(resp, default=str)[:800])

    checkout_id = parse_intasend_checkout_id(resp)
    invoice_id = parse_intasend_invoice_id(resp)
    if not checkout_id:
        return jsonify({'error': 'payment initiation failed (no checkout id)'}), 502

    conn = db()
    conn.execute(
        '''INSERT INTO orders (user_id, package, product_id, amount_kes, checkout_id,
            invoice_id, api_ref, status, phone, created_at)
           VALUES (?,?,?,?,?,?,?,'pending',?,?)''',
        (u['id'], product_id, product_id, amount, checkout_id,
         invoice_id, api_ref, phone, now_iso())
    )
    conn.commit()
    log.info('STK pushed: %s product=%s user=%s phone=%s checkout_id=%s',
             api_ref, product_id, u['id'], phone, checkout_id)

    return jsonify({
        'checkout_id': checkout_id, 'api_ref': api_ref,
        'amount_kes': amount, 'product_id': product_id,
        'label': product['label'],
    })


def _refresh_order(order):
    if not order['invoice_id']:
        return order
    try:
        r = intasend().collect.status(invoice_id=order['invoice_id'])
        log.info('IntaSend status %s: %s', order['checkout_id'],
                 json.dumps(r, default=str)[:600])
        state = parse_intasend_state(r)
        if state == 'COMPLETE':
            _mark_paid(order['id'], r)
            return db().execute('SELECT * FROM orders WHERE id=?', (order['id'],)).fetchone()
        if state in ('FAILED', 'CANCELLED', 'EXPIRED'):
            db().execute('UPDATE orders SET status=? WHERE id=?', ('failed', order['id']))
            db().commit()
            return db().execute('SELECT * FROM orders WHERE id=?', (order['id'],)).fetchone()
    except Exception as e:
        log.warning('status refresh failed: %s', e)
    return order


@app.route('/api/status/<checkout_id>')
def api_status(checkout_id):
    order = db().execute('SELECT * FROM orders WHERE checkout_id=?', (checkout_id,)).fetchone()
    if not order: return jsonify({'status': 'unknown'}), 404
    if order['status'] == 'pending':
        order = _refresh_order(order)
    return jsonify({
        'status': order['status'],
        'product_id': order['product_id'] or order['package'],
        'amount_kes': order['amount_kes'],
    })


@app.route('/api/checkout/<checkout_id>/verify', methods=['POST'])
def api_checkout_verify(checkout_id):
    order = db().execute('SELECT * FROM orders WHERE checkout_id=?', (checkout_id,)).fetchone()
    if not order: return jsonify({'status': 'unknown'}), 404
    order = _refresh_order(order)
    return jsonify({
        'status': order['status'],
        'product_id': order['product_id'] or order['package'],
        'amount_kes': order['amount_kes'],
    })


def _mark_paid(order_id, payload=None):
    conn = db()
    order = conn.execute('SELECT * FROM orders WHERE id=?', (order_id,)).fetchone()
    if not order or order['status'] == 'completed':
        return
    payload = payload or {}
    mpesa_ref = (payload.get('mpesa_reference') or payload.get('mpesa_receipt')
                 or payload.get('invoice_id') or order['invoice_id'])
    conn.execute(
        'UPDATE orders SET status=?, mpesa_reference=?, completed_at=? WHERE id=?',
        ('completed', mpesa_ref, now_iso(), order_id)
    )
    pid = order['product_id'] or order['package']
    product = get_product(conn, pid)
    if product:
        _insert_grant(conn, order['user_id'], product)
        log.info('granted: user=%s product=%s', order['user_id'], product['id'])
    conn.commit()


@app.route('/api/intasend/webhook', methods=['POST'])
def api_webhook():
    data = request.get_json(silent=True) or {}
    log.info('webhook: %s', json.dumps(data, default=str)[:800])
    challenge = data.get('challenge') or ''
    if WEBHOOK_CHALLENGE and not hmac.compare_digest(str(challenge), WEBHOOK_CHALLENGE):
        return jsonify({'status': 'rejected'}), 403
    invoice_id = data.get('invoice_id') or (data.get('invoice') or {}).get('invoice_id')
    api_ref    = data.get('api_ref')    or (data.get('invoice') or {}).get('api_ref')
    state      = parse_intasend_state(data)
    order = None
    if invoice_id:
        order = db().execute('SELECT * FROM orders WHERE invoice_id=?', (invoice_id,)).fetchone()
    if not order and api_ref:
        order = db().execute('SELECT * FROM orders WHERE api_ref=?', (api_ref,)).fetchone()
    if not order:
        return jsonify({'status': 'ok', 'matched': False}), 200
    if state == 'COMPLETE':
        _mark_paid(order['id'], data)
    elif state in ('FAILED', 'CANCELLED', 'EXPIRED'):
        db().execute('UPDATE orders SET status=? WHERE id=?', ('failed', order['id']))
        db().commit()
    return jsonify({'status': 'ok', 'matched': True}), 200


# ═══════════════════════════════════════════════════════════
#  RESTORE (legacy recovery for users without a password)
# ═══════════════════════════════════════════════════════════
@app.route('/api/restore', methods=['POST'])
def api_restore():
    d = request.get_json(silent=True) or {}
    phone = normalize_phone(d.get('phone'))
    if not phone:
        return jsonify({'error': 'invalid phone'}), 400
    conn = db()
    user = conn.execute('SELECT * FROM users WHERE phone=?', (phone,)).fetchone()
    if not user:
        return jsonify({'error': 'no account with that phone'}), 404
    paid = conn.execute(
        "SELECT 1 FROM orders WHERE user_id=? AND status='completed' LIMIT 1", (user['id'],)
    ).fetchone()
    if not paid:
        return jsonify({'error': 'no completed payment for this phone'}), 404
    return jsonify({
        'token': issue_token(user['id']),
        'user': {'id': user['id'], 'name': user['name'],
                 'email': user['email'], 'phone': user['phone']},
    })


# ── Boot ────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(_env('PORT', required=False, default='5000'))
    debug = _env('FLASK_DEBUG', required=False, default='true').lower() == 'true'

    print('=' * 60)
    print('🇰🇪  KENYA EXAM HUB — backend ready')
    print(f'    → http://localhost:{port}/')
    if ADMIN_TOKEN:
        print(f'    Admin token: SET  len={len(ADMIN_TOKEN)}  '
              f'{ADMIN_TOKEN[:3]!r}…{ADMIN_TOKEN[-3:]!r}')
    else:
        print('    Admin token: MISSING (set ADMIN_TOKEN in .env)')
    print(f'    IntaSend: {"TEST" if TEST_MODE else "LIVE" if PUBLISHABLE else "NOT CONFIGURED"}')
    print(f'    pypdf: {"OK" if PYPDF_OK else "MISSING — pip install pypdf"}')
    print(f'    SMTP: {"OK → " + SMTP_HOST if SMTP_HOST else "NOT configured (reset links print to console)"}')
    print(f'    Pricing: year={SINGLE_YEAR_PRICE} · bundle={EXAM_BUNDLE_PRICE} · mega={MEGA_PRICE}')
    print(f'    DB: {DB_PATH}')
    print('=' * 60)
    app.run(host='0.0.0.0', port=port, debug=debug)