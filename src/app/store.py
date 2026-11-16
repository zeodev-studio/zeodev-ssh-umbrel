"""Persistent SQLite store and authentication primitives for ZeoDev SSH."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from pathlib import Path

DATA_DIR = Path(os.environ.get('ZEODEV_DATA_DIR', './data')).expanduser().resolve()
DB_FILE = DATA_DIR / 'zeodev.sqlite3'
KEY_FILE = DATA_DIR / 'session.key'


def prepare():
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not KEY_FILE.exists():
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            fd = os.open(KEY_FILE, flags, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(secrets.token_bytes(32))
        except FileExistsError:
            pass
    with database() as db:
        db.execute('CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK(id=1), password_hash TEXT NOT NULL)')
        db.execute('''CREATE TABLE IF NOT EXISTS hosts (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, address TEXT NOT NULL,
            port INTEGER NOT NULL, username TEXT NOT NULL,
            pinned_fingerprint TEXT, created_at INTEGER NOT NULL
        )''')
        db.commit()


def database():
    db = sqlite3.connect(DB_FILE, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA busy_timeout=15000')
    return db


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return 'scrypt$' + base64.urlsafe_b64encode(salt).decode() + '$' + base64.urlsafe_b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_enc, digest_enc = stored.split('$', 2)
        if algo != 'scrypt':
            return False
        salt = base64.urlsafe_b64decode(salt_enc)
        expected = base64.urlsafe_b64decode(digest_enc)
        actual = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=2**14, r=8, p=1, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def has_admin() -> bool:
    with database() as db:
        return db.execute('SELECT 1 FROM admin WHERE id=1').fetchone() is not None


def create_admin(password: str) -> bool:
    with database() as db:
        try:
            db.execute('INSERT INTO admin (id, password_hash) VALUES (1, ?)', (hash_password(password),))
            db.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def check_admin(password: str) -> bool:
    with database() as db:
        row = db.execute('SELECT password_hash FROM admin WHERE id=1').fetchone()
        return bool(row and verify_password(password, row['password_hash']))


def _secret() -> bytes:
    return KEY_FILE.read_bytes()


def issue_session() -> str:
    payload = {'exp': int(time.time()) + 12 * 3600, 'rnd': secrets.token_hex(16)}
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
    sig = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    return body + '.' + sig


def verify_session(cookie: str | None) -> bool:
    if not cookie or '.' not in cookie:
        return False
    body, sig = cookie.rsplit('.', 1)
    expected = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        payload = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
        return int(payload['exp']) > int(time.time())
    except (ValueError, KeyError, TypeError):
        return False


def public_host(row) -> dict:
    return {
        'id': row['id'], 'name': row['name'], 'address': row['address'],
        'port': row['port'], 'username': row['username'],
        'fingerprint': row['pinned_fingerprint'], 'createdAt': row['created_at'],
    }


def list_hosts() -> list[dict]:
    with database() as db:
        return [public_host(row) for row in db.execute('SELECT * FROM hosts ORDER BY LOWER(name), created_at')]


def get_host(host_id: str) -> dict | None:
    with database() as db:
        row = db.execute('SELECT * FROM hosts WHERE id=?', (host_id,)).fetchone()
        return public_host(row) if row else None


def add_host(data: dict) -> dict:
    identifier = str(uuid.uuid4())
    now = int(time.time())
    with database() as db:
        db.execute('INSERT INTO hosts (id,name,address,port,username,created_at) VALUES (?,?,?,?,?,?)',
                   (identifier, data['name'], data['address'], data['port'], data['username'], now))
        db.commit()
    return get_host(identifier)


def edit_host(host_id: str, data: dict) -> dict | None:
    with database() as db:
        # Host identity changed => invalidate the previous fingerprint pin.
        old = db.execute('SELECT address,port FROM hosts WHERE id=?', (host_id,)).fetchone()
        if not old:
            return None
        pin = None if old['address'] != data['address'] or old['port'] != data['port'] else db.execute(
            'SELECT pinned_fingerprint FROM hosts WHERE id=?', (host_id,)).fetchone()['pinned_fingerprint']
        db.execute('UPDATE hosts SET name=?,address=?,port=?,username=?,pinned_fingerprint=? WHERE id=?',
                   (data['name'], data['address'], data['port'], data['username'], pin, host_id))
        db.commit()
    return get_host(host_id)


def delete_host(host_id: str) -> bool:
    with database() as db:
        cursor = db.execute('DELETE FROM hosts WHERE id=?', (host_id,))
        db.commit()
        return cursor.rowcount > 0


def pin_fingerprint(host_id: str, fingerprint: str) -> bool:
    with database() as db:
        row = db.execute('SELECT pinned_fingerprint FROM hosts WHERE id=?', (host_id,)).fetchone()
        if not row:
            return False
        if row['pinned_fingerprint'] and row['pinned_fingerprint'] != fingerprint:
            return False
        db.execute('UPDATE hosts SET pinned_fingerprint=? WHERE id=? AND (pinned_fingerprint IS NULL OR pinned_fingerprint=?)',
                   (fingerprint, host_id, fingerprint))
        db.commit()
        return True


def reset_fingerprint(host_id: str) -> bool:
    with database() as db:
        cursor = db.execute('UPDATE hosts SET pinned_fingerprint=NULL WHERE id=?', (host_id,))
        db.commit()
        return cursor.rowcount > 0


def ensure_discovery_tables():
    with database() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS scan_settings (
            id INTEGER PRIMARY KEY CHECK (id=1), cidrs TEXT NOT NULL DEFAULT '',
            last_scan INTEGER, last_count INTEGER NOT NULL DEFAULT 0
        )''')
        db.execute("INSERT OR IGNORE INTO scan_settings(id,cidrs) VALUES (1,'')")
        db.execute('''CREATE TABLE IF NOT EXISTS discovered (
            address TEXT PRIMARY KEY, banner TEXT, first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL, last_checked INTEGER NOT NULL,
            reachable INTEGER NOT NULL DEFAULT 1
        )''')
        db.commit()


def get_scan_settings() -> dict:
    with database() as db:
        row = db.execute('SELECT * FROM scan_settings WHERE id=1').fetchone()
        return {'cidrs': row['cidrs'], 'lastScan': row['last_scan'], 'lastCount': row['last_count']}


def set_scan_settings(cidrs: str):
    with database() as db:
        db.execute('UPDATE scan_settings SET cidrs=? WHERE id=1', (cidrs,))
        db.commit()


def record_scan(addresses: list[str], found: list):
    now = int(time.time())
    with database() as db:
        # Old discoveries outside the currently configured scan range must not remain "online" forever.
        db.execute('UPDATE discovered SET reachable=0')
        for address in addresses:
            db.execute('UPDATE discovered SET last_checked=? WHERE address=?', (now, address))
        for item in found:
            db.execute('''INSERT INTO discovered(address,banner,first_seen,last_seen,last_checked,reachable)
                          VALUES(?,?,?,?,?,1)
                          ON CONFLICT(address) DO UPDATE SET banner=excluded.banner,
                          last_seen=excluded.last_seen,last_checked=excluded.last_checked,reachable=1''',
                       (item.address, item.banner, now, now, now))
        db.execute('UPDATE scan_settings SET last_scan=?,last_count=? WHERE id=1', (now, len(found)))
        db.commit()


def list_discovered() -> list[dict]:
    with database() as db:
        return [dict(address=r['address'], banner=r['banner'], firstSeen=r['first_seen'],
                     lastSeen=r['last_seen'], lastChecked=r['last_checked'],
                     reachable=bool(r['reachable'])) for r in db.execute(
                         'SELECT * FROM discovered ORDER BY reachable DESC, last_seen DESC, address')]


def replace_admin_password(password: str):
    with database() as db:
        db.execute('UPDATE admin SET password_hash=? WHERE id=1', (hash_password(password),))
        db.commit()
