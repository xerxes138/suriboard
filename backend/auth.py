#!/usr/bin/env python3
"""
Suricata Dashboard - Benutzer, Anmeldung und Sitzungen

Nur Python-Standardbibliothek.

* Benutzer mit Rolle "admin" (darf alles) oder "viewer" (nur lesen)
* Passwoerter als PBKDF2-SHA256 mit Salt
* Sitzungen als zufaelliges Cookie-Token; in der Datenbank liegt nur dessen Hash
* Sperre nach mehreren Fehlversuchen pro IP (gegen Passwort-Raten)

Kommandozeile (wie "pihole setpassword"):

    python3 backend/auth.py list
    python3 backend/auth.py passwd admin
    python3 backend/auth.py add anna --role admin
    python3 backend/auth.py role anna viewer
    python3 backend/auth.py del anna
    python3 backend/auth.py logout-all
"""

import contextlib
import getpass
import hashlib
import hmac
import logging
import os
import re
import secrets
import sys
import threading
import time

log = logging.getLogger("suricata-dashboard")

AUTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username    TEXT PRIMARY KEY COLLATE NOCASE,
    pw_hash     TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'viewer',
    must_change INTEGER NOT NULL DEFAULT 0,
    created     INTEGER,
    last_login  INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL COLLATE NOCASE,
    created    INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    remember   INTEGER NOT NULL DEFAULT 0,
    ip         TEXT,
    agent      TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username);
"""

ROLES = ("admin", "viewer")
ROLE_LABELS = {"admin": "Administrator", "viewer": "Nur lesen"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,32}$")
MIN_PASSWORD = 8
PBKDF2_ITER = 200_000

COOKIE_NAME = "sd_session"
IDLE_TIMEOUT = 12 * 3600          # ohne "angemeldet bleiben"
REMEMBER_TIMEOUT = 30 * 86400     # mit "angemeldet bleiben"
TOUCH_EVERY = 60                  # last_seen hoechstens so oft schreiben
CACHE_SECONDS = 15

INITIAL_PW_FILE = "initial-admin-password.txt"


class AuthError(Exception):
    """Fehler mit HTTP-Status, Text ist fuer den Nutzer gedacht."""

    def __init__(self, msg, code=400, retry_after=None):
        super().__init__(msg)
        self.code = code
        self.retry_after = retry_after


# --------------------------------------------------------------------------
# Passwoerter
# --------------------------------------------------------------------------

def hash_password(pw, iterations=PBKDF2_ITER):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, salt.hex(), dk.hex())


def verify_password(pw, stored):
    try:
        algo, it, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(dk.hex(), digest)
    except (ValueError, AttributeError):
        return False


# Wird bei unbekanntem Benutzer geprueft, damit die Antwortzeit nichts verraet
_DUMMY_HASH = hash_password(secrets.token_hex(8))


def check_new_password(pw):
    if not isinstance(pw, str) or len(pw) < MIN_PASSWORD:
        raise AuthError("Das Passwort muss mindestens %d Zeichen lang sein." % MIN_PASSWORD)
    if len(pw) > 256:
        raise AuthError("Das Passwort ist zu lang (höchstens 256 Zeichen).")


def check_username(name):
    if not isinstance(name, str) or not USERNAME_RE.match(name):
        raise AuthError("Benutzername: 1–32 Zeichen, erlaubt sind Buchstaben, Ziffern und . _ @ -")


def check_role(role):
    if role not in ROLES:
        raise AuthError("Rolle muss 'admin' oder 'viewer' sein.")


def token_hash(token):
    return hashlib.sha256(token.encode("ascii", "replace")).hexdigest()


# --------------------------------------------------------------------------
# Schutz gegen Passwort-Raten
# --------------------------------------------------------------------------

class LoginGuard:
    """Zaehlt Fehlversuche pro IP. Ab FREE Fehlversuchen wird gesperrt,
    jede weitere Sperre dauert doppelt so lang (bis MAX_LOCK)."""

    FREE = 5
    BASE_LOCK = 30
    MAX_LOCK = 900
    FORGET_AFTER = 3600

    def __init__(self):
        self.lock = threading.Lock()
        self.state = {}  # ip -> [fails, locked_until, last_fail]

    def remaining(self, ip):
        with self.lock:
            s = self.state.get(ip)
            return max(0, int(s[1] - time.time())) if s else 0

    def fail(self, ip):
        now = time.time()
        with self.lock:
            # alte Eintraege vergessen (begrenzt den Speicher)
            if len(self.state) > 1000:
                for k in [k for k, v in self.state.items() if now - v[2] > self.FORGET_AFTER]:
                    del self.state[k]
            s = self.state.get(ip)
            if not s or now - s[2] > self.FORGET_AFTER:
                s = self.state[ip] = [0, 0, now]
            s[0] += 1
            s[2] = now
            if s[0] >= self.FREE:
                s[1] = now + min(self.MAX_LOCK, self.BASE_LOCK * 2 ** (s[0] - self.FREE))
            return max(0, int(s[1] - now))

    def success(self, ip):
        with self.lock:
            self.state.pop(ip, None)


# --------------------------------------------------------------------------
# Benutzer und Sitzungen
# --------------------------------------------------------------------------

class Auth:
    def __init__(self, cfg, connect):
        self.cfg = cfg
        self.enabled = bool(cfg.get("auth", True))
        self._connect = connect
        self.guard = LoginGuard()
        self._cache = {}
        self._cache_lock = threading.Lock()

    @contextlib.contextmanager
    def db(self):
        conn = self._connect(self.cfg["db_path"])
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @property
    def initial_pw_path(self):
        return os.path.join(os.path.dirname(self.cfg["db_path"]), INITIAL_PW_FILE)

    def init_db(self):
        # Die Datenbank enthaelt jetzt Passwort-Hashes -> nur fuer den Besitzer lesbar
        # (SQLite legt -wal/-shm mit denselben Rechten an)
        for suffix in ("", "-wal", "-shm"):
            with contextlib.suppress(OSError):
                os.chmod(self.cfg["db_path"] + suffix, 0o600)
        with self.db() as c:
            c.executescript(AUTH_SCHEMA)
            if not self.enabled:
                return
            if c.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                return
            pw = secrets.token_urlsafe(12)
            c.execute("INSERT INTO users (username, pw_hash, role, must_change, created)"
                      " VALUES ('admin', ?, 'admin', 1, ?)", (hash_password(pw), int(time.time())))
        try:
            fd = os.open(self.initial_pw_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write("Benutzer: admin\nPasswort: %s\n"
                        "(Diese Datei wird geloescht, sobald das Passwort geaendert wurde.)\n" % pw)
        except OSError as e:
            log.warning("Konnte %s nicht schreiben: %s", self.initial_pw_path, e)
        log.warning("=" * 64)
        log.warning("Erster Start: Benutzer 'admin' angelegt, Passwort: %s", pw)
        log.warning("Das Passwort steht auch in %s", self.initial_pw_path)
        log.warning("Eigenes Passwort setzen: python3 backend/auth.py passwd admin")
        log.warning("=" * 64)

    def _forget_cache(self):
        with self._cache_lock:
            self._cache.clear()

    @staticmethod
    def _public(row):
        return {"username": row["username"], "role": row["role"],
                "must_change": bool(row["must_change"])}

    # ---- Anmelden / Sitzung -----------------------------------------------

    def login(self, username, password, ip, agent, remember):
        wait = self.guard.remaining(ip)
        if wait:
            raise AuthError("Zu viele Fehlversuche. Bitte in %d s erneut versuchen." % wait, 429, wait)
        username = (username or "").strip()
        password = password or ""
        with self.db() as c:
            row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        ok = verify_password(password, row["pw_hash"] if row else _DUMMY_HASH) and row is not None
        if not ok:
            wait = self.guard.fail(ip)
            log.warning("Fehlgeschlagene Anmeldung fuer '%s' von %s", username[:40], ip)
            if wait:
                raise AuthError("Zu viele Fehlversuche. Bitte in %d s erneut versuchen." % wait, 429, wait)
            raise AuthError("Benutzername oder Passwort falsch.", 401)
        self.guard.success(ip)
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.db() as c:
            self._purge(c, now)
            c.execute("INSERT INTO sessions (token_hash, username, created, last_seen, remember, ip, agent)"
                      " VALUES (?,?,?,?,?,?,?)",
                      (token_hash(token), row["username"], now, now, 1 if remember else 0,
                       ip, (agent or "")[:200]))
            c.execute("UPDATE users SET last_login=? WHERE username=?", (now, row["username"]))
        log.info("Anmeldung: %s von %s", row["username"], ip)
        return token, self._public(row)

    @staticmethod
    def _purge(c, now):
        c.execute("DELETE FROM sessions WHERE (remember=0 AND last_seen < ?) OR last_seen < ?",
                  (now - IDLE_TIMEOUT, now - REMEMBER_TIMEOUT))

    def session(self, token):
        """Liefert den Benutzer zur Sitzung oder None."""
        if not token or len(token) > 100:
            return None
        th = token_hash(token)
        now = time.time()
        with self._cache_lock:
            hit = self._cache.get(th)
            if hit and now - hit[1] < CACHE_SECONDS:
                return hit[0]
        with self.db() as c:
            row = c.execute(
                "SELECT s.last_seen, s.remember, u.username, u.role, u.must_change"
                " FROM sessions s JOIN users u ON u.username = s.username"
                " WHERE s.token_hash=?", (th,)).fetchone()
            if not row:
                return None
            limit = REMEMBER_TIMEOUT if row["remember"] else IDLE_TIMEOUT
            if now - row["last_seen"] > limit:
                c.execute("DELETE FROM sessions WHERE token_hash=?", (th,))
                return None
            if now - row["last_seen"] > TOUCH_EVERY:
                c.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (int(now), th))
        user = self._public(row)
        with self._cache_lock:
            if len(self._cache) > 500:
                self._cache.clear()
            self._cache[th] = (user, now)
        return user

    def logout(self, token):
        if not token:
            return
        with self.db() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(token),))
        self._forget_cache()

    # ---- eigenes Konto ------------------------------------------------------

    def change_own_password(self, user, old, new, token):
        check_new_password(new)
        with self.db() as c:
            row = c.execute("SELECT pw_hash FROM users WHERE username=?", (user["username"],)).fetchone()
        if not row or not verify_password(old or "", row["pw_hash"]):
            raise AuthError("Das bisherige Passwort stimmt nicht.", 403)
        if old == new:
            raise AuthError("Das neue Passwort muss sich vom bisherigen unterscheiden.")
        self._set_password(user["username"], new, keep_token=token)
        return {"ok": True}

    def _set_password(self, username, pw, keep_token=None, must_change=False):
        with self.db() as c:
            n = c.execute("UPDATE users SET pw_hash=?, must_change=? WHERE username=?",
                          (hash_password(pw), 1 if must_change else 0, username)).rowcount
            if not n:
                raise AuthError("Benutzer '%s' gibt es nicht." % username, 404)
            # alle anderen Sitzungen dieses Benutzers beenden
            c.execute("DELETE FROM sessions WHERE username=? AND token_hash<>?",
                      (username, token_hash(keep_token) if keep_token else ""))
            admin_changed = username.lower() == "admin"
        self._forget_cache()
        if admin_changed and not must_change:
            with contextlib.suppress(OSError):
                os.remove(self.initial_pw_path)

    # ---- Verwaltung (nur Admins) -------------------------------------------

    def list_users(self):
        now = int(time.time())
        with self.db() as c:
            self._purge(c, now)
            rows = c.execute(
                "SELECT u.username, u.role, u.must_change, u.created, u.last_login,"
                " (SELECT COUNT(*) FROM sessions s WHERE s.username = u.username) AS sessions"
                " FROM users u ORDER BY u.username COLLATE NOCASE").fetchall()
        return {"users": [dict(r, must_change=bool(r["must_change"])) for r in rows],
                "roles": ROLE_LABELS, "min_password": MIN_PASSWORD}

    def _admins(self, c):
        return c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]

    def add_user(self, username, password, role, must_change=False):
        check_username(username)
        check_new_password(password)
        check_role(role)
        with self.db() as c:
            if c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                raise AuthError("Benutzer '%s' gibt es schon." % username, 409)
            c.execute("INSERT INTO users (username, pw_hash, role, must_change, created) VALUES (?,?,?,?,?)",
                      (username, hash_password(password), role, 1 if must_change else 0, int(time.time())))
        log.info("Benutzer angelegt: %s (%s)", username, role)

    def set_role(self, username, role):
        check_role(role)
        with self.db() as c:
            row = c.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
            if not row:
                raise AuthError("Benutzer '%s' gibt es nicht." % username, 404)
            if row["role"] == "admin" and role != "admin" and self._admins(c) <= 1:
                raise AuthError("Der letzte Administrator kann nicht herabgestuft werden.", 409)
            c.execute("UPDATE users SET role=? WHERE username=?", (role, username))
        self._forget_cache()

    def reset_password(self, username, password, must_change):
        check_new_password(password)
        # beendet alle Sitzungen des Zielbenutzers
        self._set_password(username, password, must_change=must_change)

    def delete_user(self, username):
        with self.db() as c:
            row = c.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
            if not row:
                raise AuthError("Benutzer '%s' gibt es nicht." % username, 404)
            if row["role"] == "admin" and self._admins(c) <= 1:
                raise AuthError("Der letzte Administrator kann nicht gelöscht werden.", 409)
            c.execute("DELETE FROM sessions WHERE username=?", (username,))
            c.execute("DELETE FROM users WHERE username=?", (username,))
        self._forget_cache()
        log.info("Benutzer geloescht: %s", username)

    def logout_user(self, username):
        with self.db() as c:
            c.execute("DELETE FROM sessions WHERE username=?", (username,))
        self._forget_cache()

    def manage(self, me, body):
        """POST /api/users  {op: add|role|password|delete|logout, username, ...}"""
        op = body.get("op")
        name = str(body.get("username", "")).strip()
        if op == "add":
            self.add_user(name, body.get("password"), body.get("role", "viewer"),
                          bool(body.get("must_change")))
        elif op == "role":
            if name.lower() == me["username"].lower() and body.get("role") != "admin":
                raise AuthError("Du kannst dir nicht selbst die Admin-Rechte nehmen.", 409)
            self.set_role(name, body.get("role"))
        elif op == "password":
            if name.lower() == me["username"].lower():
                raise AuthError("Dein eigenes Passwort änderst du über „Passwort ändern“ oben rechts.", 409)
            self.reset_password(name, body.get("password"), bool(body.get("must_change")))
        elif op == "delete":
            if name.lower() == me["username"].lower():
                raise AuthError("Du kannst dich nicht selbst löschen.", 409)
            self.delete_user(name)
        elif op == "logout":
            self.logout_user(name)
        else:
            raise AuthError("Unbekannte Aktion.")
        return self.list_users()


# --------------------------------------------------------------------------
# Kommandozeile
# --------------------------------------------------------------------------

def _ask_password():
    while True:
        pw = getpass.getpass("Neues Passwort: ")
        try:
            check_new_password(pw)
        except AuthError as e:
            print(e)
            continue
        if getpass.getpass("Wiederholen:    ") != pw:
            print("Die Eingaben stimmen nicht überein.")
            continue
        return pw


def cli():
    import argparse
    import server  # noqa: lazy, vermeidet Kreis-Import

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description="Benutzer des Suricata Dashboards verwalten")
    ap.add_argument("--config", default=os.path.join(root, "config.json"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="Benutzer anzeigen")
    p = sub.add_parser("passwd", help="Passwort setzen (legt den Benutzer an, falls er fehlt)")
    p.add_argument("username")
    p = sub.add_parser("add", help="Benutzer anlegen")
    p.add_argument("username")
    p.add_argument("--role", choices=ROLES, default="viewer")
    p = sub.add_parser("role", help="Rolle ändern")
    p.add_argument("username")
    p.add_argument("role", choices=ROLES)
    p = sub.add_parser("del", help="Benutzer löschen")
    p.add_argument("username")
    sub.add_parser("logout-all", help="Alle Sitzungen beenden")
    args = ap.parse_args()

    cfg = server.load_config(args.config)
    os.makedirs(os.path.dirname(cfg["db_path"]), exist_ok=True)
    a = Auth(dict(cfg, auth=False), server.connect)   # auth=False: kein Zufallspasswort erzeugen
    a.init_db()
    try:
        if args.cmd == "list":
            users = a.list_users()["users"]
            if not users:
                print("Noch keine Benutzer. Beim nächsten Start wird 'admin' angelegt.")
            for u in users:
                last = time.strftime("%d.%m.%Y %H:%M", time.localtime(u["last_login"])) if u["last_login"] else "nie"
                print("%-24s %-14s letzte Anmeldung: %s%s" % (
                    u["username"], ROLE_LABELS[u["role"]], last,
                    "  (muss Passwort ändern)" if u["must_change"] else ""))
        elif args.cmd == "passwd":
            check_username(args.username)
            pw = _ask_password()
            with a.db() as c:
                exists = c.execute("SELECT 1 FROM users WHERE username=?", (args.username,)).fetchone()
                no_admin = not a._admins(c)
            if exists:
                a.reset_password(args.username, pw, must_change=False)
                print("Passwort für '%s' gesetzt, alle Sitzungen beendet." % args.username)
            else:
                role = "admin" if no_admin else "viewer"
                a.add_user(args.username, pw, role)
                print("Benutzer '%s' (%s) angelegt." % (args.username, ROLE_LABELS[role]))
        elif args.cmd == "add":
            a.add_user(args.username, _ask_password(), args.role)
            print("Benutzer '%s' angelegt." % args.username)
        elif args.cmd == "role":
            a.set_role(args.username, args.role)
            print("Rolle von '%s' ist jetzt %s." % (args.username, ROLE_LABELS[args.role]))
        elif args.cmd == "del":
            a.delete_user(args.username)
            print("Benutzer '%s' gelöscht." % args.username)
        elif args.cmd == "logout-all":
            with a.db() as c:
                n = c.execute("DELETE FROM sessions").rowcount
            print("%d Sitzung(en) beendet." % n)
    except AuthError as e:
        print("Fehler:", e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(cli())
