#!/usr/bin/env python3
"""
Suricata Dashboard - Export/Import der vom Nutzer gespeicherten Daten

Gesichert werden nur Dinge, die man selbst eingegeben hat (alles andere lernt
das Dashboard aus eve.json neu):

  settings      Pfade zu eve.json/fast.log, Alert-Quelle, HTTPS-Schalter
  device_names  eigene Geraetenamen (per MAC oder IP)
  flags         als harmlos markierte Signaturen
  fp_notes      Bezeichnungen/Harmlos-Markierungen fuer TLS-Fingerprints
  feeds         ein-/ausgeschaltete Threat-Feeds
  users         Benutzer mit Rolle und Passwort-Hash (optional)

Zusaetzlich legt das Dashboard bei jeder Aenderung automatisch eine Sicherung
in data/backups/ an (die neuesten KEEP_BACKUPS bleiben erhalten).

Kommandozeile:
    python3 backend/userdata.py export [datei.json] [--no-users]
    python3 backend/userdata.py import datei.json [--mode merge|replace] [--only devices,settings,...]
    python3 backend/userdata.py list
"""

import contextlib
import hashlib
import json
import logging
import os
import re
import socket
import sys
import threading
import time

log = logging.getLogger("suricata-dashboard")

FORMAT = "suricata-dashboard-userdata"
FORMAT_VERSION = 1
SECTIONS = ("settings", "device_names", "flags", "fp_notes", "anomaly_mutes", "feeds", "users")
SECTION_LABELS = {
    "settings": "Einstellungen (Pfade, Alert-Quelle, HTTPS)",
    "device_names": "Gerätenamen",
    "flags": "Harmlos markierte Signaturen",
    "fp_notes": "Notizen zu TLS-Fingerprints",
    "anomaly_mutes": "Stummgeschaltete Anomalie-Warnungen",
    "feeds": "Ein-/ausgeschaltete Threat-Feeds",
    "users": "Benutzer (mit Passwort-Hash)",
}
# Einstellungen, die im Browser geaendert werden und in data/settings.json liegen
SETTING_KEYS = ("eve_json", "fast_log", "alert_source", "https", "https_port", "http_redirect")
HTTPS_KEYS = ("https", "https_port", "http_redirect")
CONTENT_SECTIONS = ("device_names", "flags", "fp_notes", "anomaly_mutes", "feeds")

BACKUP_DIR = "backups"
KEEP_BACKUPS = 20
BACKUP_CHECK_SECONDS = 300
BACKUP_NAME_RE = re.compile(r"^userdata-\d{8}-\d{6}\.json$")


def settings_path(cfg):
    return os.path.join(os.path.dirname(cfg["db_path"]), "settings.json")


def backup_dir(cfg):
    return os.path.join(os.path.dirname(cfg["db_path"]), BACKUP_DIR)


def write_json_private(path, obj):
    """Atomar schreiben, nur fuer den Besitzer lesbar (enthaelt ggf. Passwort-Hashes)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------

def collect(cfg, conn, include_users=True):
    """Alle Nutzerdaten als dict (ohne Zeitstempel-Kopf, damit sich Aenderungen vergleichen lassen)."""
    rows = lambda sql: [dict(r) for r in conn.execute(sql)]  # noqa: E731
    data = {
        "settings": {k: cfg[k] for k in SETTING_KEYS if k in cfg},
        "device_names": rows("SELECT kind, key, name, updated FROM device_names ORDER BY kind, key"),
        "flags": rows("SELECT gid, sid, status, note, created FROM flags ORDER BY gid, sid"),
        "fp_notes": rows("SELECT type, fp, label, harmless, updated FROM fp_notes ORDER BY type, fp"),
        "feeds": {},
    }
    with contextlib.suppress(Exception):  # Tabelle fehlt vor Version 1.9
        data["anomaly_mutes"] = rows("SELECT dev, kind, metric, created FROM anomaly_mutes "
                                     "ORDER BY dev, kind, metric")
    row = conn.execute("SELECT value FROM state WHERE key='intel:enabled'").fetchone()
    if row:
        with contextlib.suppress(ValueError):
            data["feeds"] = json.loads(row["value"])
    if include_users:
        with contextlib.suppress(Exception):  # Tabelle fehlt bei sehr alten Datenbanken
            data["users"] = rows("SELECT username, pw_hash, role, must_change, created FROM users "
                                 "ORDER BY username COLLATE NOCASE")
    return data


def envelope(data, app_version):
    return {"format": FORMAT, "version": FORMAT_VERSION, "app_version": app_version,
            "exported": int(time.time()), "host": socket.gethostname(), **data}


def counts(doc):
    out = {}
    for s in SECTIONS:
        v = doc.get(s)
        if v is None:
            continue
        out[s] = len(v) if isinstance(v, (list, dict)) else 1
    return out


# --------------------------------------------------------------------------
# Import
# --------------------------------------------------------------------------

def validate(doc):
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise ValueError("Keine Export-Datei des Suricata Dashboards (Feld 'format' fehlt oder passt nicht).")
    if int(doc.get("version", 0)) > FORMAT_VERSION:
        raise ValueError("Die Datei stammt aus einer neueren Dashboard-Version (Format %s)." % doc.get("version"))


def _clean_settings(s):
    out = {}
    for k in ("eve_json", "fast_log"):
        if k in s:
            v = str(s[k]).strip()
            if not os.path.isabs(v):
                raise ValueError("%s: Pfad muss absolut sein" % k)
            out[k] = v
    if "alert_source" in s:
        if s["alert_source"] not in ("fastlog", "eve"):
            raise ValueError("alert_source muss 'fastlog' oder 'eve' sein")
        out["alert_source"] = s["alert_source"]
    if "https" in s:
        out["https"] = bool(s["https"])
    if "https_port" in s:
        p = int(s["https_port"])
        if not 1 <= p <= 65535:
            raise ValueError("https_port ungültig")
        out["https_port"] = p
    if "http_redirect" in s:
        out["http_redirect"] = bool(s["http_redirect"])
    return out


def apply(conn, doc, sections, mode="merge"):
    """Schreibt die gewaehlten Abschnitte in die Datenbank.
    mode: merge   - vorhandene Eintraege behalten, gleiche Schluessel ueberschreiben
          replace - Abschnitt vorher leeren (gilt nicht fuer Benutzer: die werden nie geloescht)
    Rueckgabe: (Zusammenfassung, bereinigte Einstellungen oder None)"""
    validate(doc)
    if mode not in ("merge", "replace"):
        raise ValueError("mode muss 'merge' oder 'replace' sein")
    summary = {}
    settings = None
    if "settings" in sections and isinstance(doc.get("settings"), dict):
        settings = _clean_settings(doc["settings"])
        summary["settings"] = len(settings)
    now = int(time.time())
    with conn:
        if "device_names" in sections and isinstance(doc.get("device_names"), list):
            if mode == "replace":
                conn.execute("DELETE FROM device_names")
            n = 0
            for d in doc["device_names"]:
                kind, key, name = d.get("kind"), str(d.get("key", "")).strip().lower(), str(d.get("name", "")).strip()
                if kind not in ("mac", "ip") or not key or not name:
                    continue
                conn.execute("INSERT INTO device_names(kind, key, name, updated) VALUES(?,?,?,?) "
                             "ON CONFLICT(kind, key) DO UPDATE SET name=excluded.name, updated=excluded.updated",
                             (kind, key, name[:64], int(d.get("updated") or now)))
                n += 1
            summary["device_names"] = n
        if "flags" in sections and isinstance(doc.get("flags"), list):
            if mode == "replace":
                conn.execute("DELETE FROM flags")
            n = 0
            for f in doc["flags"]:
                try:
                    gid, sid = int(f.get("gid", 1)), int(f["sid"])
                except (KeyError, TypeError, ValueError):
                    continue
                conn.execute("INSERT INTO flags(gid, sid, status, note, created) VALUES(?,?,?,?,?) "
                             "ON CONFLICT(gid, sid) DO UPDATE SET status=excluded.status, note=excluded.note",
                             (gid, sid, str(f.get("status") or "harmless"), f.get("note"),
                              int(f.get("created") or now)))
                n += 1
            summary["flags"] = n
        if "fp_notes" in sections and isinstance(doc.get("fp_notes"), list):
            if mode == "replace":
                conn.execute("DELETE FROM fp_notes")
            n = 0
            for f in doc["fp_notes"]:
                t, fp = f.get("type"), str(f.get("fp", "")).strip().lower()
                if t not in ("ja3", "ja3s", "ja4", "ja4s") or not fp or len(fp) > 64:
                    continue
                conn.execute("INSERT INTO fp_notes(type, fp, label, harmless, updated) VALUES(?,?,?,?,?) "
                             "ON CONFLICT(type, fp) DO UPDATE SET label=excluded.label, "
                             "harmless=excluded.harmless, updated=excluded.updated",
                             (t, fp, (f.get("label") or None), 1 if f.get("harmless") else 0,
                              int(f.get("updated") or now)))
                n += 1
            summary["fp_notes"] = n
        if "anomaly_mutes" in sections and isinstance(doc.get("anomaly_mutes"), list):
            if mode == "replace":
                conn.execute("DELETE FROM anomaly_mutes")
            n = 0
            for m in doc["anomaly_mutes"]:
                dev, kind, metric = str(m.get("dev", "")).lower(), m.get("kind"), str(m.get("metric") or "*")
                if not dev or kind not in ("new", "volume", "time"):
                    continue
                conn.execute("INSERT OR IGNORE INTO anomaly_mutes(dev, kind, metric, created) VALUES(?,?,?,?)",
                             (dev, kind, metric, int(m.get("created") or now)))
                n += 1
            summary["anomaly_mutes"] = n
        if "feeds" in sections and isinstance(doc.get("feeds"), dict):
            cur = {}
            row = conn.execute("SELECT value FROM state WHERE key='intel:enabled'").fetchone()
            if row and mode == "merge":
                with contextlib.suppress(ValueError):
                    cur = json.loads(row["value"])
            cur.update({str(k): bool(v) for k, v in doc["feeds"].items()})
            conn.execute("INSERT INTO state(key, value) VALUES('intel:enabled', ?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(cur),))
            summary["feeds"] = len(doc["feeds"])
        if "users" in sections and isinstance(doc.get("users"), list):
            n = 0
            for u in doc["users"]:
                name, h, role = str(u.get("username", "")).strip(), u.get("pw_hash"), u.get("role")
                if not name or not isinstance(h, str) or not h.startswith("pbkdf2_sha256$") \
                        or role not in ("admin", "viewer"):
                    continue
                conn.execute("INSERT INTO users(username, pw_hash, role, must_change, created) VALUES(?,?,?,?,?) "
                             "ON CONFLICT(username) DO UPDATE SET pw_hash=excluded.pw_hash, role=excluded.role, "
                             "must_change=excluded.must_change",
                             (name[:32], h, role, 1 if u.get("must_change") else 0, int(u.get("created") or now)))
                n += 1
            if n:
                # geaenderte Passwoerter -> deren Sitzungen ungueltig machen
                names = [str(u.get("username", "")).strip() for u in doc["users"]]
                conn.executemany("DELETE FROM sessions WHERE username=?", [(x,) for x in names])
            summary["users"] = n
    return summary, settings


# --------------------------------------------------------------------------
# Automatische Sicherungen
# --------------------------------------------------------------------------

def list_backups(cfg):
    d = backup_dir(cfg)
    out = []
    try:
        names = sorted((n for n in os.listdir(d) if BACKUP_NAME_RE.match(n)), reverse=True)
    except FileNotFoundError:
        return out
    for n in names:
        p = os.path.join(d, n)
        try:
            st = os.stat(p)
            with open(p) as f:
                doc = json.load(f)
            out.append({"name": n, "time": doc.get("exported") or int(st.st_mtime), "size": st.st_size,
                        "counts": counts(doc), "app_version": doc.get("app_version")})
        except (OSError, ValueError) as e:
            out.append({"name": n, "time": None, "size": None, "counts": {}, "error": str(e)})
    return out


def read_backup(cfg, name):
    if not BACKUP_NAME_RE.match(name or ""):
        raise ValueError("ungültiger Name")
    with open(os.path.join(backup_dir(cfg), name)) as f:
        return json.load(f)


class AutoBackup(threading.Thread):
    """Schreibt eine Sicherung, sobald sich die Nutzerdaten geaendert haben
    (Pruefung alle BACKUP_CHECK_SECONDS oder sofort nach poke())."""

    def __init__(self, cfg, connect, app_version):
        super().__init__(daemon=True, name="userdata-backup")
        self.cfg, self.connect, self.app_version = cfg, connect, app_version
        self.wake = threading.Event()
        self.last_hash = None
        self.last_written = None
        self.restore_hint = None   # gesetzt, wenn die DB leer wirkt, eine Sicherung aber Daten hat
        self.lock = threading.Lock()

    def poke(self):
        self.wake.set()

    @staticmethod
    def has_content(c):
        """Eigene Daten, die das Dashboard nicht selbst neu lernen kann (Einstellungen und
        Benutzer zaehlen nicht: die gibt es auch in einer frisch angelegten Datenbank)."""
        return any(c.get(k) for k in CONTENT_SECTIONS)

    def _newest(self):
        for b in list_backups(self.cfg):
            if b.get("error"):
                continue
            try:
                return b, read_backup(self.cfg, b["name"])
            except (OSError, ValueError):
                continue
        return None, None

    @staticmethod
    def _hash(data):
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def check(self):
        with self.lock:
            conn = self.connect(self.cfg["db_path"])
            try:
                data = collect(self.cfg, conn, include_users=True)
            finally:
                conn.close()
            h = self._hash(data)
            newest, doc = self._newest()
            if newest and self.last_hash is None:
                self.last_hash = self._hash({k: doc.get(k) for k in SECTIONS if k in doc})
            if not self.has_content(counts(data)):
                # Leere Datenbank nie sichern: sonst ueberschreibt eine verlorene/neu angelegte
                # Datenbank nach und nach die guten Sicherungen.
                if newest and self.has_content(newest["counts"]):
                    if not self.restore_hint or self.restore_hint["name"] != newest["name"]:
                        log.warning("Die Datenbank enthält keine eigenen Daten (Gerätenamen, Markierungen …), "
                                    "die Sicherung %s aber schon. Wiederherstellen unter Einstellungen → "
                                    "Sichern & Wiederherstellen oder: ./userdata.sh import data/backups/%s",
                                    newest["name"], newest["name"])
                    self.restore_hint = {k: newest[k] for k in ("name", "time", "counts")}
                return None
            self.restore_hint = None
            if h == self.last_hash:
                return None
            name = time.strftime("userdata-%Y%m%d-%H%M%S.json")
            write_json_private(os.path.join(backup_dir(self.cfg), name), envelope(data, self.app_version))
            self.last_hash = h
            self.last_written = name
            self._prune()
            log.info("Nutzerdaten gesichert: %s/%s", backup_dir(self.cfg), name)
            return name

    def _prune(self):
        names = [b["name"] for b in list_backups(self.cfg)]
        for n in names[KEEP_BACKUPS:]:
            with contextlib.suppress(OSError):
                os.remove(os.path.join(backup_dir(self.cfg), n))

    def run(self):
        while True:
            try:
                self.check()
            except Exception:
                log.exception("Automatische Sicherung der Nutzerdaten fehlgeschlagen")
            self.wake.wait(BACKUP_CHECK_SECONDS)
            self.wake.clear()
            time.sleep(2)  # mehrere schnelle Aenderungen zusammenfassen


# --------------------------------------------------------------------------
# Kommandozeile
# --------------------------------------------------------------------------

SECTION_ALIASES = {"devices": "device_names", "geraete": "device_names", "signatures": "flags",
                   "fingerprints": "fp_notes"}


def cli():
    import argparse
    import server  # noqa: lazy, vermeidet Kreis-Import
    import auth as authmod

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description="Nutzerdaten des Suricata Dashboards exportieren/importieren")
    ap.add_argument("--config", default=os.path.join(root, "config.json"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("export", help="Nutzerdaten als JSON ausgeben")
    p.add_argument("file", nargs="?", help="Zieldatei (ohne Angabe: Standardausgabe)")
    p.add_argument("--no-users", action="store_true", help="Benutzer/Passwort-Hashes weglassen")
    p = sub.add_parser("import", help="Nutzerdaten aus JSON übernehmen")
    p.add_argument("file")
    p.add_argument("--mode", choices=("merge", "replace"), default="merge")
    p.add_argument("--only", help="Abschnitte, z. B. devices,settings (Standard: alle in der Datei)")
    sub.add_parser("list", help="Automatische Sicherungen anzeigen")
    args = ap.parse_args()

    cfg = server.load_config(args.config)
    os.makedirs(os.path.dirname(cfg["db_path"]), exist_ok=True)
    conn = server.connect(cfg["db_path"])
    conn.executescript(server.SCHEMA)
    conn.executescript(authmod.AUTH_SCHEMA)
    import anomaly
    conn.executescript(anomaly.SCHEMA)
    try:
        if args.cmd == "export":
            doc = envelope(collect(cfg, conn, include_users=not args.no_users), server.VERSION)
            if args.file:
                write_json_private(args.file, doc)
                print("Exportiert nach %s: %s" % (args.file, ", ".join("%s %d" % kv for kv in counts(doc).items())))
            else:
                json.dump(doc, sys.stdout, indent=2, ensure_ascii=False)
                print()
        elif args.cmd == "import":
            with open(args.file) as f:
                doc = json.load(f)
            if args.only:
                secs = [SECTION_ALIASES.get(s.strip(), s.strip()) for s in args.only.split(",")]
                bad = [s for s in secs if s not in SECTIONS]
                if bad:
                    raise ValueError("unbekannte Abschnitte: %s (möglich: %s)" % (", ".join(bad), ", ".join(SECTIONS)))
            else:
                secs = [s for s in SECTIONS if s in doc]
            summary, settings = apply(conn, doc, secs, args.mode)
            if settings:
                path = settings_path(cfg)
                cur = {}
                if os.path.exists(path):
                    with open(path) as f:
                        cur = json.load(f)
                cur.update(settings)
                write_json_private(path, cur)
            print("Importiert: %s" % ", ".join("%s %d" % kv for kv in summary.items()))
            print("Bitte das Dashboard neu starten: sudo systemctl restart suricata-dashboard")
        elif args.cmd == "list":
            for b in list_backups(cfg):
                t = time.strftime("%d.%m.%Y %H:%M", time.localtime(b["time"])) if b["time"] else "?"
                print("%s  %s  %s" % (b["name"], t, ", ".join("%s %d" % kv for kv in b["counts"].items())))
    except (OSError, ValueError) as e:
        print("Fehler:", e, file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(cli())
