#!/usr/bin/env python3
"""
Suricata Dashboard - Backend

Nur Python-Standardbibliothek (>= 3.9), keine pip-Pakete noetig.

* liest regelmaessig eve.json (Flows, DNS, TLS, HTTP, Event-Typen) und
  fast.log (Alerts) inkrementell ein (merkt sich Datei-Offsets, erkennt Rotation)
* schreibt aggregierte Daten in eine SQLite-Datenbank
* stellt eine JSON-API unter /api/... bereit
* liefert das Frontend (Ordner ../frontend) aus

Start:  python3 backend/server.py            (Konfiguration: config.json)
        python3 backend/server.py --config /pfad/zur/config.json
"""

import argparse
import contextlib
import ipaddress
import json
import logging
import mimetypes
import os
import re
import signal
import sqlite3
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

import threatintel
from threatintel import ThreatIntel, is_global, norm_domain, FP_TYPES, RE_MD5, RE_JA4, RE_JA4S
from live import LiveTracker, addr_kind
import auth as authmod
from auth import Auth, AuthError
import tls
import userdata
import anomaly

VERSION = "1.9.0"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")

DEFAULT_CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 8080,
    "eve_json": "/var/log/suricata/eve.json",
    "fast_log": "/var/log/suricata/fast.log",
    # Quelle fuer Alerts: "fastlog" (fast.log) oder "eve" (event_type=alert in eve.json)
    "alert_source": "fastlog",
    "db_path": os.path.join(ROOT_DIR, "data", "suricata.db"),
    "poll_interval_seconds": 5,
    "retention_days": 30,
    # Beim allerersten Start vorhandene Logdaten ueberspringen (nur neue Zeilen lesen)
    "start_at_end": False,
    # Maximale Bytes pro Datei und Durchlauf (schuetzt den Pi bei riesigen Logs)
    "max_bytes_per_cycle": 32 * 1024 * 1024,
    # Signaturen, die juenger als so viele Stunden sind, gelten als "neu"
    "new_signature_hours": 24,
    # Oeffentliche Threat-Feeds automatisch laden (braucht Internetzugang)
    "threat_intel": True,
    # Wie viele Domains aus der Tranco-Rangliste geladen werden (RAM: ca. 10 MB je 100k)
    "tranco_top": 100000,
    # Eigene vertrauenswuerdige Domains: {"meine-firma.de": "Firmen-VPN"}
    "trusted_domains": {},
    # Eigene Feeds: [{"id": "x", "name": "...", "url": "https://...", "kind": "ip"|"domain",
    #                 "category": "malicious"|"suspicious", "interval_h": 12}]
    "custom_feeds": [],
    # Anmeldung erforderlich (Benutzerverwaltung). false = jeder im Netz hat vollen Zugriff
    "auth": True,
    # HTTPS: Zertifikat wird bei Bedarf selbstsigniert erzeugt
    "https": False,
    "https_port": 8443,
    "https_cert": os.path.join(ROOT_DIR, "data", "tls", "cert.pem"),
    "https_key": os.path.join(ROOT_DIR, "data", "tls", "key.pem"),
    "https_self_signed": True,
    # Bei aktivem HTTPS leitet listen_port alle Anfragen auf HTTPS um
    "http_redirect": True,
    # Verhaltensprofile lokaler Geraete und Warnungen bei Abweichungen
    "anomaly_detection": True,
    "anomaly_learning_days": 7,
    # Optional: Warnungen per HTTP-POST verschicken, z. B. "https://ntfy.sh/mein-geheimes-thema"
    "anomaly_notify_url": "",
    "anomaly_notify_min_severity": "medium",
}

log = logging.getLogger("suricata-dashboard")

SCHEMA = """
CREATE TABLE IF NOT EXISTS state (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    gid       INTEGER NOT NULL,
    sid       INTEGER NOT NULL,
    rev       INTEGER,
    signature TEXT,
    category  TEXT,
    severity  INTEGER,
    action    TEXT,
    proto     TEXT,
    app_proto TEXT,
    src_ip    TEXT,
    src_port  INTEGER,
    dest_ip   TEXT,
    dest_port INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts  ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_sid ON alerts(gid, sid, ts);

CREATE TABLE IF NOT EXISTS signatures (
    gid        INTEGER NOT NULL,
    sid        INTEGER NOT NULL,
    signature  TEXT,
    category   TEXT,
    severity   INTEGER,
    first_seen INTEGER,
    last_seen  INTEGER,
    total      INTEGER DEFAULT 0,
    PRIMARY KEY (gid, sid)
);

CREATE TABLE IF NOT EXISTS flags (
    gid     INTEGER NOT NULL,
    sid     INTEGER NOT NULL,
    status  TEXT NOT NULL DEFAULT 'harmless',
    note    TEXT,
    created INTEGER,
    PRIMARY KEY (gid, sid)
);

CREATE TABLE IF NOT EXISTS traffic (
    minute    INTEGER NOT NULL,
    proto     TEXT NOT NULL,
    app_proto TEXT NOT NULL,
    flows     INTEGER DEFAULT 0,
    bytes     INTEGER DEFAULT 0,
    pkts      INTEGER DEFAULT 0,
    PRIMARY KEY (minute, proto, app_proto)
);

CREATE TABLE IF NOT EXISTS events (
    minute     INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    count      INTEGER DEFAULT 0,
    PRIMARY KEY (minute, event_type)
);

-- Zeitindex: an welcher Byte-Position in eve.json (Datei = inode) beginnt welche Minute
CREATE TABLE IF NOT EXISTS eve_index (
    inode  INTEGER NOT NULL,
    minute INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    PRIMARY KEY (inode, minute)
);
CREATE INDEX IF NOT EXISTS idx_eve_index_minute ON eve_index(minute);

-- Welche Hostnamen wurden zu einer IP gesehen (DNS-Antworten, TLS-SNI, HTTP-Host)
CREATE TABLE IF NOT EXISTS ip_names (
    ip         TEXT NOT NULL,
    name       TEXT NOT NULL,
    source     TEXT,
    first_seen INTEGER,
    last_seen  INTEGER,
    count      INTEGER DEFAULT 0,
    PRIMARY KEY (ip, name)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_ip_names_name ON ip_names(name);
CREATE INDEX IF NOT EXISTS idx_ip_names_seen ON ip_names(last_seen);

-- Lokale Adressen mit zuletzt gesehener MAC (ether-Feld in eve.json bzw. DHCP)
CREATE TABLE IF NOT EXISTS hosts (
    ip         TEXT PRIMARY KEY,
    mac        TEXT,
    first_seen INTEGER,
    last_seen  INTEGER
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac);

-- MAC-Adressen mit Hostname aus DHCP
CREATE TABLE IF NOT EXISTS macs (
    mac        TEXT PRIMARY KEY,
    dhcp_name  TEXT,
    first_seen INTEGER,
    last_seen  INTEGER
) WITHOUT ROWID;

-- Selbst vergebene Geraetenamen: kind = 'mac' oder 'ip'
CREATE TABLE IF NOT EXISTS device_names (
    kind    TEXT NOT NULL,
    key     TEXT NOT NULL,
    name    TEXT NOT NULL,
    updated INTEGER,
    PRIMARY KEY (kind, key)
) WITHOUT ROWID;

-- TLS-Fingerabdruecke (JA3/JA3S/JA4/JA4S): welcher Client hat welchen benutzt ...
CREATE TABLE IF NOT EXISTS fp_clients (
    type       TEXT NOT NULL,
    fp         TEXT NOT NULL,
    ip         TEXT NOT NULL,
    first_seen INTEGER,
    last_seen  INTEGER,
    count      INTEGER DEFAULT 0,
    PRIMARY KEY (type, fp, ip)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_fp_clients_seen ON fp_clients(last_seen);
CREATE INDEX IF NOT EXISTS idx_fp_clients_ip ON fp_clients(ip);
-- ... und zu welchen Zielen (SNI, ersatzweise Ziel-IP)
CREATE TABLE IF NOT EXISTS fp_servers (
    type       TEXT NOT NULL,
    fp         TEXT NOT NULL,
    server     TEXT NOT NULL,
    first_seen INTEGER,
    last_seen  INTEGER,
    count      INTEGER DEFAULT 0,
    PRIMARY KEY (type, fp, server)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_fp_servers_seen ON fp_servers(last_seen);
-- Eigene Bezeichnung / Harmlos-Markierung fuer einen Fingerabdruck
CREATE TABLE IF NOT EXISTS fp_notes (
    type     TEXT NOT NULL,
    fp       TEXT NOT NULL,
    label    TEXT,
    harmless INTEGER NOT NULL DEFAULT 0,
    updated  INTEGER,
    PRIMARY KEY (type, fp)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS talkers (
    hour  INTEGER NOT NULL,
    kind  TEXT NOT NULL,
    key   TEXT NOT NULL,
    count INTEGER DEFAULT 0,
    bytes INTEGER DEFAULT 0,
    PRIMARY KEY (hour, kind, key)
);
"""


def connect(db_path):
    conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


# --------------------------------------------------------------------------
# Zeitstempel
# --------------------------------------------------------------------------

_eve_ts_cache = {}


def parse_eve_ts(s):
    """'2026-11-19T10:23:45.123456+0100' -> epoch (int). Cache pro Sekunde."""
    if not s:
        return int(time.time())
    key = s[:19] + s[-5:]
    v = _eve_ts_cache.get(key)
    if v is None:
        try:
            v = int(datetime.strptime(key, "%Y-%m-%dT%H:%M:%S%z").timestamp())
        except ValueError:
            try:
                v = int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
            except ValueError:
                v = int(time.time())
        if len(_eve_ts_cache) > 20000:
            _eve_ts_cache.clear()
        _eve_ts_cache[key] = v
    return v


_fast_ts_cache = {}


def parse_fast_ts(s):
    """'11/19/2026-10:23:45' (lokale Zeit) -> epoch (int)."""
    v = _fast_ts_cache.get(s)
    if v is None:
        v = int(time.mktime(time.strptime(s, "%m/%d/%Y-%H:%M:%S")))
        if len(_fast_ts_cache) > 20000:
            _fast_ts_cache.clear()
        _fast_ts_cache[s] = v
    return v


# --------------------------------------------------------------------------
# Datei-Tailer (inkrementelles Lesen mit Rotationserkennung)
# --------------------------------------------------------------------------

class Tailer:
    def __init__(self, conn, name, path, start_at_end, max_bytes):
        self.conn = conn
        self.name = name
        self.path = path
        self.start_at_end = start_at_end
        self.max_bytes = max_bytes
        self.inode, self.offset = self._load_state()
        self.last_error = None
        self.size = 0

    def _load_state(self):
        row = self.conn.execute(
            "SELECT value FROM state WHERE key=?", ("tail:" + self.name,)
        ).fetchone()
        if row:
            try:
                d = json.loads(row["value"])
                if d.get("path", self.path) == self.path:
                    return d.get("inode"), d.get("offset", 0)
            except ValueError:
                pass
        return None, None

    def save_state(self):
        self.conn.execute(
            "INSERT INTO state(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ("tail:" + self.name, json.dumps({"inode": self.inode, "offset": self.offset, "path": self.path})),
        )

    def read_lines(self):
        """Liefert eine Liste (byte_offset, zeile) vollstaendiger neuer Zeilen."""
        try:
            st = os.stat(self.path)
        except OSError as e:
            self.last_error = str(e)
            return []
        self.size = st.st_size
        if self.offset is None:  # allererster Start
            self.offset = st.st_size if self.start_at_end else 0
            self.inode = st.st_ino
        elif self.inode != st.st_ino or st.st_size < self.offset:
            log.info("%s: Rotation erkannt, lese von vorn", self.path)
            self.inode = st.st_ino
            self.offset = 0
        if st.st_size == self.offset:
            self.last_error = None
            return []
        try:
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                data = f.read(self.max_bytes)
        except OSError as e:
            self.last_error = str(e)
            return []
        self.last_error = None
        end = data.rfind(b"\n")
        if end < 0:
            return []
        pos = self.offset
        self.offset += end + 1
        out = []
        for raw in data[:end].split(b"\n"):
            out.append((pos, raw.decode("utf-8", errors="replace")))
            pos += len(raw) + 1
        return out


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

FAST_RE = re.compile(
    r"^(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2})\.\d+\s+"
    r"(?:\[(Drop|wDrop)\]\s+)?"
    r"\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.*?)\s+\[\*\*\]\s+"
    r"(?:\[Classification:\s*(.*?)\]\s+)?"
    r"\[Priority:\s*(\d+)\]\s+"
    r"(?:\{(\S+)\}\s+(\S+)\s+->\s+(\S+))?"
)


def split_endpoint(ep):
    """'1.2.3.4:443' / '2001:db8::1:443' -> (ip, port)."""
    if not ep:
        return None, None
    ip, sep, port = ep.rpartition(":")
    if not sep:
        return ep, None
    try:
        return ip, int(port)
    except ValueError:
        return ep, None


def parse_fast_line(line):
    m = FAST_RE.match(line)
    if not m:
        return None
    ts, drop, gid, sid, rev, msg, cls, prio, proto, src, dst = m.groups()
    src_ip, src_port = split_endpoint(src)
    dest_ip, dest_port = split_endpoint(dst)
    action = {"Drop": "blocked", "wDrop": "wdrop"}.get(drop, "allowed")
    return {
        "ts": parse_fast_ts(ts),
        "gid": int(gid), "sid": int(sid), "rev": int(rev),
        "signature": msg, "category": cls or "", "severity": int(prio),
        "action": action, "proto": proto or "", "app_proto": "",
        "src_ip": src_ip, "src_port": src_port,
        "dest_ip": dest_ip, "dest_port": dest_port,
    }


def eve_alert(ev, ts):
    a = ev.get("alert") or {}
    return {
        "ts": ts,
        "gid": int(a.get("gid", 1)), "sid": int(a.get("signature_id", 0)),
        "rev": int(a.get("rev", 0)),
        "signature": a.get("signature", ""), "category": a.get("category", ""),
        "severity": int(a.get("severity", 3)),
        "action": a.get("action", "allowed"),
        "proto": ev.get("proto", ""), "app_proto": ev.get("app_proto", "") or "",
        "src_ip": ev.get("src_ip"), "src_port": ev.get("src_port"),
        "dest_ip": ev.get("dest_ip"), "dest_port": ev.get("dest_port"),
    }


def dns_query_name(dns):
    t = dns.get("type")
    if t not in ("query", "request"):
        return None
    name = dns.get("rrname")
    if not name:
        qs = dns.get("queries") or []
        if qs:
            name = qs[0].get("rrname")
    return name.lower().rstrip(".") if name else None


def dns_answer_pairs(dns):
    """(ip, angefragter Name) aus einer DNS-Antwort (eve v1, v2 und v3)."""
    t = dns.get("type")
    if t not in ("answer", "response"):
        return []
    qname = dns.get("rrname")
    qs = dns.get("queries")
    if isinstance(qs, list) and qs and isinstance(qs[0], dict) and qs[0].get("rrname"):
        qname = qs[0]["rrname"]
    qname = norm_domain(qname)
    if not qname:
        return []
    ips = []
    if dns.get("rrtype") in ("A", "AAAA") and isinstance(dns.get("rdata"), str):
        ips.append(dns["rdata"])  # eve v1: ein Event je Antwort-Record
    for ans in dns.get("answers") or []:
        if isinstance(ans, dict) and ans.get("rrtype") in ("A", "AAAA") and ans.get("rdata"):
            ips.append(ans["rdata"])
    grouped = dns.get("grouped") or {}
    if isinstance(grouped, dict):
        for k in ("A", "AAAA"):
            for ip in grouped.get(k) or []:
                if isinstance(ip, str):
                    ips.append(ip)
    return [(ip, qname) for ip in set(ips)]


MAC_RE = re.compile(r"^[0-9a-f]{2}([:-]?)[0-9a-f]{2}(\1[0-9a-f]{2}){4}$")


def norm_mac(mac):
    """'AA-BB-CC-DD-EE-FF' / 'aabbccddeeff' -> 'aa:bb:cc:dd:ee:ff'; None fuer ungueltige,
    Null-, Broadcast- und Multicast-Adressen."""
    if not isinstance(mac, str):
        return None
    m = mac.strip().lower()
    if not MAC_RE.match(m):
        return None
    h = m.replace(":", "").replace("-", "")
    if h == "000000000000" or int(h[1], 16) & 1:   # Gruppen-Bit gesetzt -> Multicast/Broadcast
        return None
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def ether_macs(ev):
    """(src_mac, dest_mac) aus dem ether-Feld. Paket-Events haben src_mac/dest_mac,
    flow-Events (Suricata 7+) Listen src_macs/dest_macs."""
    e = ev.get("ether")
    if not isinstance(e, dict):
        return None, None
    def one(k):
        v = e.get(k)
        if v is None:
            l = e.get(k + "s")
            v = l[0] if isinstance(l, list) and l else None
        return norm_mac(v)
    return one("src_mac"), one("dest_mac")


def tls_fingerprints(obj):
    """JA3/JA3S/JA4/JA4S aus einem tls- oder quic-Objekt von eve.json.
    Suricata schreibt ja3/ja3s als {"hash", "string"}, ja4 als Text - beides wird akzeptiert."""
    out = []
    if not isinstance(obj, dict):
        return out
    for t in FP_TYPES:
        v = obj.get(t)
        if isinstance(v, dict):
            v = v.get("hash")
        if isinstance(v, str):
            v = v.strip().lower()
            if 0 < len(v) <= 64:
                out.append((t, v))
    return out


def fp_type_for(term):
    """Moegliche Typen fuer einen eingegebenen Hash (Suche)."""
    t = term.strip().lower()
    if RE_MD5.match(t):
        return t, ["ja3", "ja3s"]
    if RE_JA4.match(t):
        return t, ["ja4"]
    if RE_JA4S.match(t):
        return t, ["ja4s"]
    return t, []


# --------------------------------------------------------------------------
# Ingest
# --------------------------------------------------------------------------

class Batch:
    def __init__(self):
        self.traffic = defaultdict(lambda: [0, 0, 0])
        self.events = defaultdict(int)
        self.talkers = defaultdict(lambda: [0, 0])
        self.alerts = []
        self.index = []
        self.names = {}
        self.hosts = {}   # lokale IP -> [mac, first, last]
        self.macs = {}    # mac -> [dhcp_name, first, last]
        self.fp_clients = {}  # (typ, fp, ip) -> [first, last, count]
        self.fp_servers = {}  # (typ, fp, server) -> [first, last, count]

    @staticmethod
    def _seen(d, key, ts):
        v = d.get(key)
        if v is None:
            d[key] = [ts, ts, 1]
        else:
            v[0] = min(v[0], ts)
            v[1] = max(v[1], ts)
            v[2] += 1

    def fingerprints(self, ev, obj, ts):
        fps = tls_fingerprints(obj)
        if not fps:
            return
        client = ev.get("src_ip")
        server = norm_domain(obj.get("sni") or "") or ev.get("dest_ip")
        for t, fp in fps:
            if client:
                self._seen(self.fp_clients, (t, fp, client), ts)
            if server:
                self._seen(self.fp_servers, (t, fp, server), ts)

    def host(self, ip, mac, ts):
        if not ip or addr_kind(ip) != "device":
            return
        h = self.hosts.get(ip)
        if h is None:
            self.hosts[ip] = [mac, ts, ts]
        else:
            if mac and ts >= h[2]:
                h[0] = mac
            elif mac and not h[0]:
                h[0] = mac
            h[1] = min(h[1], ts)
            h[2] = max(h[2], ts)

    def mac(self, mac, dhcp_name, ts):
        m = self.macs.get(mac)
        if m is None:
            self.macs[mac] = [dhcp_name, ts, ts]
        else:
            m[0] = dhcp_name or m[0]
            m[1] = min(m[1], ts)
            m[2] = max(m[2], ts)

    def name(self, ip, name, source, ts):
        name = norm_domain(name)
        if not ip or not name or not is_global(ip):
            return
        n = self.names.get((ip, name))
        if n is None:
            self.names[(ip, name)] = [source, ts, ts, 1]
        else:
            n[0] = source
            n[1] = min(n[1], ts)
            n[2] = max(n[2], ts)
            n[3] += 1

    def talk(self, hour, kind, key, nbytes=0):
        if key is None or key == "":
            return
        t = self.talkers[(hour, kind, str(key))]
        t[0] += 1
        t[1] += nbytes

    def empty(self):
        return not (self.traffic or self.events or self.talkers or self.alerts or self.names
                    or self.hosts or self.macs or self.fp_clients or self.fp_servers)


class Ingestor(threading.Thread):
    def __init__(self, cfg):
        super().__init__(daemon=True, name="ingestor")
        self.cfg = cfg
        self.conn = connect(cfg["db_path"])
        self.cycle_lock = threading.Lock()
        self._setup_sources()
        self.status = {"last_cycle": None, "last_cycle_seconds": 0,
                       "lines_total": 0, "parse_errors": 0, "behind": False}
        self.lock = threading.Lock()
        self.last_cleanup = 0
        self.write_clock = 0       # groesster bisher gesehener Zeitstempel in eve.json
        self.index_key = None      # (inode, minute) des letzten Index-Eintrags
        self.live_on = False
        self.live = LiveTracker(self.alerts_from_eve)
        # intel wird in main() gesetzt (ThreatIntel entsteht nach dem Ingestor)
        self.profiler = anomaly.Profiler(None) if cfg.get("anomaly_detection", True) else None
        self._migrate_live_hosts()

    def _migrate_live_hosts(self):
        """Version 1.4.0 hat Geraete als JSON im state gespeichert -> in die Tabellen uebernehmen."""
        row = self.conn.execute("SELECT value FROM state WHERE key='live:hosts'").fetchone()
        if not row:
            return
        try:
            d = json.loads(row["value"])
        except ValueError:
            d = {}
        b = Batch()
        for ip, h in (d.get("hosts") or {}).items():
            if isinstance(h, dict):
                b.host(ip, norm_mac(h.get("mac")), int(h.get("seen") or time.time()))
        for mac, name in (d.get("macs") or {}).items():
            if norm_mac(mac):
                b.mac(norm_mac(mac), name, int(time.time()))
        with self.conn as c:
            self._flush_hosts(c, b)
            c.execute("DELETE FROM state WHERE key='live:hosts'")

    def _setup_sources(self):
        cfg = self.cfg
        self.alerts_from_eve = cfg["alert_source"] == "eve"
        self.eve = Tailer(self.conn, "eve", cfg["eve_json"], cfg["start_at_end"],
                          cfg["max_bytes_per_cycle"])
        self.fast = Tailer(self.conn, "fast", cfg["fast_log"], cfg["start_at_end"],
                           cfg["max_bytes_per_cycle"])

    def reconfigure(self, changes):
        """Neue Dateipfade / Alert-Quelle uebernehmen (wartet auf laufenden Zyklus)."""
        with self.cycle_lock:
            self.cfg.update(changes)
            self._setup_sources()
            self.live.alerts_from_eve = self.alerts_from_eve
        log.info("Neue Einstellungen: eve=%s fast=%s alerts=%s", self.cfg["eve_json"],
                 self.cfg["fast_log"], self.cfg["alert_source"])

    def run(self):
        while True:
            try:
                with self.cycle_lock:
                    behind = self.cycle()
            except Exception:
                log.exception("Fehler im Ingest-Zyklus")
                behind = False
            if time.time() - self.last_cleanup > 3600:
                try:
                    self.cleanup()
                except Exception:
                    log.exception("Fehler beim Aufraeumen")
            if not behind:
                # Live-Ansicht offen -> jede Sekunde lesen, sonst im normalen Takt
                if self.live.active():
                    time.sleep(1)
                else:
                    for _ in range(int(self.cfg["poll_interval_seconds"] * 4)):
                        time.sleep(0.25)
                        if self.live.active() and time.time() - (self.status["last_cycle"] or 0) >= 1:
                            break

    def cycle(self):
        t0 = time.time()
        batch = Batch()
        n = 0
        self.live_on = self.live.active()
        errors = 0

        now = time.time()
        for off, line in self.eve.read_lines():
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                errors += 1
                continue
            n += 1
            ts = self.handle_eve(ev, batch)
            # Zeitindex: Dateiposition je Minute (nach "Schreibzeit" = max. Zeitstempel,
            # weil flow-Events mit ihrer Startzeit erst am Flow-Ende geschrieben werden)
            if ts > self.write_clock and ts < now + 300:
                self.write_clock = ts
            key = (self.eve.inode, self.write_clock - self.write_clock % 60)
            if key != self.index_key and self.write_clock:
                batch.index.append((key[0], key[1], off))
                self.index_key = key

        if not self.alerts_from_eve:
            for _, line in self.fast.read_lines():
                if not line.strip():
                    continue
                a = parse_fast_line(line)
                if a is None:
                    errors += 1
                    continue
                n += 1
                batch.alerts.append(a)
                if self.live_on:
                    self.live.feed_fast_alert(a)

        self.flush(batch)
        self.live.tick(n)
        behind = (self.eve.offset or 0) < self.eve.size or (
            not self.alerts_from_eve and (self.fast.offset or 0) < self.fast.size)
        with self.lock:
            self.status.update(
                last_cycle=int(time.time()),
                last_cycle_seconds=round(time.time() - t0, 3),
                behind=behind,
            )
            self.status["lines_total"] += n
            self.status["parse_errors"] += errors
        if n:
            log.debug("%d Zeilen verarbeitet in %.2fs", n, time.time() - t0)
        return behind

    def handle_eve(self, ev, b):
        et = ev.get("event_type", "unknown")
        ts = parse_eve_ts(ev.get("timestamp"))
        minute = ts - ts % 60
        hour = ts - ts % 3600
        b.events[(minute, et)] += 1
        # Live-Ansicht: nur wenn jemand zusieht
        live = self.live if self.live_on else None
        if live:
            if et == "flow":
                live.feed(ev, parse_eve_ts((ev.get("flow") or {}).get("end") or ev.get("timestamp")))
            else:
                live.feed(ev, ts)

        if et == "flow" or et == "dhcp":
            smac, dmac = ether_macs(ev)
            b.host(ev.get("src_ip"), smac, ts)
            b.host(ev.get("dest_ip"), dmac, ts)
            if et == "dhcp":
                d = ev.get("dhcp") or {}
                mac = norm_mac(d.get("client_mac"))
                if mac:
                    b.mac(mac, (d.get("hostname") or "").strip()[:64] or None, ts)
                    for k in ("assigned_ip", "client_ip"):
                        if d.get(k) and d[k] != "0.0.0.0":
                            b.host(d[k], mac, ts)

        if et == "flow":
            f = ev.get("flow") or {}
            if self.profiler:
                self.profiler.flow(ev, ts, *ether_macs(ev))
            nbytes = int(f.get("bytes_toserver", 0)) + int(f.get("bytes_toclient", 0))
            pkts = int(f.get("pkts_toserver", 0)) + int(f.get("pkts_toclient", 0))
            proto = ev.get("proto") or "?"
            app = ev.get("app_proto") or "unknown"
            t = b.traffic[(minute, proto, app)]
            t[0] += 1
            t[1] += nbytes
            t[2] += pkts
            b.talk(hour, "src_ip", ev.get("src_ip"), nbytes)
            b.talk(hour, "dest_ip", ev.get("dest_ip"), nbytes)
            if ev.get("dest_port") is not None:
                b.talk(hour, "dest_port", "%s/%s" % (proto, ev.get("dest_port")), nbytes)
        elif et == "dns":
            dns = ev.get("dns") or {}
            name = dns_query_name(dns)
            if name:
                b.talk(hour, "dns", name)
                b.talk(hour, "dns_client", ev.get("src_ip"))
                if self.profiler:
                    self.profiler.dns(ev, ts, name, ether_macs(ev)[0])
            for ip, qname in dns_answer_pairs(dns):
                b.name(ip, qname, "dns", ts)
                if live:
                    live.name(ip, qname)
        elif et == "tls":
            sni = (ev.get("tls") or {}).get("sni")
            b.fingerprints(ev, ev.get("tls") or {}, ts)
            if self.profiler:
                self.profiler.tls(ev, ts, sni, ether_macs(ev)[0])
            b.talk(hour, "tls_sni", sni)
            b.name(ev.get("dest_ip"), sni, "tls", ts)
            if live:
                live.name(ev.get("dest_ip"), sni)
        elif et == "http":
            host = (ev.get("http") or {}).get("hostname")
            b.talk(hour, "http_host", host)
            b.name(ev.get("dest_ip"), host, "http", ts)
            if live:
                live.name(ev.get("dest_ip"), host)
        elif et == "quic":
            b.fingerprints(ev, ev.get("quic") or {}, ts)
            if self.profiler:
                self.profiler.tls(ev, ts, (ev.get("quic") or {}).get("sni"), ether_macs(ev)[0])
        elif et == "alert" and self.alerts_from_eve:
            b.alerts.append(eve_alert(ev, ts))
        return ts

    def flush(self, b):
        c = self.conn
        with c:
            if b.traffic:
                c.executemany(
                    "INSERT INTO traffic(minute, proto, app_proto, flows, bytes, pkts) "
                    "VALUES(?,?,?,?,?,?) ON CONFLICT(minute, proto, app_proto) DO UPDATE SET "
                    "flows=flows+excluded.flows, bytes=bytes+excluded.bytes, pkts=pkts+excluded.pkts",
                    [(k[0], k[1], k[2], v[0], v[1], v[2]) for k, v in b.traffic.items()],
                )
            if b.events:
                c.executemany(
                    "INSERT INTO events(minute, event_type, count) VALUES(?,?,?) "
                    "ON CONFLICT(minute, event_type) DO UPDATE SET count=count+excluded.count",
                    [(k[0], k[1], v) for k, v in b.events.items()],
                )
            if b.talkers:
                c.executemany(
                    "INSERT INTO talkers(hour, kind, key, count, bytes) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(hour, kind, key) DO UPDATE SET "
                    "count=count+excluded.count, bytes=bytes+excluded.bytes",
                    [(k[0], k[1], k[2], v[0], v[1]) for k, v in b.talkers.items()],
                )
            if b.alerts:
                c.executemany(
                    "INSERT INTO alerts(ts, gid, sid, rev, signature, category, severity, action, "
                    "proto, app_proto, src_ip, src_port, dest_ip, dest_port) VALUES "
                    "(:ts,:gid,:sid,:rev,:signature,:category,:severity,:action,"
                    ":proto,:app_proto,:src_ip,:src_port,:dest_ip,:dest_port)",
                    b.alerts,
                )
                c.executemany(
                    "INSERT INTO signatures(gid, sid, signature, category, severity, "
                    "first_seen, last_seen, total) VALUES(:gid,:sid,:signature,:category,"
                    ":severity,:ts,:ts,1) ON CONFLICT(gid, sid) DO UPDATE SET "
                    "signature=excluded.signature, category=excluded.category, "
                    "severity=excluded.severity, "
                    "first_seen=MIN(first_seen, excluded.first_seen), "
                    "last_seen=MAX(last_seen, excluded.last_seen), total=total+1",
                    b.alerts,
                )
            if b.names:
                c.executemany(
                    "INSERT INTO ip_names(ip, name, source, first_seen, last_seen, count) "
                    "VALUES(?,?,?,?,?,?) ON CONFLICT(ip, name) DO UPDATE SET source=excluded.source, "
                    "first_seen=MIN(first_seen, excluded.first_seen), "
                    "last_seen=MAX(last_seen, excluded.last_seen), count=count+excluded.count",
                    [(k[0], k[1], v[0], v[1], v[2], v[3]) for k, v in b.names.items()],
                )
            if b.index:
                c.executemany(
                    "INSERT INTO eve_index(inode, minute, offset) VALUES(?,?,?) "
                    "ON CONFLICT(inode, minute) DO UPDATE SET offset=MIN(offset, excluded.offset)",
                    b.index,
                )
            self._flush_hosts(c, b)
            if self.profiler:
                self.profiler.flush(c)
            for table, col, d in (("fp_clients", "ip", b.fp_clients), ("fp_servers", "server", b.fp_servers)):
                if d:
                    c.executemany(
                        "INSERT INTO %s(type, fp, %s, first_seen, last_seen, count) VALUES(?,?,?,?,?,?) "
                        "ON CONFLICT(type, fp, %s) DO UPDATE SET "
                        "first_seen=MIN(first_seen, excluded.first_seen), "
                        "last_seen=MAX(last_seen, excluded.last_seen), count=count+excluded.count"
                        % (table, col, col),
                        [(k[0], k[1], k[2], v[0], v[1], v[2]) for k, v in d.items()])
            self.eve.save_state()
            self.fast.save_state()

    @staticmethod
    def _flush_hosts(c, b):
        if b.hosts:
            c.executemany(
                "INSERT INTO hosts(ip, mac, first_seen, last_seen) VALUES(?,?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET "
                "mac=CASE WHEN excluded.mac IS NOT NULL AND excluded.last_seen >= hosts.last_seen "
                "THEN excluded.mac ELSE COALESCE(hosts.mac, excluded.mac) END, "
                "first_seen=MIN(first_seen, excluded.first_seen), "
                "last_seen=MAX(last_seen, excluded.last_seen)",
                [(k, v[0], v[1], v[2]) for k, v in b.hosts.items()],
            )
        if b.macs:
            c.executemany(
                "INSERT INTO macs(mac, dhcp_name, first_seen, last_seen) VALUES(?,?,?,?) "
                "ON CONFLICT(mac) DO UPDATE SET dhcp_name=COALESCE(excluded.dhcp_name, macs.dhcp_name), "
                "first_seen=MIN(first_seen, excluded.first_seen), "
                "last_seen=MAX(last_seen, excluded.last_seen)",
                [(k, v[0], v[1], v[2]) for k, v in b.macs.items()],
            )

    def cleanup(self):
        self.last_cleanup = time.time()
        cutoff = int(time.time()) - self.cfg["retention_days"] * 86400
        with self.conn as c:
            c.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,))
            c.execute("DELETE FROM traffic WHERE minute < ?", (cutoff,))
            c.execute("DELETE FROM events WHERE minute < ?", (cutoff,))
            c.execute("DELETE FROM talkers WHERE hour < ?", (cutoff,))
            c.execute("DELETE FROM eve_index WHERE minute < ?", (cutoff,))
            c.execute("DELETE FROM ip_names WHERE last_seen < ?", (cutoff,))
            c.execute("DELETE FROM hosts WHERE last_seen < ?", (cutoff,))
            c.execute("DELETE FROM macs WHERE last_seen < ?", (cutoff,))
            c.execute("DELETE FROM fp_clients WHERE last_seen < ?", (cutoff,))
            c.execute("DELETE FROM fp_servers WHERE last_seen < ?", (cutoff,))
            anomaly.cleanup(c, self.cfg["retention_days"])
        self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        log.info("Aufraeumen: Daten aelter als %d Tage geloescht", self.cfg["retention_days"])

    def get_status(self):
        with self.lock:
            s = dict(self.status)
        s["files"] = {
            "eve_json": {"path": self.eve.path, "offset": self.eve.offset,
                         "size": self.eve.size, "error": self.eve.last_error},
            "fast_log": {"path": self.fast.path, "offset": self.fast.offset,
                         "size": self.fast.size, "error": self.fast.last_error,
                         "used": not self.alerts_from_eve},
        }
        s["alert_source"] = self.cfg["alert_source"]
        return s


# --------------------------------------------------------------------------
# API-Abfragen
# --------------------------------------------------------------------------

NICE_BUCKETS = [60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400]


def bucket_for(hours):
    target = hours * 3600 / 150.0
    for b in NICE_BUCKETS:
        if b >= target:
            return b
    return NICE_BUCKETS[-1]


def time_axis(since, now, bucket):
    start = since - since % bucket
    return list(range(start, now + 1, bucket))


def series_from_rows(rows, axis, bucket, top_n=8):
    """rows: (bucket_ts, name, value) -> {buckets, series:[{name, data}]}"""
    idx = {t: i for i, t in enumerate(axis)}
    per = defaultdict(lambda: [0] * len(axis))
    totals = defaultdict(int)
    for t, name, v in rows:
        i = idx.get(t)
        if i is None:
            continue
        per[name][i] += v or 0
        totals[name] += v or 0
    names = sorted(totals, key=lambda n: -totals[n])
    keep, rest = names[:top_n], names[top_n:]
    series = [{"name": n, "total": totals[n], "data": per[n]} for n in keep]
    if rest:
        other = [0] * len(axis)
        for n in rest:
            for i, v in enumerate(per[n]):
                other[i] += v
        series.append({"name": "andere", "total": sum(other), "data": other})
    return {"bucket": bucket, "buckets": axis, "series": series}


def compact_rep(a):
    """Kurzfassung einer IP-Bewertung fuer Listen."""
    if not a:
        return None
    out = {"verdict": a["verdict"]}
    if not a["global"]:
        return out
    asn = a.get("asn")
    out.update(
        lists=[l["name"] for l in a["lists"]],
        domain_lists=sorted({l["name"] for n in a["names"] for l in n["lists"]}),
        services=a.get("services", []),
        rank=a.get("rank"),
        name=a["names"][0]["name"] if a["names"] else None,
        asn=("AS%d %s" % (asn["asn"], asn["short"] or asn["name"])) if asn else None,
        reasons=[r["text"] for r in a["reasons"]],
    )
    return out


class Api:
    REP_CACHE_SECONDS = 120

    def __init__(self, cfg, ingestor, intel):
        self.cfg = cfg
        self.ingestor = ingestor
        self.intel = intel
        self._rep_cache = {}
        self._rep_lock = threading.Lock()
        self._live_cache = {}
        self._dev_cache = (0, None)
        self.runtime = {}   # https_active, https_error (von main gesetzt)
        self.auth = None    # von main gesetzt
        self.backup = None  # userdata.AutoBackup, von main gesetzt
        self.detector = None  # anomaly.Detector, von main gesetzt

    @contextlib.contextmanager
    def db(self):
        conn = connect(self.cfg["db_path"])
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def window(q):
        try:
            hours = float(q.get("hours", ["24"])[0])
        except ValueError:
            hours = 24
        hours = max(0.25, min(hours, 24 * 90))
        now = int(time.time())
        return hours, now - int(hours * 3600), now

    @staticmethod
    def flag_filter(q, alias="a"):
        if q.get("include_harmless", ["0"])[0] in ("1", "true"):
            return ""
        return (" AND NOT EXISTS (SELECT 1 FROM flags f WHERE f.gid=%s.gid AND f.sid=%s.sid)"
                % (alias, alias))

    # --- Reputation ------------------------------------------------------------

    @staticmethod
    def names_for(c, ips):
        """Alle zu den IPs gesehenen Hostnamen (neueste zuerst)."""
        out = {}
        ips = [ip for ip in set(ips) if ip and is_global(ip)]
        for i in range(0, len(ips), 500):
            chunk = ips[i:i + 500]
            rows = c.execute(
                "SELECT ip, name, source, last_seen, count FROM ip_names WHERE ip IN (%s) "
                "ORDER BY last_seen DESC" % ",".join("?" * len(chunk)), chunk)
            for r in rows:
                out.setdefault(r["ip"], []).append(dict(r))
        return out

    @staticmethod
    def _trim_names(a, keep):
        """Hostnamen fuer die Anzeige kuerzen: Blocklisten-Treffer und bekannte Dienste zuerst."""
        names = sorted(a.get("names") or [], key=lambda n: (
            not n["lists"], not n["service"], -(n.get("last_seen") or 0)))
        a = dict(a)
        a["names_total"] = len(names)
        a["names"] = names[:keep]
        return a

    def assess_ips(self, c, ips, keep_names=5):
        """{ip: Bewertung} mit kurzem Cache (Feeds und Namen aendern sich langsam)."""
        now = time.time()
        out, missing = {}, []
        with self._rep_lock:
            for ip in set(ips):
                if not ip:
                    continue
                hit = self._rep_cache.get(ip)
                if hit and now - hit[0] < self.REP_CACHE_SECONDS:
                    out[ip] = hit[1]
                else:
                    missing.append(ip)
        if missing:
            names = self.names_for(c, missing)
            fresh = {ip: self.intel.assess_ip(ip, names.get(ip)) for ip in missing}
            out.update(fresh)
            with self._rep_lock:
                if len(self._rep_cache) > 20000:
                    self._rep_cache.clear()
                for ip, a in fresh.items():
                    self._rep_cache[ip] = (now, a)
        return {ip: self._trim_names(a, keep_names) for ip, a in out.items()}

    def _pair_verdicts(self, c, where, args, extra_join=""):
        """[(src, dest, n, verdict)] fuer alle Quelle/Ziel-Paare der passenden Alerts."""
        rows = c.execute(
            "SELECT COALESCE(a.src_ip,'') s, COALESCE(a.dest_ip,'') d, COUNT(*) n FROM alerts a "
            + extra_join + " WHERE " + where + " GROUP BY s, d", args).fetchall()
        reps = self.assess_ips(c, {r["s"] for r in rows} | {r["d"] for r in rows}, keep_names=0)
        return [(r["s"], r["d"], r["n"], self.intel.combine([reps.get(r["s"]), reps.get(r["d"])]))
                for r in rows]

    REP_FILTERS = {
        "bad": lambda v: v in ("malicious", "suspicious"),
        "malicious": lambda v: v == "malicious",
        "hide_known": lambda v: v != "known",
        "unknown": lambda v: v == "unknown",
    }

    # --- GET ---------------------------------------------------------------

    def summary(self, q):
        hours, since, now = self.window(q)
        new_since = now - self.cfg["new_signature_hours"] * 3600
        with self.db() as c:
            t = c.execute("SELECT COALESCE(SUM(flows),0) flows, COALESCE(SUM(bytes),0) bytes, "
                          "COALESCE(SUM(pkts),0) pkts FROM traffic WHERE minute >= ?",
                          (since,)).fetchone()
            ev = c.execute("SELECT COALESCE(SUM(count),0) n FROM events WHERE minute >= ?",
                           (since,)).fetchone()
            a = c.execute(
                "SELECT COUNT(*) total, "
                "SUM(CASE WHEN f.sid IS NULL THEN 1 ELSE 0 END) open, "
                "SUM(CASE WHEN f.sid IS NOT NULL THEN 1 ELSE 0 END) harmless, "
                "SUM(CASE WHEN a.action='blocked' AND f.sid IS NULL THEN 1 ELSE 0 END) blocked_open, "
                "SUM(CASE WHEN a.action='blocked' THEN 1 ELSE 0 END) blocked, "
                "COUNT(DISTINCT a.gid || ':' || a.sid) sids "
                "FROM alerts a LEFT JOIN flags f ON f.gid=a.gid AND f.sid=a.sid WHERE a.ts >= ?",
                (since,)).fetchone()
            new_sigs = c.execute(
                "SELECT COUNT(*) n FROM signatures s WHERE s.first_seen >= ? AND NOT EXISTS "
                "(SELECT 1 FROM flags f WHERE f.gid=s.gid AND f.sid=s.sid)",
                (new_since,)).fetchone()
            clients = c.execute(
                "SELECT COUNT(DISTINCT key) n FROM talkers WHERE kind='src_ip' AND hour >= ?",
                (since - since % 3600,)).fetchone()
            fp_hits = self._fp_hits(c, since)
            anomalies_open = c.execute("SELECT COUNT(*) n FROM anomalies WHERE status='open'").fetchone()["n"]
            rep = defaultdict(int)
            for _, _, n, v in self._pair_verdicts(
                    c, "a.ts >= ? AND f.sid IS NULL", (since,),
                    "LEFT JOIN flags f ON f.gid=a.gid AND f.sid=a.sid"):
                rep[v] += n
        return {
            "hours": hours,
            "flows": t["flows"], "bytes": t["bytes"], "pkts": t["pkts"],
            "events": ev["n"],
            "alerts_total": a["total"] or 0, "alerts_open": a["open"] or 0,
            "alerts_harmless": a["harmless"] or 0, "alerts_blocked": a["blocked"] or 0,
            "alerts_blocked_open": a["blocked_open"] or 0,
            "signatures": a["sids"] or 0, "new_signatures": new_sigs["n"],
            "new_signature_hours": self.cfg["new_signature_hours"],
            "clients": clients["n"],
            "rep": dict(rep),
            "fp_hits": fp_hits,
            "anomalies_open": anomalies_open,
        }

    def traffic(self, q):
        hours, since, now = self.window(q)
        bucket = bucket_for(hours)
        metric = q.get("metric", ["flows"])[0]
        if metric not in ("flows", "bytes", "pkts"):
            metric = "flows"
        group = q.get("group", ["app_proto"])[0]
        if group not in ("app_proto", "proto"):
            group = "app_proto"
        with self.db() as c:
            rows = c.execute(
                "SELECT (minute / ?) * ? AS b, %s AS name, SUM(%s) v FROM traffic "
                "WHERE minute >= ? GROUP BY b, name" % (group, metric),
                (bucket, bucket, since - since % bucket)).fetchall()
        out = series_from_rows([(r["b"], r["name"], r["v"]) for r in rows],
                               time_axis(since, now, bucket), bucket)
        out["metric"] = metric
        return out

    def event_types(self, q):
        hours, since, now = self.window(q)
        with self.db() as c:
            rows = c.execute("SELECT event_type name, SUM(count) n FROM events "
                             "WHERE minute >= ? GROUP BY event_type ORDER BY n DESC",
                             (since,)).fetchall()
        return [dict(r) for r in rows]

    def protocols(self, q):
        hours, since, now = self.window(q)
        with self.db() as c:
            app = c.execute("SELECT app_proto name, SUM(flows) flows, SUM(bytes) bytes "
                            "FROM traffic WHERE minute >= ? GROUP BY app_proto "
                            "ORDER BY flows DESC", (since,)).fetchall()
            tr = c.execute("SELECT proto name, SUM(flows) flows, SUM(bytes) bytes "
                           "FROM traffic WHERE minute >= ? GROUP BY proto "
                           "ORDER BY flows DESC", (since,)).fetchall()
        return {"app_proto": [dict(r) for r in app], "proto": [dict(r) for r in tr]}

    def top(self, q):
        hours, since, now = self.window(q)
        kind = q.get("kind", ["src_ip"])[0]
        order = "bytes" if q.get("order", ["count"])[0] == "bytes" else "count"
        try:
            limit = max(1, min(int(q.get("limit", ["10"])[0]), 100))
        except ValueError:
            limit = 10
        with self.db() as c:
            rows = c.execute(
                "SELECT key, SUM(count) count, SUM(bytes) bytes FROM talkers "
                "WHERE kind=? AND hour >= ? GROUP BY key ORDER BY %s DESC LIMIT ?" % order,
                (kind, since - since % 3600, limit)).fetchall()
        return [dict(r) for r in rows]

    def alert_timeline(self, q):
        hours, since, now = self.window(q)
        bucket = bucket_for(hours)
        with self.db() as c:
            rows = c.execute(
                "SELECT (a.ts / ?) * ? AS b, "
                "CASE WHEN f.sid IS NOT NULL THEN 'harmlos' "
                "     WHEN a.severity <= 1 THEN 'Schwere 1' "
                "     WHEN a.severity = 2 THEN 'Schwere 2' ELSE 'Schwere 3+' END AS name, "
                "COUNT(*) v FROM alerts a LEFT JOIN flags f ON f.gid=a.gid AND f.sid=a.sid "
                "WHERE a.ts >= ? GROUP BY b, name",
                (bucket, bucket, since)).fetchall()
        out = series_from_rows([(r["b"], r["name"], r["v"]) for r in rows],
                               time_axis(since, now, bucket), bucket)
        order = ["Schwere 1", "Schwere 2", "Schwere 3+", "harmlos"]
        out["series"].sort(key=lambda s: order.index(s["name"]) if s["name"] in order else 9)
        return out

    def alerts(self, q):
        hours, since, now = self.window(q)
        where = "a.ts >= ?" + self.flag_filter(q)
        args = [since]
        if q.get("sid"):
            where += " AND a.sid = ?"
            args.append(int(q["sid"][0]))
        if q.get("action"):
            where += " AND a.action = ?"
            args.append(q["action"][0])
        if q.get("ip"):
            where += " AND (a.src_ip = ? OR a.dest_ip = ?)"
            args += [q["ip"][0], q["ip"][0]]
        if q.get("q"):
            where += " AND (a.signature LIKE ? OR a.category LIKE ? OR CAST(a.sid AS TEXT) = ?)"
            like = "%" + q["q"][0] + "%"
            args += [like, like, q["q"][0]]
        try:
            limit = max(1, min(int(q.get("limit", ["100"])[0]), 1000))
            offset = max(0, int(q.get("offset", ["0"])[0]))
        except ValueError:
            limit, offset = 100, 0
        new_since = now - self.cfg["new_signature_hours"] * 3600
        rep_filter = self.REP_FILTERS.get(q.get("rep", [""])[0])
        with self.db() as c:
            if rep_filter:
                keep = [(s_, d_) for s_, d_, _, v in self._pair_verdicts(c, where, args) if rep_filter(v)]
                c.execute("CREATE TEMP TABLE IF NOT EXISTS rep_pairs (s TEXT, d TEXT, PRIMARY KEY (s, d))")
                c.execute("DELETE FROM rep_pairs")
                c.executemany("INSERT OR IGNORE INTO rep_pairs VALUES (?, ?)", keep)
                where += (" AND (COALESCE(a.src_ip,''), COALESCE(a.dest_ip,'')) IN "
                          "(SELECT s, d FROM rep_pairs)")
            total = c.execute("SELECT COUNT(*) n FROM alerts a WHERE " + where, args).fetchone()["n"]
            rows = c.execute(
                "SELECT a.*, (f.sid IS NOT NULL) harmless, f.note, "
                "(s.first_seen >= ?) is_new, s.first_seen "
                "FROM alerts a LEFT JOIN flags f ON f.gid=a.gid AND f.sid=a.sid "
                "LEFT JOIN signatures s ON s.gid=a.gid AND s.sid=a.sid "
                "WHERE " + where + " ORDER BY a.ts DESC, a.id DESC LIMIT ? OFFSET ?",
                [new_since] + args + [limit, offset]).fetchall()
            items = [dict(r) for r in rows]
            reps = self.assess_ips(c, {i["src_ip"] for i in items} | {i["dest_ip"] for i in items})
        for it in items:
            sr, dr = reps.get(it["src_ip"]), reps.get(it["dest_ip"])
            it["rep"] = {"verdict": self.intel.combine([sr, dr]),
                         "src": compact_rep(sr), "dest": compact_rep(dr)}
        return {"total": total, "items": items}

    def signatures(self, q):
        hours, since, now = self.window(q)
        new_since = now - self.cfg["new_signature_hours"] * 3600
        with self.db() as c:
            rows = c.execute(
                "SELECT a.gid, a.sid, s.signature, s.category, s.severity, "
                "COUNT(*) count, MAX(a.ts) last_seen, s.first_seen, s.total, "
                "SUM(CASE WHEN a.action='blocked' THEN 1 ELSE 0 END) blocked, "
                "COUNT(DISTINCT a.src_ip) src_count, COUNT(DISTINCT a.dest_ip) dest_count, "
                "(f.sid IS NOT NULL) harmless, f.note, (s.first_seen >= ?) is_new "
                "FROM alerts a JOIN signatures s ON s.gid=a.gid AND s.sid=a.sid "
                "LEFT JOIN flags f ON f.gid=a.gid AND f.sid=a.sid "
                "WHERE a.ts >= ?" + self.flag_filter(q) +
                " GROUP BY a.gid, a.sid ORDER BY harmless ASC, is_new DESC, count DESC",
                (new_since, since)).fetchall()
            items = [dict(r) for r in rows]
            # Beispiel-Verbindungen (haeufigste Quell->Ziel-Paare) je Signatur
            for it in items[:200]:
                ex = c.execute(
                    "SELECT src_ip, dest_ip, dest_port, COUNT(*) n FROM alerts "
                    "WHERE gid=? AND sid=? AND ts >= ? GROUP BY src_ip, dest_ip, dest_port "
                    "ORDER BY n DESC LIMIT 3", (it["gid"], it["sid"], since)).fetchall()
                it["examples"] = [dict(e) for e in ex]
            ips = {e[k] for it in items[:200] for e in it["examples"] for k in ("src_ip", "dest_ip")}
            reps = self.assess_ips(c, ips)
        for it in items[:200]:
            verdicts = []
            for e in it["examples"]:
                sr, dr = reps.get(e["src_ip"]), reps.get(e["dest_ip"])
                e["src_rep"], e["dest_rep"] = compact_rep(sr), compact_rep(dr)
                e["verdict"] = self.intel.combine([sr, dr])
                verdicts.append(e["verdict"])
            it["verdict"] = max(verdicts, key=lambda v: threatintel.VERDICT_ORDER[v]) if verdicts else None
        return items

    def flags(self, q):
        with self.db() as c:
            rows = c.execute(
                "SELECT f.*, s.signature, s.category, s.last_seen, s.total FROM flags f "
                "LEFT JOIN signatures s ON s.gid=f.gid AND s.sid=f.sid "
                "ORDER BY f.created DESC").fetchall()
        return [dict(r) for r in rows]

    def status(self, q):
        s = self.ingestor.get_status()
        try:
            s["db_size"] = os.path.getsize(self.cfg["db_path"])
        except OSError:
            s["db_size"] = None
        with self.db() as c:
            s["alerts_in_db"] = c.execute("SELECT COUNT(*) n FROM alerts").fetchone()["n"]
            s["flags"] = c.execute("SELECT COUNT(*) n FROM flags").fetchone()["n"]
            row = c.execute("SELECT MIN(minute) a, MAX(minute) b FROM events").fetchone()
            s["data_from"], s["data_to"] = row["a"], row["b"]
        s["retention_days"] = self.cfg["retention_days"]
        s["version"] = VERSION
        s["install_dir"] = ROOT_DIR
        s["server_time"] = int(time.time())
        s["restore_hint"] = self.backup.restore_hint if self.backup else None
        return s

    # --- POST / DELETE -------------------------------------------------------

    def set_flag(self, body):
        gid = int(body.get("gid", 1))
        sid = int(body["sid"])
        note = (body.get("note") or "")[:500]
        with self.db() as c:
            c.execute(
                "INSERT INTO flags(gid, sid, status, note, created) VALUES(?,?,'harmless',?,?) "
                "ON CONFLICT(gid, sid) DO UPDATE SET note=excluded.note",
                (gid, sid, note, int(time.time())))
        return {"ok": True}

    # --- Alert-Kontext aus eve.json -------------------------------------------

    MAX_CONTEXT_BYTES = 64 * 1024 * 1024
    MAX_EVENTS = 150

    def _eve_file_for_inode(self, inode):
        """Aktuelle eve.json oder rotierte Kopie (eve.json.1, eve.json-2026...) mit diesem inode."""
        cur = self.cfg["eve_json"]
        d, base = os.path.split(cur)
        try:
            names = sorted(os.listdir(d))
        except OSError:
            return None
        for name in [base] + [n for n in names if n.startswith(base) and n != base]:
            if name.endswith((".gz", ".xz", ".bz2", ".zst", ".lz4")):
                continue
            path = os.path.join(d, name)
            try:
                if os.stat(path).st_ino == inode:
                    return path
            except OSError:
                pass
        return None

    def _ranges(self, c, t0, t1):
        """Byte-Bereiche (inode, start, ende|None) in eve-Dateien, die [t0, t1] abdecken."""
        inodes = [r["inode"] for r in c.execute(
            "SELECT DISTINCT inode FROM eve_index WHERE minute BETWEEN ? AND ?", (t0 - 60, t1))]
        row = c.execute("SELECT inode FROM eve_index WHERE minute <= ? ORDER BY minute DESC LIMIT 1",
                        (t0,)).fetchone()
        if row and row["inode"] not in inodes:
            inodes.insert(0, row["inode"])
        out = []
        for ino in inodes:
            r = c.execute("SELECT offset FROM eve_index WHERE inode=? AND minute <= ? "
                          "ORDER BY minute DESC LIMIT 1", (ino, t0 - t0 % 60)).fetchone()
            start = r["offset"] if r else c.execute(
                "SELECT MIN(offset) o FROM eve_index WHERE inode=?", (ino,)).fetchone()["o"]
            r = c.execute("SELECT offset FROM eve_index WHERE inode=? AND minute > ? "
                          "ORDER BY minute ASC LIMIT 1", (ino, t1)).fetchone()
            out.append((ino, start, r["offset"] if r else None))
        return out

    @staticmethod
    def _endpoints(ev):
        return {(ev.get("src_ip"), ev.get("src_port")), (ev.get("dest_ip"), ev.get("dest_port"))}

    @staticmethod
    def _dns_name(dns):
        name = dns.get("rrname")
        if not name:
            for k in ("queries", "answers"):
                lst = dns.get(k) or []
                if lst and isinstance(lst, list) and lst[0].get("rrname"):
                    name = lst[0]["rrname"]
                    break
        return name

    def alert_context(self, q):
        alert_id = int(q["id"][0])
        before = max(0, min(int(q.get("before", ["60"])[0]), 6 * 3600))
        after = max(0, min(int(q.get("after", ["300"])[0]), 6 * 3600))
        with self.db() as c:
            a = c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            if not a:
                raise KeyError("Alert %d nicht gefunden" % alert_id)
            a = dict(a)
            t0, t1 = a["ts"] - before, a["ts"] + after
            ranges = self._ranges(c, t0, t1)

        src, dst = a["src_ip"], a["dest_ip"]
        ips = [ip for ip in (src, dst) if ip]
        needles = [('"%s"' % ip).encode() for ip in ips]
        alert_eps = {(src, a["src_port"]), (dst, a["dest_port"])}
        has_ports = a["src_port"] is not None and a["dest_port"] is not None
        proto = (a["proto"] or "").upper()

        result = {"alert": a, "window": {"from": t0, "to": t1, "before": before, "after": after},
                  "files": [], "notes": [], "eve_alerts": [], "connection": [], "host_pair": [],
                  "dns": [], "hostnames": {ip: [] for ip in ips}, "peers": {ip: {} for ip in ips}}
        if not ranges:
            result["notes"].append("Für diesen Zeitraum gibt es keinen eve.json-Index. "
                                   "Er entsteht beim Einlesen, ältere Daten haben ihn evtl. nicht.")
        candidates = []
        for ino, start, end in ranges:
            path = self._eve_file_for_inode(ino)
            if not path:
                result["notes"].append("Eine Logdatei für den Zeitraum ist nicht mehr verfügbar "
                                       "(rotiert, komprimiert oder gelöscht).")
                continue
            length = (end - start) if end is not None else self.MAX_CONTEXT_BYTES
            length = min(length, self.MAX_CONTEXT_BYTES)
            try:
                with open(path, "rb") as f:
                    f.seek(start)
                    data = f.read(length)
            except OSError as e:
                result["notes"].append("%s: %s" % (path, e))
                continue
            truncated = end is not None and (end - start) > self.MAX_CONTEXT_BYTES
            result["files"].append({"path": path, "bytes_read": len(data), "truncated": truncated})
            if truncated:
                result["notes"].append("Zeitfenster zu groß, nur die ersten 64 MB wurden durchsucht.")
            for raw in data.split(b"\n"):
                if any(nd in raw for nd in needles):
                    candidates.append(raw)

        hostnames = {ip: {} for ip in ips}
        flow_ids = set()
        events = []
        for raw in candidates:
            try:
                ev = json.loads(raw)
            except ValueError:
                continue
            ts = parse_eve_ts(ev.get("timestamp"))
            if ts < t0 - 86400 or ts > t1 + 86400:  # Schutz gegen falsche Datei
                continue
            ev["_ts"] = ts
            events.append(ev)
            et = ev.get("event_type")
            if (et == "alert" and (ev.get("alert") or {}).get("signature_id") == a["sid"]
                    and (not has_ports or self._endpoints(ev) == alert_eps)):
                if ev.get("flow_id"):
                    flow_ids.add(ev["flow_id"])

        seen_conn = 0
        for ev in events:
            et = ev.get("event_type")
            ev_ips = {ev.get("src_ip"), ev.get("dest_ip")}
            same_tuple = has_ports and self._endpoints(ev) == alert_eps and (
                not proto or (ev.get("proto") or "").upper() == proto)
            same_pair = src in ev_ips and dst in ev_ips
            in_window = t0 <= ev["_ts"] <= t1
            # Hostnamen aus DNS-Antworten und TLS-SNI
            if et == "dns":
                dns = ev.get("dns") or {}
                answers = json.dumps([dns.get("answers"), dns.get("grouped"), dns.get("rdata")])
                name = self._dns_name(dns)
                for ip in ips:
                    if name and '"%s"' % ip in answers:
                        hostnames[ip].setdefault(name.rstrip("."), "dns")
                        if len(result["dns"]) < 30:
                            result["dns"].append(ev)
            if et == "tls" and (ev.get("tls") or {}).get("sni") and ev.get("dest_ip") in hostnames:
                hostnames[ev["dest_ip"]].setdefault(ev["tls"]["sni"], "tls")
            if et == "http" and (ev.get("http") or {}).get("hostname") and ev.get("dest_ip") in hostnames:
                hostnames[ev["dest_ip"]].setdefault(ev["http"]["hostname"], "http")

            if (ev.get("flow_id") in flow_ids and ev.get("flow_id")) or same_tuple:
                if et == "alert":
                    result["eve_alerts"].append(ev)
                if seen_conn < self.MAX_EVENTS:
                    result["connection"].append(ev)
                    seen_conn += 1
            elif same_pair:
                if in_window and len(result["host_pair"]) < self.MAX_EVENTS:
                    result["host_pair"].append(ev)
            elif in_window and et != "dns":
                # andere Gespraechspartner der beteiligten IPs
                for ip in ips:
                    if ip in ev_ips:
                        peer = ev.get("dest_ip") if ev.get("src_ip") == ip else ev.get("src_ip")
                        p = result["peers"][ip].setdefault(peer, {"peer": peer, "count": 0, "types": {}})
                        p["count"] += 1
                        p["types"][et] = p["types"].get(et, 0) + 1

        result["hostnames"] = {ip: [{"name": n, "source": s} for n, s in hostnames[ip].items()]
                               for ip in ips}
        result["reputation"] = self.reputation_for_alert(a, hostnames)
        result["peers"] = {ip: sorted(v.values(), key=lambda p: -p["count"])[:15]
                           for ip, v in result["peers"].items()}
        result["flow_ids"] = [str(f) for f in flow_ids]
        result["events_scanned"] = len(events)
        fps = []
        for ev in result["connection"] + result["host_pair"]:
            et = ev.get("event_type")
            for t, fp in tls_fingerprints(ev.get(et) if et in ("tls", "quic") else ev.get("tls")):
                if (t, fp) not in fps:
                    fps.append((t, fp))
        with self.db() as c:
            notes = self._fp_notes(c)
        result["fingerprints"] = [self._fp_assess(t, fp, notes) for t, fp in fps[:12]]
        for lst in (result["connection"], result["host_pair"], result["dns"], result["eve_alerts"]):
            lst.sort(key=lambda e: e["_ts"])
            for e in lst:  # flow_id ist groesser als 2^53 -> als Text, sonst rundet JavaScript
                for k in ("flow_id", "parent_id"):
                    if isinstance(e.get(k), int):
                        e[k] = str(e[k])
        return result

    def reputation_for_alert(self, a, ctx_names=None):
        """Ausfuehrliche Bewertung beider IPs; Namen aus eve-Kontext zaehlen mit."""
        ips = [ip for ip in (a["src_ip"], a["dest_ip"]) if ip]
        with self.db() as c:
            names = self.names_for(c, ips)
        out = {}
        for ip in ips:
            lst = [{"name": n, "source": s + " (Kontext)"} for n, s in (ctx_names or {}).get(ip, {}).items()]
            seen = {n["name"] for n in lst}
            lst += [n for n in names.get(ip, []) if n["name"] not in seen]
            out[ip] = self._trim_names(self.intel.assess_ip(ip, lst), 15)
        return {"verdict": self.intel.combine(list(out.values())), "ips": out,
                "feeds_loaded": any(f["loaded"] for f in self.intel.status()["feeds"])}

    # --- Threat-Feeds -------------------------------------------------------------

    # --- Geraete ----------------------------------------------------------------

    SHARED_MAC_IPS = 4   # so viele IPv4-Adressen an einer MAC (24 h) -> Router o. ae.

    def _device_data(self):
        """Rohdaten aus hosts/macs/device_names plus erkannte geteilte MACs."""
        with self.db() as c:
            hosts = [dict(r) for r in c.execute("SELECT ip, mac, first_seen, last_seen FROM hosts")]
            macs = {r["mac"]: dict(r) for r in c.execute("SELECT * FROM macs")}
            names = {(r["kind"], r["key"]): r["name"] for r in c.execute("SELECT kind, key, name FROM device_names")}
        day = time.time() - 86400
        v4 = defaultdict(int)
        for h in hosts:
            if h["mac"] and ":" not in h["ip"] and (h["last_seen"] or 0) > day:
                v4[h["mac"]] += 1
        shared = {m for m, n in v4.items() if n >= self.SHARED_MAC_IPS}
        return hosts, macs, names, shared

    def device_map(self):
        """{ip: {name, source, mac, shared}} fuer alle lokalen IPs (10 s Cache).
        Reihenfolge: Name der MAC > Name der IP > DHCP-Hostname."""
        ts, m = self._dev_cache
        if m is not None and time.time() - ts < 10:
            return m
        hosts, macs, names, shared = self._device_data()
        m = {}
        for h in hosts:
            ip, mac = h["ip"], h["mac"]
            usable = mac and mac not in shared
            name, src = None, None
            if usable and ("mac", mac) in names:
                name, src = names[("mac", mac)], "mac"
            elif ("ip", ip) in names:
                name, src = names[("ip", ip)], "ip"
            elif usable and (macs.get(mac) or {}).get("dhcp_name"):
                name, src = macs[mac]["dhcp_name"], "dhcp"
            m[ip] = {"name": name, "source": src, "mac": mac, "shared": bool(mac and mac in shared)}
        for (kind, key), name in names.items():
            if kind == "ip" and key not in m:
                m[key] = {"name": name, "source": "ip", "mac": None, "shared": False}
        self._dev_cache = (time.time(), m)
        return m

    def device_names(self, q):
        return {ip: [d["name"], d["source"]] for ip, d in self.device_map().items() if d["name"]}

    def devices(self, q):
        hosts, macs, names, shared = self._device_data()
        by_mac, out = {}, []
        for h in hosts:
            mac = h["mac"]
            if mac and mac not in shared:
                by_mac.setdefault(mac, []).append(h)
            else:
                out.append({"kind": "ip", "key": h["ip"], "mac": mac, "shared": bool(mac),
                            "ips": [h], "first_seen": h["first_seen"], "last_seen": h["last_seen"],
                            "dhcp": None, "name": names.get(("ip", h["ip"]))})
        for mac, hs in by_mac.items():
            hs.sort(key=lambda h: (":" in h["ip"], -(h["last_seen"] or 0)))
            out.append({"kind": "mac", "key": mac, "mac": mac, "shared": False, "ips": hs,
                        "first_seen": min(h["first_seen"] or 0 for h in hs),
                        "last_seen": max(h["last_seen"] or 0 for h in hs),
                        "dhcp": (macs.get(mac) or {}).get("dhcp_name"),
                        "name": names.get(("mac", mac)),
                        # Name, der noch an einer der IPs haengt (vor der MAC-Erkennung vergeben)
                        "ip_names": {h["ip"]: names[("ip", h["ip"])] for h in hs if ("ip", h["ip"]) in names}})
        # MACs nur aus DHCP (noch kein Verkehr gesehen)
        for mac, mrow in macs.items():
            if mac not in by_mac and not any(h["mac"] == mac for h in hosts):
                out.append({"kind": "mac", "key": mac, "mac": mac, "shared": False, "ips": [],
                            "first_seen": mrow["first_seen"], "last_seen": mrow["last_seen"],
                            "dhcp": mrow["dhcp_name"], "name": names.get(("mac", mac))})
        seen = {(d["kind"], d["key"]) for d in out}
        seen.update(("ip", h["ip"]) for h in hosts)   # alte IP-Namen stehen beim Geraet (ip_names)
        for (kind, key), name in names.items():
            if (kind, key) not in seen:   # von Hand angelegt, noch nie gesehen
                out.append({"kind": kind, "key": key, "mac": key if kind == "mac" else None,
                            "shared": False, "ips": [], "first_seen": None, "last_seen": None,
                            "dhcp": None, "name": name, "manual": True})
        def order(d):   # stabil nach IP sortieren (IPv4 vor IPv6), nie gesehene ans Ende
            if not d["ips"]:
                return (2, 0, d["key"])
            ip = ipaddress.ip_address(d["ips"][0]["ip"])
            return (0 if ip.version == 4 else 1, int(ip), "")
        out.sort(key=order)
        return {"devices": out, "has_macs": any(h["mac"] for h in hosts) or bool(macs),
                "shared_limit": self.SHARED_MAC_IPS}

    def set_device(self, body):
        kind = body.get("kind")
        key = str(body.get("key") or "").strip()
        if kind == "mac":
            key = norm_mac(key)
            if not key:
                raise ValueError("ungueltige MAC-Adresse")
        elif kind == "ip":
            try:
                key = str(ipaddress.ip_address(key))
            except ValueError:
                raise ValueError("ungueltige IP-Adresse")
        else:
            raise ValueError("kind muss 'mac' oder 'ip' sein")
        name = " ".join(str(body.get("name") or "").split())[:64]
        with self.db() as c:
            if name:
                c.execute("INSERT INTO device_names(kind, key, name, updated) VALUES(?,?,?,?) "
                          "ON CONFLICT(kind, key) DO UPDATE SET name=excluded.name, updated=excluded.updated",
                          (kind, key, name, int(time.time())))
            else:
                c.execute("DELETE FROM device_names WHERE kind=? AND key=?", (kind, key))
            # Name per MAC ersetzt einen alten Namen an einer der IPs dieser MAC
            if kind == "mac" and name and body.get("replace_ip_names"):
                c.execute("DELETE FROM device_names WHERE kind='ip' AND key IN "
                          "(SELECT ip FROM hosts WHERE mac=?)", (key,))
        self._dev_cache = (0, None)
        return {"ok": True, "kind": kind, "key": key, "name": name or None}

    # --- Live-Ansicht ------------------------------------------------------------

    LIVE_HOLDS = (10, 15, 30, 60, 120, 300)

    def live(self, q):
        hold = int(q.get("hold", ["30"])[0])
        if hold not in self.LIVE_HOLDS:
            raise ValueError("hold muss einer von %s sein" % (self.LIVE_HOLDS,))
        flag = lambda k, d: q.get(k, [d])[0] in ("1", "true")
        snap = self.ingestor.live.snapshot(hold, alerts_only=flag("alerts", "0"),
                                           show_lan=flag("lan", "1"), show_groups=flag("groups", "1"))
        dm = self.device_map()
        for n in snap["nodes"]:
            if n["kind"] == "device":
                d = dm.get(n["id"]) or {}
                n.update(name=d.get("name"), name_source=d.get("source"), mac=d.get("mac"),
                         shared=d.get("shared", False))
        remotes = [n for n in snap["nodes"] if n["kind"] == "remote"]
        names = {n["id"]: list(n["names"]) for n in remotes}
        for e in snap["edges"]:
            if e["peer"] in names:
                for nm in e["names"]:
                    if nm not in names[e["peer"]]:
                        names[e["peer"]].append(nm)
        now = time.time()
        cache = self._live_cache   # ip -> (zeit, live-Namen, angezeigte Namen, Bewertung)
        todo = []
        for n in remotes:
            ip, live_ns = n["id"], tuple(names[n["id"]])
            hit = cache.get(ip)
            if hit and now - hit[0] < 60 and hit[1] == live_ns:
                n["names"], n["rep"] = list(hit[2]), hit[3]
            else:
                todo.append((n, live_ns))
        if todo:
            # IPs ohne live gesehene Namen: Namen aus der Datenbank
            need_db = [n["id"] for n, ns in todo if not ns]
            db_names = {}
            if need_db:
                with self.db() as c:
                    db_names = self.names_for(c, need_db)
            if len(cache) > 5000:
                cache.clear()
            for n, live_ns in todo:
                ns = live_ns or tuple(r["name"] for r in db_names.get(n["id"], [])[:5])
                rep = compact_rep(self.intel.assess_ip(n["id"], [{"name": x} for x in ns]))
                cache[n["id"]] = (now, live_ns, ns, rep)
                n["names"], n["rep"] = list(ns), rep
        snap["interval"] = 1
        return snap

    # --- Anomalieerkennung ----------------------------------------------------

    def _dev_labels(self, devs):
        """Anzeige fuer Geraeteschluessel (MAC oder IPv4): Name, IPs, MAC."""
        hosts, macs, names, shared = self._device_data()
        dm = self.device_map()
        by_mac = defaultdict(list)
        for h in sorted(hosts, key=lambda h: -(h["last_seen"] or 0)):
            if h["mac"]:
                by_mac[h["mac"]].append(h["ip"])
        out = {}
        for d in set(devs):
            if anomaly.is_mac(d):
                ips = by_mac.get(d, [])[:4]
                name = names.get(("mac", d)) or (macs.get(d) or {}).get("dhcp_name") or \
                    next((dm[i]["name"] for i in ips if (dm.get(i) or {}).get("name")), None)
                out[d] = {"dev": d, "mac": d, "ips": ips, "name": name}
            else:
                e = dm.get(d) or {}
                out[d] = {"dev": d, "mac": e.get("mac"), "ips": [d], "name": e.get("name")}
        return out

    @staticmethod
    def _anomaly_row(r):
        a = dict(r)
        try:
            a["detail"] = json.loads(a["detail"] or "{}")
        except ValueError:
            a["detail"] = {}
        return a

    def anomalies(self, q):
        status = q.get("status", ["open"])[0]
        days = max(1, min(int(q.get("days", ["30"])[0]), 365))
        learning = max(1, int(self.cfg.get("anomaly_learning_days", 7)))
        with self.db() as c:
            now = anomaly.data_now(c)
            where = "ts >= ?" + (" AND status='open'" if status == "open" else "")
            rows = [self._anomaly_row(r) for r in c.execute(
                "SELECT * FROM anomalies WHERE " + where + " ORDER BY ts DESC LIMIT 500", (now - days * 86400,))]
            metas = c.execute("SELECT * FROM dev_meta WHERE last_seen >= ? ORDER BY last_seen DESC",
                              (now - 7 * 86400,)).fetchall()
            known = defaultdict(dict)
            for r in c.execute("SELECT dev, kind, COUNT(*) n FROM dev_seen GROUP BY dev, kind"):
                known[r["dev"]][r["kind"]] = r["n"]
            open_by_dev = {r["dev"]: r["n"] for r in c.execute(
                "SELECT dev, COUNT(*) n FROM anomalies WHERE status='open' GROUP BY dev")}
            devices = []
            for m in metas:
                b = anomaly.baseline(c, m, now, learning)
                devices.append({"dev": m["dev"], "first_seen": m["first_seen"], "last_seen": m["last_seen"],
                                "last_ip": m["last_ip"], "learned": b["learned"], "learn_left": b["learn_left"],
                                "need_active": b["need_active"], "active_days": b["active_days"],
                                "stats": {k: b["stats"][k] for k in ("bytes_out", "flows", "peers_ext")},
                                "known": known.get(m["dev"], {}), "open": open_by_dev.get(m["dev"], 0)})
            mutes = [dict(r) for r in c.execute("SELECT * FROM anomaly_mutes ORDER BY created DESC")]
        labels = self._dev_labels([a["dev"] for a in rows] + [d["dev"] for d in devices] + [m["dev"] for m in mutes])
        for x in rows + devices + mutes:
            x["device"] = labels.get(x["dev"])
        devices.sort(key=lambda d: (-d["open"], not d["learned"], ((d["device"] or {}).get("name") or "~").lower()))
        det = self.detector
        return {"items": rows, "devices": devices, "mutes": mutes, "learning_days": learning,
                "enabled": bool(self.cfg.get("anomaly_detection", True)), "data_now": now,
                "last_run": det.last_run if det else None, "error": det.last_error if det else None,
                "notify": bool((self.cfg.get("anomaly_notify_url") or "").strip()),
                "novelty_labels": anomaly.NOVELTY_LABELS, "metric_labels": anomaly.METRIC_LABELS}

    def anomaly_device(self, q):
        dev = q["dev"][0]
        learning = max(1, int(self.cfg.get("anomaly_learning_days", 7)))
        with self.db() as c:
            meta = c.execute("SELECT * FROM dev_meta WHERE dev=?", (dev,)).fetchone()
            if not meta:
                raise KeyError("Gerät %s" % dev)
            now = anomaly.data_now(c)
            b = anomaly.baseline(c, meta, now, learning)
            known = {}
            for kind in anomaly.NOVELTY:
                known[kind] = [dict(r) for r in c.execute(
                    "SELECT item, first_seen, last_seen, count FROM dev_seen WHERE dev=? AND kind=? "
                    "ORDER BY count DESC LIMIT 30", (dev, kind))]
                known[kind + "_total"] = c.execute("SELECT COUNT(*) n FROM dev_seen WHERE dev=? AND kind=?",
                                                   (dev, kind)).fetchone()["n"]
            recent = [dict(r) for r in c.execute(
                "SELECT hour, flows, bytes_out, bytes_in, peers_ext, peers_lan, dns FROM dev_hours "
                "WHERE dev=? AND hour >= ? ORDER BY hour", (dev, now - now % 3600 - 47 * 3600))]
            items = [self._anomaly_row(r) for r in c.execute(
                "SELECT * FROM anomalies WHERE dev=? ORDER BY ts DESC LIMIT 50", (dev,))]
            mutes = [dict(r) for r in c.execute("SELECT * FROM anomaly_mutes WHERE dev=?", (dev,))]
        b.pop("check", None)
        return {"dev": dev, "device": self._dev_labels([dev]).get(dev), "meta": dict(meta), "baseline": b,
                "known": known, "recent": recent, "items": items, "mutes": mutes, "learning_days": learning,
                "data_now": now, "novelty_labels": anomaly.NOVELTY_LABELS, "metric_labels": anomaly.METRIC_LABELS}

    def anomaly_ack(self, body):
        st = body.get("status", "ack")
        if st not in ("ack", "open"):
            raise ValueError("status muss 'ack' oder 'open' sein")
        ids = [int(i) for i in body.get("ids") or []]
        with self.db() as c:
            if body.get("all"):
                n = c.execute("UPDATE anomalies SET status=?, updated=? WHERE status='open'",
                              (st, int(time.time()))).rowcount
            else:
                n = 0
                for i in ids:
                    n += c.execute("UPDATE anomalies SET status=?, updated=? WHERE id=?",
                                   (st, int(time.time()), i)).rowcount
        return {"ok": True, "changed": n}

    def anomaly_mute(self, body):
        dev, kind, metric = str(body["dev"]), str(body["kind"]), str(body.get("metric") or "*")
        if kind not in ("new", "volume", "time"):
            raise ValueError("kind ungültig")
        with self.db() as c:
            if body.get("mute", True):
                c.execute("INSERT OR IGNORE INTO anomaly_mutes(dev, kind, metric, created) VALUES(?,?,?,?)",
                          (dev, kind, metric, int(time.time())))
                c.execute("UPDATE anomalies SET status='ack', updated=? WHERE dev=? AND kind=? AND status='open'"
                          + ("" if metric == "*" else " AND metric=?"),
                          (int(time.time()), dev, kind) + (() if metric == "*" else (metric,)))
            else:
                c.execute("DELETE FROM anomaly_mutes WHERE dev=? AND kind=? AND metric=?", (dev, kind, metric))
        return {"ok": True}

    def anomaly_check_now(self, body):
        if not self.detector:
            raise ValueError("Anomalieerkennung ist abgeschaltet (\"anomaly_detection\": false)")
        new = self.detector.check()
        return {"ok": True, "new": len(new)}

    # --- TLS-Fingerabdruecke -------------------------------------------------

    FP_ORDER = {"malicious": 0, "suspicious": 1, "unknown": 2, "known": 3}

    @staticmethod
    def _fp_notes(c):
        return {(r["type"], r["fp"]): r for r in c.execute("SELECT type, fp, label, harmless FROM fp_notes")}

    def _fp_assess(self, t, fp, notes):
        a = self.intel.assess_fp(t, fp)
        n = notes.get((t, fp))
        a["note"] = n["label"] if n else None
        a["harmless"] = bool(n and n["harmless"])
        return a

    def _fp_hits(self, c, since):
        """Anzahl auffaelliger/boesartiger, nicht als harmlos markierter Fingerabdruecke seit 'since'."""
        notes = self._fp_notes(c)
        n = 0
        for r in c.execute("SELECT DISTINCT type, fp FROM fp_clients WHERE last_seen >= ?", (since,)):
            a = self._fp_assess(r["type"], r["fp"], notes)
            if a["verdict"] in ("malicious", "suspicious") and not a["harmless"]:
                n += 1
        return n

    def fingerprints(self, q):
        hours, since, now = self.window(q)
        new_since = now - self.cfg["new_signature_hours"] * 3600
        with self.db() as c:
            notes = self._fp_notes(c)
            rows = c.execute(
                "SELECT type, fp, SUM(count) conns, MIN(first_seen) first_seen, MAX(last_seen) last_seen "
                "FROM fp_clients GROUP BY type, fp HAVING MAX(last_seen) >= ?", (since,)).fetchall()
            clients, servers = defaultdict(list), defaultdict(list)
            for r in c.execute("SELECT type, fp, ip, count, last_seen FROM fp_clients WHERE last_seen >= ? "
                               "ORDER BY count DESC", (since,)):
                clients[(r["type"], r["fp"])].append({"ip": r["ip"], "count": r["count"], "last_seen": r["last_seen"]})
            for r in c.execute("SELECT type, fp, server, count FROM fp_servers WHERE last_seen >= ? "
                               "ORDER BY count DESC", (since,)):
                servers[(r["type"], r["fp"])].append({"server": r["server"], "count": r["count"]})
            any_data = c.execute("SELECT EXISTS(SELECT 1 FROM fp_clients)").fetchone()[0]
        items, types = [], defaultdict(int)
        for r in rows:
            key = (r["type"], r["fp"])
            a = self._fp_assess(r["type"], r["fp"], notes)
            a.update(conns=r["conns"], first_seen=r["first_seen"], last_seen=r["last_seen"],
                     is_new=r["first_seen"] >= new_since,
                     clients=clients[key][:8], clients_total=len(clients[key]),
                     servers=servers[key][:8], servers_total=len(servers[key]))
            items.append(a)
            types[r["type"]] += 1
        items.sort(key=lambda a: (a["harmless"], self.FP_ORDER.get(a["verdict"], 9), not a["is_new"], -a["conns"]))
        return {"items": items, "types": dict(types), "any_data": bool(any_data),
                "feeds_loaded": self.intel.fp_feeds_loaded(), "hours": hours,
                "new_hours": self.cfg["new_signature_hours"]}

    def set_fp_note(self, body):
        t = str(body.get("type", ""))
        fp = str(body.get("fp", "")).strip().lower()
        if t not in FP_TYPES or not fp or len(fp) > 64:
            raise ValueError("type/fp ungültig")
        label = str(body.get("label") or "").strip()[:80] or None
        harmless = bool(body.get("harmless"))
        with self.db() as c:
            if not label and not harmless:
                c.execute("DELETE FROM fp_notes WHERE type=? AND fp=?", (t, fp))
            else:
                c.execute("INSERT INTO fp_notes(type, fp, label, harmless, updated) VALUES(?,?,?,?,?) "
                          "ON CONFLICT(type, fp) DO UPDATE SET label=excluded.label, "
                          "harmless=excluded.harmless, updated=excluded.updated",
                          (t, fp, label, 1 if harmless else 0, int(time.time())))
        return {"ok": True, "type": t, "fp": fp, "label": label, "harmless": harmless}

    def _fp_lookup(self, c, term):
        fp, types = fp_type_for(term)
        notes = self._fp_notes(c)
        out = []
        for t in types:
            a = self._fp_assess(t, fp, notes)
            seen = c.execute("SELECT COUNT(*) clients, SUM(count) conns, MIN(first_seen) first_seen, "
                             "MAX(last_seen) last_seen FROM fp_clients WHERE type=? AND fp=?", (t, fp)).fetchone()
            a.update(dict(seen))
            a["clients_list"] = [dict(r) for r in c.execute(
                "SELECT ip, count, last_seen FROM fp_clients WHERE type=? AND fp=? ORDER BY count DESC LIMIT 10", (t, fp))]
            a["servers_list"] = [dict(r) for r in c.execute(
                "SELECT server, count FROM fp_servers WHERE type=? AND fp=? ORDER BY count DESC LIMIT 10", (t, fp))]
            out.append(a)
        # bei MD5 (JA3 oder JA3S) nur die Variante zeigen, zu der es etwas gibt
        relevant = [a for a in out if a["clients"] or a["matches"]]
        return {"type": "fingerprint", "fp": fp, "items": relevant or out[:1]}

    def intel_status(self, q):
        s = self.intel.status()
        with self.db() as c:
            r = c.execute("SELECT COUNT(*) n, COUNT(DISTINCT ip) ips, MIN(first_seen) since "
                          "FROM ip_names").fetchone()
        s["ip_names"] = dict(r)
        return s

    def intel_lookup(self, q):
        term = q.get("q", [""])[0].strip()
        if not term:
            raise ValueError("bitte IP, Domain oder JA3/JA4-Hash angeben")
        with self.db() as c:
            if fp_type_for(term)[1]:
                return self._fp_lookup(c, term)
            if threatintel.looks_like_ip(term):
                names = self.names_for(c, [term])
                a = self._trim_names(self.intel.assess_ip(term, names.get(term)), 25)
                n = c.execute("SELECT COUNT(*) n, MAX(ts) last FROM alerts WHERE src_ip=? OR dest_ip=?",
                              (term, term)).fetchone()
                return {"type": "ip", "ip": a, "alerts": n["n"], "last_alert": n["last"]}
            d = norm_domain(term)
            if not d:
                raise ValueError("keine gültige IP oder Domain")
            info = self.intel.domain_info(d)
            rows = c.execute(
                "SELECT ip, MAX(last_seen) last_seen FROM ip_names WHERE name=? OR name LIKE ? "
                "GROUP BY ip ORDER BY last_seen DESC LIMIT 20", (d, "%." + d)).fetchall()
            ips = [r["ip"] for r in rows]
            reps = self.assess_ips(c, ips)
        return {"type": "domain", "domain": info,
                "ips": [compact_rep(reps[ip]) | {"ip": ip} for ip in ips if ip in reps]}

    def intel_set_feed(self, body):
        self.intel.set_enabled(str(body["id"]), bool(body.get("enabled")))
        self._rep_cache.clear()
        return self.intel_status({})

    def intel_update(self, body):
        self.intel.request_update(body.get("id") or None)
        self._rep_cache.clear()
        return {"ok": True}

    # --- Einstellungen -------------------------------------------------------

    SETTING_KEYS = ("eve_json", "fast_log", "alert_source")

    @staticmethod
    def check_file(path):
        info = {"path": path, "exists": False, "readable": False, "size": None, "error": None}
        if not path:
            info["error"] = "kein Pfad angegeben"
            return info
        if not os.path.isabs(path):
            info["error"] = "Pfad muss absolut sein (mit / beginnen)"
            return info
        if os.path.isdir(path):
            info["error"] = "das ist ein Ordner, keine Datei"
            return info
        if not os.path.exists(path):
            info["error"] = "Datei nicht gefunden"
            return info
        info["exists"] = True
        info["size"] = os.path.getsize(path)
        if os.access(path, os.R_OK):
            info["readable"] = True
        else:
            info["error"] = "keine Leserechte fuer den Dashboard-Prozess"
        return info

    def settings(self, q):
        cfg = self.ingestor.cfg
        return {
            "eve_json": cfg["eve_json"], "fast_log": cfg["fast_log"],
            "alert_source": cfg["alert_source"],
            "check": {"eve_json": self.check_file(cfg["eve_json"]),
                      "fast_log": self.check_file(cfg["fast_log"])},
            "config_path": self.cfg.get("_config_path"),
            "settings_path": userdata.settings_path(self.cfg),
        }

    def check_path(self, q):
        return self.check_file(q.get("path", [""])[0].strip())

    def find_logs(self, q):
        """Sucht eve.json / fast.log an ueblichen Orten (begrenzte Tiefe)."""
        roots = ["/var/log", "/var/lib/suricata", "/usr/local/var/log", "/opt",
                 "/home", "/root", "/mnt", "/media", "/srv", "/data", "/tmp"]
        wanted = {"eve.json": "eve_json", "fast.log": "fast_log"}
        found = {"eve_json": [], "fast_log": []}
        deadline = time.time() + 5
        for root in roots:
            base_depth = root.rstrip("/").count("/")
            for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
                if time.time() > deadline:
                    break
                if dirpath.count("/") - base_depth >= 4:
                    dirnames[:] = []
                dirnames[:] = [d for d in dirnames if not d.startswith(".")]
                for fn in filenames:
                    if fn in wanted:
                        found[wanted[fn]].append(self.check_file(os.path.join(dirpath, fn)))
        return found

    def save_settings(self, body):
        changes = {}
        for k in self.SETTING_KEYS:
            if k in body:
                v = str(body[k]).strip()
                if k == "alert_source":
                    if v not in ("fastlog", "eve"):
                        raise ValueError("alert_source muss 'fastlog' oder 'eve' sein")
                elif not os.path.isabs(v):
                    raise ValueError("%s: Pfad muss absolut sein" % k)
                changes[k] = v
        saved = self._write_config(changes)
        self.ingestor.reconfigure(changes)
        out = self.settings({})
        out["saved_to_file"] = saved
        return out

    def _write_config(self, changes):
        """Im Browser geaenderte Einstellungen nach data/settings.json schreiben. Die Datei liegt
        bei der Datenbank und uebersteht so den Austausch der Programmdateien (inkl. config.json)."""
        path = userdata.settings_path(self.cfg)
        try:
            raw = {}
            if os.path.exists(path):
                with open(path) as f:
                    raw = json.load(f)
            raw.update({k: v for k, v in changes.items() if k in userdata.SETTING_KEYS})
            userdata.write_json_private(path, raw)
            return True
        except (OSError, ValueError) as e:
            log.warning("%s konnte nicht geschrieben werden: %s", path, e)
            return False

    # ---- Export / Import der Nutzerdaten -------------------------------------

    def userdata_export(self, q):
        include_users = q.get("users", ["0"])[0] == "1"
        with self.db() as c:
            return userdata.envelope(userdata.collect(self.cfg, c, include_users), VERSION)

    def userdata_backups(self, q):
        return {"backups": userdata.list_backups(self.cfg), "dir": userdata.backup_dir(self.cfg),
                "restore_hint": self.backup.restore_hint if self.backup else None,
                "keep": userdata.KEEP_BACKUPS, "labels": userdata.SECTION_LABELS,
                "settings_path": userdata.settings_path(self.cfg)}

    def userdata_backup(self, q):
        try:
            return userdata.read_backup(self.cfg, q.get("name", [""])[0])
        except FileNotFoundError:
            raise KeyError("Sicherung nicht gefunden")

    def userdata_backup_now(self, body):
        name = self.backup.check() if self.backup else None
        return {"ok": True, "written": name, **self.userdata_backups({})}

    def userdata_import(self, body):
        doc = body.get("data")
        userdata.validate(doc)
        sections = [s for s in body.get("sections") or [] if s in userdata.SECTIONS and s in doc]
        if not sections:
            raise ValueError("keine Abschnitte ausgewählt")
        mode = body.get("mode", "merge")
        notes = []
        # vor dem Schreiben pruefen, ob HTTPS ueberhaupt moeglich waere (sonst aussperren)
        if "settings" in sections and isinstance(doc.get("settings"), dict) and doc["settings"].get("https") \
                and not self.cfg["https"]:
            try:
                tls.prepare(dict(self.cfg, https=True))
            except RuntimeError as e:
                doc = dict(doc, settings={k: v for k, v in doc["settings"].items() if k != "https"})
                notes.append("HTTPS nicht übernommen: %s" % e)
        conn = connect(self.cfg["db_path"])
        try:
            summary, settings = userdata.apply(conn, doc, sections, mode)
        finally:
            conn.close()
        restart = False
        if settings:
            changed = {k: v for k, v in settings.items() if self.cfg.get(k) != v}
            self._write_config(settings)
            log_changes = {k: v for k, v in changed.items() if k in ("eve_json", "fast_log", "alert_source")}
            if log_changes:
                self.ingestor.reconfigure(log_changes)
            if any(k in changed for k in userdata.HTTPS_KEYS):
                self.cfg.update(changed)
                restart = True
                restart_soon(2.0)
        if "feeds" in sections and isinstance(doc.get("feeds"), dict):
            for fid, on in doc["feeds"].items():
                f = self.intel.feeds.get(fid)
                if f and f["enabled"] != bool(on):
                    self.intel.set_enabled(fid, bool(on))
        if "users" in sections and self.auth:
            self.auth._forget_cache()
        self._dev_cache = (0, None)
        self._rep_cache.clear()
        log.info("Nutzerdaten importiert (%s): %s", mode, summary)
        if self.backup:
            self.backup.poke()
            self.backup.restore_hint = None
        return {"ok": True, "summary": summary, "notes": notes, "restarting": restart,
                "scheme": "https" if self.cfg["https"] else "http",
                "port": self.cfg["https_port"] if self.cfg["https"] else self.cfg["listen_port"]}

    # ---- HTTPS ---------------------------------------------------------------

    def https_status(self, q):
        cfg, rt = self.cfg, self.runtime
        out = {
            "configured": bool(cfg["https"]), "active": rt.get("https_active", False),
            "error": rt.get("https_error"), "https_port": cfg["https_port"],
            "http_port": cfg["listen_port"], "http_redirect": bool(cfg["http_redirect"]),
            "cert_path": cfg["https_cert"], "key_path": cfg["https_key"],
            "cert": None, "auth": bool(cfg.get("auth", True)),
        }
        if os.path.exists(cfg["https_cert"]):
            out["cert"] = tls.cert_info(cfg["https_cert"])
        return out

    def save_https(self, body):
        changes = {}
        if "enabled" in body:
            changes["https"] = bool(body["enabled"])
        if "https_port" in body:
            port = int(body["https_port"])
            if not 1 <= port <= 65535:
                raise ValueError("Port muss zwischen 1 und 65535 liegen")
            if port == self.cfg["listen_port"]:
                raise ValueError("HTTPS-Port muss sich vom HTTP-Port %d unterscheiden" % port)
            changes["https_port"] = port
        if "http_redirect" in body:
            changes["http_redirect"] = bool(body["http_redirect"])
        if body.get("regenerate"):
            # neues selbstsigniertes Zertifikat erzwingen (z. B. nach IP-Wechsel)
            for p in (self.cfg["https_cert"], self.cfg["https_key"]):
                with contextlib.suppress(FileNotFoundError):
                    os.remove(p)
        new = dict(self.cfg, **changes)
        if new["https"]:
            try:  # vorab pruefen, damit man sich nicht aussperrt
                tls.prepare(new)
            except RuntimeError as e:
                raise ValueError("HTTPS nicht moeglich: %s" % e)
        if not self._write_config(changes):
            raise ValueError("%s konnte nicht geschrieben werden, HTTPS bleibt unveraendert"
                             % userdata.settings_path(self.cfg))
        self.cfg.update(changes)
        restart_soon()
        port = new["https_port"] if new["https"] else new["listen_port"]
        return {"ok": True, "restarting": True, "scheme": "https" if new["https"] else "http", "port": port}

    def delete_flag(self, q):
        gid = int(q.get("gid", ["1"])[0])
        sid = int(q["sid"][0])
        with self.db() as c:
            c.execute("DELETE FROM flags WHERE gid=? AND sid=?", (gid, sid))
        return {"ok": True}


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

# Ohne Anmeldung erreichbar (Login-Seite und ihr Stylesheet)
PUBLIC_STATIC = {"/login", "/login.html", "/style.css"}
# GET-Routen, die nur Admins sehen duerfen (Dateisystem, Benutzer, Server-Konfiguration)
ADMIN_GET = {"/api/settings", "/api/settings/check", "/api/settings/find", "/api/users", "/api/https",
             "/api/userdata/export", "/api/userdata/backups", "/api/userdata/backup"}
FORBIDDEN_MSG = "Nur Administratoren dürfen das. Dein Konto hat die Rolle „Nur lesen“."


_DB_PATH = [None]


def checkpoint_db(db_path):
    """WAL in die Hauptdatei uebernehmen. Danach enthaelt suricata.db allein alle Daten -
    wichtig, falls jemand nur diese Datei sichert."""
    if not db_path:
        return
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()
    except sqlite3.Error as e:
        log.warning("WAL-Checkpoint fehlgeschlagen: %s", e)


def restart_soon(delay=1.0):
    """Prozess neu starten (z. B. nach HTTPS-Umstellung). systemd sieht dieselbe PID."""
    def go():
        log.info("Starte neu, um die neuen Server-Einstellungen zu uebernehmen ...")
        checkpoint_db(_DB_PATH[0])
        logging.shutdown()
        os.execv(sys.executable, [sys.executable] + sys.argv)
    threading.Timer(delay, go).start()


def make_handler(api, auth, is_tls=False):
    get_routes = {
        "/api/summary": api.summary,
        "/api/traffic": api.traffic,
        "/api/event_types": api.event_types,
        "/api/protocols": api.protocols,
        "/api/top": api.top,
        "/api/alerts": api.alerts,
        "/api/alerts/timeline": api.alert_timeline,
        "/api/signatures": api.signatures,
        "/api/flags": api.flags,
        "/api/status": api.status,
        "/api/settings": api.settings,
        "/api/alert_context": api.alert_context,
        "/api/settings/check": api.check_path,
        "/api/settings/find": api.find_logs,
        "/api/intel/status": api.intel_status,
        "/api/intel/lookup": api.intel_lookup,
        "/api/live": api.live,
        "/api/devices": api.devices,
        "/api/devices/names": api.device_names,
        "/api/https": api.https_status,
        "/api/fingerprints": api.fingerprints,
        "/api/userdata/backups": api.userdata_backups,
        "/api/userdata/backup": api.userdata_backup,
        "/api/anomalies": api.anomalies,
        "/api/anomalies/device": api.anomaly_device,
    }
    post_routes = {
        "/api/flags": api.set_flag,
        "/api/settings": api.save_settings,
        "/api/intel/feeds": api.intel_set_feed,
        "/api/intel/update": api.intel_update,
        "/api/devices": api.set_device,
        "/api/https": api.save_https,
        "/api/fingerprints/note": api.set_fp_note,
        "/api/userdata/import": api.userdata_import,
        "/api/userdata/backup_now": api.userdata_backup_now,
        "/api/anomalies/ack": api.anomaly_ack,
        "/api/anomalies/mute": api.anomaly_mute,
        "/api/anomalies/check": api.anomaly_check_now,
    }
    open_admin = {"username": "", "role": "admin", "must_change": False}

    class Handler(BaseHTTPRequestHandler):
        server_version = "SuricataDashboard/1.0"
        user = None

        def log_message(self, fmt, *args):
            log.debug("%s - %s", self.address_string(), fmt % args)

        def end_headers(self):
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "same-origin")
            super().end_headers()

        def send_json(self, obj, code=200, headers=()):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def redirect(self, location):
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        # ---- Anmeldung --------------------------------------------------------

        def token(self):
            try:
                c = SimpleCookie(self.headers.get("Cookie", ""))
            except CookieError:
                return None
            m = c.get(authmod.COOKIE_NAME)
            return m.value if m else None

        def cookie(self, token, max_age=None):
            parts = ["%s=%s" % (authmod.COOKIE_NAME, token), "Path=/", "HttpOnly", "SameSite=Strict"]
            if is_tls:
                parts.append("Secure")
            if max_age is not None:
                parts.append("Max-Age=%d" % max_age)
            return ("Set-Cookie", "; ".join(parts))

        def authenticate(self):
            if not auth.enabled:
                self.user = open_admin
            else:
                self.user = auth.session(self.token())
            return self.user

        def same_origin(self):
            """Schutz gegen CSRF zusaetzlich zu SameSite=Strict: Origin muss zum Host passen."""
            origin = self.headers.get("Origin")
            if not origin:
                return True
            return urlparse(origin).netloc.lower() == (self.headers.get("Host") or "").lower()

        def guard(self, path, write):
            """True, wenn die Anfrage weiterlaufen darf; sonst ist die Antwort schon gesendet."""
            if write and not self.same_origin():
                self.send_json({"error": "Anfrage von fremder Seite abgelehnt"}, 403)
                return False
            if not self.authenticate():
                self.send_json({"error": "Bitte anmelden", "login": True}, 401)
                return False
            if self.user["must_change"] and path not in ("/api/me", "/api/me/password", "/api/logout"):
                self.send_json({"error": "Bitte zuerst das Passwort ändern", "must_change": True}, 403)
                return False
            if (write or path in ADMIN_GET) and self.user["role"] != "admin" \
                    and path not in ("/api/me/password", "/api/logout"):
                self.send_json({"error": FORBIDDEN_MSG}, 403)
                return False
            return True

        def client_ip(self):
            return self.client_address[0]

        def read_body(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            if n > 8 * 1024 * 1024:
                raise ValueError("Anfrage zu gross")
            body = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("JSON-Objekt erwartet")
            return body

        def do_login(self):
            if not self.same_origin():
                return self.send_json({"error": "Anfrage von fremder Seite abgelehnt"}, 403)
            if not auth.enabled:
                return self.send_json({"ok": True, "user": open_admin})
            try:
                body = self.read_body()
                remember = bool(body.get("remember"))
                token, user = auth.login(str(body.get("username", "")), str(body.get("password", "")),
                                         self.client_ip(), self.headers.get("User-Agent"), remember)
            except AuthError as e:
                hdr = [("Retry-After", str(e.retry_after))] if e.retry_after else []
                return self.send_json({"error": str(e), "retry_after": e.retry_after}, e.code, hdr)
            except (ValueError, TypeError) as e:
                return self.send_json({"error": "ungueltige Anfrage: %s" % e}, 400)
            max_age = authmod.REMEMBER_TIMEOUT if remember else None
            return self.send_json({"ok": True, "user": user}, headers=[self.cookie(token, max_age)])

        def me(self):
            return dict(self.user, auth_enabled=auth.enabled, https=is_tls,
                        roles=authmod.ROLE_LABELS, min_password=authmod.MIN_PASSWORD)

        # ---- Methoden ------------------------------------------------------------

        def do_GET(self):
            u = urlparse(self.path)
            path = u.path.rstrip("/") or "/"
            if path in PUBLIC_STATIC:
                if path in ("/login", "/login.html"):
                    if self.authenticate():
                        return self.redirect("/")
                    return self.serve_static("/login.html")
                return self.serve_static(path)
            if not path.startswith("/api/"):
                if not self.authenticate():
                    return self.redirect("/login")
                return self.serve_static(u.path)
            if not self.guard(path, write=False):
                return
            if path == "/api/me":
                return self.send_json(self.me())
            if path == "/api/users":
                return self.send_json(auth.list_users())
            if path == "/api/userdata/export":
                doc = api.userdata_export(parse_qs(u.query))
                fname = "suricata-dashboard-%s.json" % time.strftime("%Y-%m-%d")
                return self.send_json(doc, headers=[("Content-Disposition", 'attachment; filename="%s"' % fname)])
            fn = get_routes.get(path)
            if not fn:
                return self.send_json({"error": "not found"}, 404)
            try:
                return self.send_json(fn(parse_qs(u.query)))
            except KeyError as e:
                return self.send_json({"error": "fehlt/unbekannt: %s" % e.args[0]}, 404)
            except ValueError as e:
                return self.send_json({"error": "ungueltiger Wert: %s" % e}, 400)
            except Exception as e:
                log.exception("API-Fehler %s", u.path)
                return self.send_json({"error": str(e)}, 500)

        def do_POST(self):
            try:
                return self._post()
            finally:
                if api.backup and getattr(self, "_status", 500) < 400:
                    api.backup.poke()

        def send_response(self, code, message=None):
            self._status = code
            super().send_response(code, message)

        def _post(self):
            path = urlparse(self.path).path.rstrip("/")
            if path == "/api/login":
                return self.do_login()
            if not self.guard(path, write=True):
                return
            try:
                if path == "/api/logout":
                    auth.logout(self.token())
                    return self.send_json({"ok": True}, headers=[self.cookie("", 0)])
                body = self.read_body()
                if path == "/api/me/password":
                    if not auth.enabled:
                        raise AuthError("Die Anmeldung ist abgeschaltet (\"auth\": false).", 409)
                    return self.send_json(auth.change_own_password(
                        self.user, body.get("old"), body.get("new"), self.token()))
                if path == "/api/users":
                    if not auth.enabled:
                        raise AuthError("Die Anmeldung ist abgeschaltet (\"auth\": false).", 409)
                    return self.send_json(auth.manage(self.user, body))
                fn = post_routes.get(path)
                if not fn:
                    return self.send_json({"error": "not found"}, 404)
                return self.send_json(fn(body))
            except AuthError as e:
                return self.send_json({"error": str(e)}, e.code)
            except (KeyError, ValueError, TypeError) as e:
                return self.send_json({"error": "ungueltige Anfrage: %s" % e}, 400)

        def do_DELETE(self):
            u = urlparse(self.path)
            path = u.path.rstrip("/")
            if not self.guard(path, write=True):
                return
            if path != "/api/flags":
                return self.send_json({"error": "not found"}, 404)
            try:
                out = self.send_json(api.delete_flag(parse_qs(u.query)))
                if api.backup:
                    api.backup.poke()
                return out
            except (KeyError, ValueError) as e:
                return self.send_json({"error": "ungueltige Anfrage: %s" % e}, 400)

        def serve_static(self, path):
            rel = path.lstrip("/") or "index.html"
            full = os.path.realpath(os.path.join(FRONTEND_DIR, rel))
            if not full.startswith(os.path.realpath(FRONTEND_DIR) + os.sep) or not os.path.isfile(full):
                full = os.path.join(FRONTEND_DIR, "index.html")
            ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            with open(full, "rb") as f:
                data = f.read()
            if full.endswith(".html"):
                # Versionsnummer an app.js/style.css haengen -> Browser laedt neue Dateien sicher nach
                data = data.replace(b"__VERSION__", VERSION.encode())
            self.send_response(200)
            self.send_header("X-Dashboard-Version", VERSION)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control",
                             "max-age=86400" if "/vendor/" in full else "no-cache")
            self.end_headers()
            self.wfile.write(data)

    return Handler


def load_config(path):
    cfg = dict(DEFAULT_CONFIG)
    if path and os.path.exists(path):
        with open(path) as f:
            user = json.load(f)
        cfg.update({k: v for k, v in user.items() if not k.startswith("_")})
    for k in ("db_path", "https_cert", "https_key"):
        if not os.path.isabs(cfg[k]):
            cfg[k] = os.path.join(ROOT_DIR, cfg[k])
    # Im Browser gespeicherte Einstellungen (data/settings.json) haben Vorrang vor config.json
    sp = userdata.settings_path(cfg)
    if os.path.exists(sp):
        try:
            with open(sp) as f:
                saved = json.load(f)
            cfg.update({k: v for k, v in saved.items() if k in userdata.SETTING_KEYS})
        except (OSError, ValueError) as e:
            log.warning("%s nicht lesbar, nutze config.json: %s", sp, e)
    if cfg["alert_source"] not in ("fastlog", "eve"):
        raise SystemExit("alert_source muss 'fastlog' oder 'eve' sein")
    cfg["_config_path"] = os.path.abspath(path) if path else None
    return cfg


def migrate_settings(cfg):
    """Bis 1.7 landeten im Browser geaenderte Pfade in config.json. Beim ersten Start einmalig
    nach data/settings.json uebernehmen, damit sie den naechsten Programm-Austausch ueberstehen."""
    sp = userdata.settings_path(cfg)
    if os.path.exists(sp):
        return
    custom = {k: cfg[k] for k in userdata.SETTING_KEYS if cfg.get(k) != DEFAULT_CONFIG.get(k)}
    if not custom:
        return
    try:
        userdata.write_json_private(sp, custom)
        log.info("Einstellungen aus config.json nach %s übernommen: %s", sp, ", ".join(custom))
    except OSError as e:
        log.warning("Konnte %s nicht anlegen: %s", sp, e)


def main():
    ap = argparse.ArgumentParser(description="Suricata Dashboard")
    ap.add_argument("--config", default=os.path.join(ROOT_DIR, "config.json"))
    ap.add_argument("--port", type=int)
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    if args.port:
        cfg["listen_port"] = args.port

    os.makedirs(os.path.dirname(cfg["db_path"]), exist_ok=True)
    conn = connect(cfg["db_path"])
    conn.executescript(SCHEMA)
    conn.executescript(anomaly.SCHEMA)
    conn.close()
    migrate_settings(cfg)

    auth = Auth(cfg, connect)
    auth.init_db()
    if not auth.enabled:
        log.warning("Anmeldung abgeschaltet (\"auth\": false) - jeder im Netz hat vollen Zugriff!")

    ingestor = Ingestor(cfg)
    ingestor.start()
    intel = ThreatIntel(cfg, connect)
    intel.start()
    if ingestor.profiler:
        ingestor.profiler.intel = intel

    mimetypes.add_type("application/javascript", ".js")
    api = Api(cfg, ingestor, intel)
    api.auth = auth
    api.backup = userdata.AutoBackup(cfg, connect, VERSION)
    api.backup.start()
    if cfg.get("anomaly_detection", True):
        api.detector = anomaly.Detector(cfg, connect)
        api.detector.start()
    _DB_PATH[0] = cfg["db_path"]
    host = cfg["listen_host"]

    ctx = None
    if cfg["https"]:
        try:
            ctx = tls.prepare(cfg)
        except RuntimeError as e:
            # lieber unverschluesselt weiterlaufen als sich auszusperren
            log.error("HTTPS nicht moeglich, nutze HTTP: %s", e)
            api.runtime["https_error"] = str(e)
    api.runtime["https_active"] = ctx is not None

    servers = []
    if ctx:
        servers.append(tls.TLSServer((host, cfg["https_port"]), make_handler(api, auth, True), ctx))
        log.info("Dashboard laeuft auf https://%s:%d", host, cfg["https_port"])
        if cfg["http_redirect"] and cfg["listen_port"]:
            servers.append(tls.QuietServer((host, cfg["listen_port"]), tls.redirect_handler(cfg["https_port"])))
            log.info("http://%s:%d leitet auf HTTPS um", host, cfg["listen_port"])
    else:
        servers.append(tls.QuietServer((host, cfg["listen_port"]), make_handler(api, auth, False)))
        log.info("Dashboard laeuft auf http://%s:%d", host, cfg["listen_port"])
    log.info("Suricata Dashboard %s aus %s (eve: %s, alerts aus: %s)",
             VERSION, ROOT_DIR, cfg["eve_json"], cfg["alert_source"])
    for s in servers[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()

    def stop(signum, frame):
        # serve_forever laeuft im Hauptthread -> shutdown() aus einem anderen Thread aufrufen
        log.info("Beende (Signal %d) ...", signum)
        threading.Thread(target=servers[0].shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    try:
        servers[0].serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            api.backup.check()
        except Exception as e:
            log.warning("Abschluss-Sicherung fehlgeschlagen: %s", e)
        checkpoint_db(cfg["db_path"])
        log.info("Datenbank geschlossen.")


if __name__ == "__main__":
    main()
