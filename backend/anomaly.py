"""
Suricata Dashboard - Verhaltensprofile lokaler Geraete und Anomalieerkennung

Nur Python-Standardbibliothek. Absichtlich einfach und nachvollziehbar statt "KI":
jede Warnung laesst sich mit konkreten Zahlen begruenden.

1. Profil (beim Einlesen, Klasse Profiler)
   Pro Geraet und Stunde: Verbindungen, gesendete/empfangene Bytes, eingehende Verbindungen,
   verschiedene externe Gegenstellen, kontaktierte lokale Geraete, verschiedene Ziel-Ports,
   DNS-Anfragen (Tabelle dev_hours). Dazu, was ein Geraet "kennt" (Tabelle dev_seen):
     port      Ziel-Port ins Internet (z. B. TCP/443)
     lan_port  genutzter Dienst im lokalen Netz (z. B. TCP/445)
     in_port   von aussen erreichbarer Dienst (Geraet antwortet auf Verbindungen aus dem Internet)
     app       Anwendungsprotokoll (tls, dns, ssh ...)
     country   Zielland (ueber die IP->ASN-Tabelle der Threat-Feeds)
     domain    Domain aus DNS-Anfragen und TLS-SNI (auf die registrierte Domain gekuerzt)

   Geraet = MAC-Adresse, wenn bekannt und nicht von mehreren IPs geteilt (Router), sonst IPv4.
   IPv6-Adressen ohne MAC werden ignoriert (Privacy-Adressen wechseln taeglich).

2. Erkennung (Hintergrund-Thread Detector, alle 5 Minuten)
   Erst nach einer Lernphase (anomaly_learning_days, mind. 3 aktive Tage):
     volume  Stundenwert liegt ueber max(Mindestwert, 3 x 99%-Wert, 1,2 x bisheriges Maximum)
             der letzten 14 Tage (z. B. Datenabfluss, Scan vieler Geraete/Ports)
     new     etwas Neues (Port, Land, Domain ...), aber nur, wenn das Geraet in dieser Kategorie
             sonst selten Neues zeigt (z. B. Smart-Plug ja, Laptop nein)
     time    deutliche Aktivitaet zu einer Uhrzeit, zu der das Geraet sonst nie aktiv ist
"""

import json
import logging
import re
import threading
import time
import urllib.request
from collections import defaultdict

from live import addr_kind

log = logging.getLogger("suricata-dashboard")

SCHEMA = """
CREATE TABLE IF NOT EXISTS dev_hours (
    dev       TEXT NOT NULL,
    hour      INTEGER NOT NULL,
    flows     INTEGER DEFAULT 0,
    bytes_out INTEGER DEFAULT 0,
    bytes_in  INTEGER DEFAULT 0,
    flows_in  INTEGER DEFAULT 0,
    peers_ext INTEGER DEFAULT 0,
    peers_lan INTEGER DEFAULT 0,
    ports     INTEGER DEFAULT 0,
    dns       INTEGER DEFAULT 0,
    PRIMARY KEY (dev, hour)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_dev_hours_hour ON dev_hours(hour);
CREATE TABLE IF NOT EXISTS dev_seen (
    dev        TEXT NOT NULL,
    kind       TEXT NOT NULL,
    item       TEXT NOT NULL,
    first_seen INTEGER,
    last_seen  INTEGER,
    count      INTEGER DEFAULT 0,
    PRIMARY KEY (dev, kind, item)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_dev_seen_first ON dev_seen(first_seen);
CREATE TABLE IF NOT EXISTS dev_meta (
    dev        TEXT PRIMARY KEY,
    first_seen INTEGER,
    last_seen  INTEGER,
    last_ip    TEXT
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS anomalies (
    id       INTEGER PRIMARY KEY,
    ts       INTEGER NOT NULL,
    dev      TEXT NOT NULL,
    ip       TEXT,
    kind     TEXT NOT NULL,
    metric   TEXT NOT NULL,
    item     TEXT NOT NULL DEFAULT '',
    bucket   INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL,
    score    REAL DEFAULT 0,
    title    TEXT,
    detail   TEXT,
    status   TEXT NOT NULL DEFAULT 'open',
    updated  INTEGER,
    UNIQUE (dev, kind, metric, item, bucket)
);
CREATE INDEX IF NOT EXISTS idx_anomalies_ts ON anomalies(ts);
CREATE TABLE IF NOT EXISTS anomaly_mutes (
    dev     TEXT NOT NULL,
    kind    TEXT NOT NULL,
    metric  TEXT NOT NULL,
    created INTEGER,
    PRIMARY KEY (dev, kind, metric)
) WITHOUT ROWID;
"""

MB = 1024 * 1024
BASELINE_DAYS = 14
MIN_ACTIVE_DAYS = 3
ACTIVE_HOUR_FLOWS = 10   # ab so vielen Verbindungen gilt eine Stunde als "aktiv"
SET_CAP = 20000

# kind -> (Titel, erlaubte neue Eintraege pro Tag in der Vergangenheit, Schwere)
NOVELTY = {
    "in_port": ("Neuer von außen erreichbarer Dienst", 0.2, "high"),
    "lan_port": ("Neuer Dienst im lokalen Netz genutzt", 0.3, "medium"),
    "port": ("Neuer Ziel-Port im Internet", 0.3, "medium"),
    "country": ("Neues Zielland", 0.3, "medium"),
    "app": ("Neues Protokoll", 0.2, "low"),
    "domain": ("Neue Domain", 1.0, "low"),
}
NOVELTY_LABELS = {"in_port": "Von außen erreichbar", "lan_port": "Dienste im LAN", "port": "Ziel-Ports",
                  "country": "Zielländer", "app": "Protokolle", "domain": "Domains"}

# metric -> (Titel, Mindestwert pro Stunde, Einheit)
METRICS = {
    "bytes_out": ("Ungewöhnlich viele Daten gesendet", 50 * MB, "bytes"),
    "flows": ("Ungewöhnlich viele Verbindungen", 300, "n"),
    "peers_ext": ("Ungewöhnlich viele externe Gegenstellen", 50, "n"),
    "peers_lan": ("Viele lokale Geräte kontaktiert – möglicher Netzwerk-Scan", 10, "n"),
    "ports": ("Viele verschiedene Ports – möglicher Port-Scan", 30, "n"),
    "dns": ("Ungewöhnlich viele DNS-Anfragen", 500, "n"),
}
METRIC_LABELS = {"bytes_out": "Gesendet", "bytes_in": "Empfangen", "flows": "Verbindungen",
                 "flows_in": "Eingehend", "peers_ext": "Externe Gegenstellen", "peers_lan": "Lokale Geräte",
                 "ports": "Ziel-Ports", "dns": "DNS-Anfragen"}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".arpa", ".internal", ".localdomain", ".box", ".intranet",
                  ".home.arpa", ".localhost")
SLD2 = {"co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go", "gv"}
IPV4_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def is_mac(k):
    return bool(MAC_RE.match(k or ""))


def base_domain(name):
    """Registrierte Domain (vereinfacht): api.eu.example.com -> example.com, x.bbc.co.uk -> bbc.co.uk"""
    n = (name or "").strip().rstrip(".").lower()
    if not n or "." not in n or n.endswith(LOCAL_SUFFIXES) or IPV4_RE.match(n) or ":" in n:
        return None
    parts = n.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SLD2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def percentile(sorted_vals, p):
    if not sorted_vals:
        return 0
    i = min(len(sorted_vals) - 1, max(0, int(round(p * (len(sorted_vals) - 1)))))
    return sorted_vals[i]


# --------------------------------------------------------------------------
# Profil beim Einlesen
# --------------------------------------------------------------------------

class Profiler:
    """Wird vom Ingestor-Thread benutzt (nicht threadsicher, braucht es auch nicht)."""

    REFRESH = 300
    SHARED_MAC_IPS = 4

    def __init__(self, intel):
        self.intel = intel
        self.ip_mac = {}
        self.shared = set()
        self.loaded_at = 0
        self.geo = {}
        self.sets = {}   # (dev, hour) -> {"ext": set, "lan": set, "ports": set}
        self._reset()

    def _reset(self):
        self.hours = defaultdict(lambda: [0, 0, 0, 0, 0])  # flows, bytes_out, bytes_in, flows_in, dns
        self.seen = {}
        self.meta = {}

    def refresh(self, conn):
        """IP->MAC aus der hosts-Tabelle und geteilte MACs (Router) laden."""
        day = time.time() - 86400
        ip_mac, v4 = {}, defaultdict(int)
        for r in conn.execute("SELECT ip, mac, last_seen FROM hosts WHERE mac IS NOT NULL"):
            ip_mac[r["ip"]] = r["mac"]
            if ":" not in r["ip"] and (r["last_seen"] or 0) > day:
                v4[r["mac"]] += 1
        self.ip_mac = ip_mac
        self.shared = {m for m, n in v4.items() if n >= self.SHARED_MAC_IPS}
        self.loaded_at = time.time()

    def dev(self, ip, mac=None):
        if mac and mac not in self.shared:
            self.ip_mac[ip] = mac
            return mac
        m = self.ip_mac.get(ip)
        if m and m not in self.shared:
            return m
        return ip if ip and ":" not in ip else None

    def _meta(self, dev, ts, ip):
        m = self.meta.get(dev)
        if m is None:
            self.meta[dev] = [ts, ts, ip]
        else:
            m[0] = min(m[0], ts)
            if ts >= m[1]:
                m[1], m[2] = ts, ip

    def _seen(self, dev, kind, item, ts):
        if not item:
            return
        k = (dev, kind, str(item)[:120])
        v = self.seen.get(k)
        if v is None:
            self.seen[k] = [ts, ts, 1]
        else:
            v[0] = min(v[0], ts)
            v[1] = max(v[1], ts)
            v[2] += 1

    def _add(self, dev, hour, name, value):
        s = self.sets.get((dev, hour))
        if s is None:
            s = self.sets[(dev, hour)] = {"ext": set(), "lan": set(), "ports": set()}
        if len(s[name]) < SET_CAP:
            s[name].add(value)

    def country(self, ip):
        c = self.geo.get(ip)
        if c is None:
            info = self.intel.asn_info(ip) if self.intel else None
            c = (info or {}).get("country") or ""
            if len(self.geo) > 50000:
                self.geo.clear()
            self.geo[ip] = c
        return c or None

    def flow(self, ev, ts, smac, dmac):
        src, dst = ev.get("src_ip"), ev.get("dest_ip")
        ks, kd = addr_kind(src), addr_kind(dst)
        f = ev.get("flow") or {}
        proto = ev.get("proto") or "?"
        port = ev.get("dest_port")
        portkey = "%s/%s" % (proto, port) if port is not None else proto
        b_out, b_in = int(f.get("bytes_toserver", 0) or 0), int(f.get("bytes_toclient", 0) or 0)
        p_back = int(f.get("pkts_toclient", 0) or 0)
        # "beantwortet": mehr als ein Handshake-/RST-Paket zurueck (TCP) bzw. irgendeine Antwort (UDP)
        answered = p_back >= (2 if proto == "TCP" else 1)
        hour = ts - ts % 3600
        if ks == "device":
            d = self.dev(src, smac)
            if not d:
                return
            self._meta(d, ts, src)
            h = self.hours[(d, hour)]
            h[0] += 1
            h[1] += b_out
            h[2] += b_in
            if kd == "remote":
                self._add(d, hour, "ext", dst)
                self._add(d, hour, "ports", portkey)
                if answered:
                    self._seen(d, "port", portkey, ts)
                    app = ev.get("app_proto")
                    if app and app != "failed":
                        self._seen(d, "app", app, ts)
                    self._seen(d, "country", self.country(dst), ts)
            elif kd == "device":
                self._add(d, hour, "lan", dst)
                self._add(d, hour, "ports", portkey)
                if answered:
                    self._seen(d, "lan_port", portkey, ts)
        elif ks == "remote" and kd == "device":
            d = self.dev(dst, dmac)
            if not d:
                return
            self._meta(d, ts, dst)
            h = self.hours[(d, hour)]
            h[3] += 1
            h[1] += b_in    # Antwort des Geraets = gesendete Daten
            h[2] += b_out
            if answered:
                self._seen(d, "in_port", portkey, ts)

    def dns(self, ev, ts, name, smac):
        src = ev.get("src_ip")
        if addr_kind(src) != "device":
            return
        d = self.dev(src, smac)
        if not d:
            return
        self._meta(d, ts, src)
        self.hours[(d, ts - ts % 3600)][4] += 1
        self._seen(d, "domain", base_domain(name), ts)

    def tls(self, ev, ts, sni, smac):
        src = ev.get("src_ip")
        if not sni or addr_kind(src) != "device":
            return
        d = self.dev(src, smac)
        if d:
            self._seen(d, "domain", base_domain(sni), ts)

    def flush(self, conn):
        """Im Transaktionskontext des Ingestors aufrufen."""
        if time.time() - self.loaded_at > self.REFRESH:
            self.refresh(conn)
        if self.hours:
            rows = []
            for (d, h), v in self.hours.items():
                s = self.sets.get((d, h)) or {"ext": (), "lan": (), "ports": ()}
                rows.append((d, h, v[0], v[1], v[2], v[3], len(s["ext"]), len(s["lan"]), len(s["ports"]), v[4]))
            conn.executemany(
                "INSERT INTO dev_hours(dev, hour, flows, bytes_out, bytes_in, flows_in, peers_ext, peers_lan, "
                "ports, dns) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(dev, hour) DO UPDATE SET "
                "flows=flows+excluded.flows, bytes_out=bytes_out+excluded.bytes_out, "
                "bytes_in=bytes_in+excluded.bytes_in, flows_in=flows_in+excluded.flows_in, "
                "peers_ext=MAX(peers_ext, excluded.peers_ext), peers_lan=MAX(peers_lan, excluded.peers_lan), "
                "ports=MAX(ports, excluded.ports), dns=dns+excluded.dns", rows)
        if self.seen:
            conn.executemany(
                "INSERT INTO dev_seen(dev, kind, item, first_seen, last_seen, count) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(dev, kind, item) DO UPDATE SET first_seen=MIN(first_seen, excluded.first_seen), "
                "last_seen=MAX(last_seen, excluded.last_seen), count=count+excluded.count",
                [(k[0], k[1], k[2], v[0], v[1], v[2]) for k, v in self.seen.items()])
        if self.meta:
            conn.executemany(
                "INSERT INTO dev_meta(dev, first_seen, last_seen, last_ip) VALUES(?,?,?,?) "
                "ON CONFLICT(dev) DO UPDATE SET first_seen=MIN(first_seen, excluded.first_seen), "
                "last_ip=CASE WHEN excluded.last_seen >= last_seen THEN excluded.last_ip ELSE last_ip END, "
                "last_seen=MAX(last_seen, excluded.last_seen)",
                [(d, v[0], v[1], v[2]) for d, v in self.meta.items()])
        # Mengen fuer verschiedene Gegenstellen nur fuer die letzten Stunden behalten
        cutoff = time.time() - 3 * 3600
        newest = max((h for _, h in self.sets), default=0)
        cutoff = min(cutoff, newest - 2 * 3600)
        for k in [k for k in self.sets if k[1] < cutoff]:
            del self.sets[k]
        self._reset()


def cleanup(conn, retention_days):
    now = int(time.time())
    conn.execute("DELETE FROM dev_hours WHERE hour < ?", (now - max(retention_days, BASELINE_DAYS + 1) * 86400,))
    conn.execute("DELETE FROM dev_seen WHERE last_seen < ?", (now - max(retention_days, 90) * 86400,))
    conn.execute("DELETE FROM dev_meta WHERE last_seen < ?", (now - max(retention_days, 90) * 86400,))
    conn.execute("DELETE FROM anomalies WHERE ts < ?", (now - max(retention_days, 90) * 86400,))


# --------------------------------------------------------------------------
# Auswertung
# --------------------------------------------------------------------------

def data_now(conn):
    """'Jetzt' aus Sicht der Daten (letztes Event), nie in der Zukunft."""
    row = conn.execute("SELECT MAX(last_seen) t FROM dev_meta").fetchone()
    t = row["t"] if row and row["t"] else time.time()
    return int(min(time.time(), t))


def baseline(conn, meta, now, learning_days):
    """Statistik eines Geraets aus dev_hours. meta: Zeile aus dev_meta."""
    dev, first = meta["dev"], meta["first_seen"] or now
    cur = now - now % 3600
    check_from = cur - 3600                       # letzte volle und aktuelle Stunde werden geprueft
    start = max(first - first % 3600, cur - BASELINE_DAYS * 86400)
    rows = {r["hour"]: dict(r) for r in conn.execute(
        "SELECT * FROM dev_hours WHERE dev=? AND hour >= ?", (dev, start))}
    hist_hours = list(range(start, check_from, 3600))
    series = {m: sorted(rows.get(h, {}).get(m, 0) or 0 for h in hist_hours)
              for m in list(METRICS) + ["bytes_in", "flows_in"]}
    active = [h for h in hist_hours if (rows.get(h, {}).get("flows") or 0) >= ACTIVE_HOUR_FLOWS]
    active_days = len({time.strftime("%Y%m%d", time.localtime(h)) for h in active})
    days = len({time.strftime("%Y%m%d", time.localtime(h)) for h in hist_hours})
    hod_days = defaultdict(set)
    for h in active:
        lt = time.localtime(h)
        hod_days[lt.tm_hour].add(time.strftime("%Y%m%d", lt))
    observed = now - first
    learned = observed >= learning_days * 86400 and active_days >= MIN_ACTIVE_DAYS
    stats = {m: {"median": percentile(v, 0.5), "p99": percentile(v, 0.99), "max": v[-1] if v else 0}
             for m, v in series.items()}
    return {
        "dev": dev, "learned": learned, "observed": observed, "active_days": active_days, "days": days,
        "learn_left": max(0, learning_days * 86400 - observed), "need_active": max(0, MIN_ACTIVE_DAYS - active_days),
        "hours": len(hist_hours), "active_share": (len(active) / len(hist_hours)) if hist_hours else 0,
        "hod": [len(hod_days[i]) for i in range(24)], "stats": stats,
        "check": {h: rows.get(h, {}) for h in (check_from, cur)},
    }


class Detector(threading.Thread):
    INTERVAL = 300

    def __init__(self, cfg, connect):
        super().__init__(daemon=True, name="anomaly-detector")
        self.cfg, self.connect = cfg, connect
        self.wake = threading.Event()
        self.last_run = None
        self.last_error = None

    @property
    def learning_days(self):
        return max(1, int(self.cfg.get("anomaly_learning_days", 7)))

    def run(self):
        time.sleep(30)
        while True:
            try:
                self.check()
                self.last_error = None
            except Exception as e:
                self.last_error = str(e)
                log.exception("Anomalieerkennung fehlgeschlagen")
            self.wake.wait(self.INTERVAL)
            self.wake.clear()

    # ---- Hilfen -------------------------------------------------------------

    @staticmethod
    def _state(conn, key, default=None):
        row = conn.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        try:
            return json.loads(row["value"]) if row else default
        except ValueError:
            return default

    @staticmethod
    def _set_state(conn, key, value):
        conn.execute("INSERT INTO state(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET "
                     "value=excluded.value", (key, json.dumps(value)))

    # ---- Pruefungen -------------------------------------------------------------

    def check(self):
        conn = self.connect(self.cfg["db_path"])
        found = []
        try:
            now = data_now(conn)
            mark = self._state(conn, "anomaly:seen_mark")
            newest = conn.execute("SELECT MAX(first_seen) m FROM dev_seen").fetchone()["m"] or 0
            if mark is None:      # erster Lauf: Vergangenheit nicht melden
                mark = newest
            mutes = {(r["dev"], r["kind"], r["metric"]) for r in conn.execute("SELECT * FROM anomaly_mutes")}
            metas = conn.execute("SELECT * FROM dev_meta WHERE last_seen >= ?", (now - 2 * 86400,)).fetchall()
            for meta in metas:
                b = baseline(conn, meta, now, self.learning_days)
                if not b["learned"]:
                    continue
                cands = self._novelty(conn, meta, mark) + self._volume(b) + self._timing(b)
                for a in cands:
                    if (meta["dev"], a["kind"], a["metric"]) in mutes or (meta["dev"], a["kind"], "*") in mutes:
                        continue
                    a.update(dev=meta["dev"], ip=meta["last_ip"])
                    found.append(a)
            new = []
            with conn:
                for a in found:
                    existed = conn.execute(
                        "SELECT id FROM anomalies WHERE dev=? AND kind=? AND metric=? AND item=? AND bucket=?",
                        (a["dev"], a["kind"], a["metric"], a["item"], a["bucket"])).fetchone()
                    conn.execute(
                        "INSERT INTO anomalies(ts, dev, ip, kind, metric, item, bucket, severity, score, title, "
                        "detail, status, updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,'open',?) "
                        "ON CONFLICT(dev, kind, metric, item, bucket) DO UPDATE SET "
                        "detail=CASE WHEN excluded.score >= score THEN excluded.detail ELSE detail END, "
                        "severity=CASE WHEN excluded.score >= score THEN excluded.severity ELSE severity END, "
                        "score=MAX(score, excluded.score), updated=excluded.updated",
                        (a["ts"], a["dev"], a["ip"], a["kind"], a["metric"], a["item"], a["bucket"], a["severity"],
                         a["score"], a["title"], json.dumps(a["detail"]), int(time.time())))
                    if not existed:
                        new.append(a)
                self._set_state(conn, "anomaly:seen_mark", max(mark, newest))
        finally:
            conn.close()
        self.last_run = int(time.time())
        for a in new:
            log.warning("Anomalie [%s] %s (%s): %s", a["severity"], a["title"], a["ip"] or a["dev"],
                        a["detail"].get("text", ""))
        if new:
            self.notify(new)
        return new

    def _novelty(self, conn, meta, mark):
        dev = meta["dev"]
        learn_end = (meta["first_seen"] or 0) + self.learning_days * 86400
        since = max(mark, learn_end)
        out = []
        for kind, (title, allowed, sev) in NOVELTY.items():
            rows = conn.execute("SELECT item, first_seen, count FROM dev_seen WHERE dev=? AND kind=? "
                                "AND first_seen > ? ORDER BY first_seen", (dev, kind, since)).fetchall()
            if not rows:
                continue
            # Wie oft kam in dieser Kategorie frueher Neues dazu? (ohne die ersten 2 Tage)
            ref_start = max((meta["first_seen"] or 0) + 2 * 86400, since - BASELINE_DAYS * 86400)
            ref_days = max(1.0, (since - ref_start) / 86400)
            prior = conn.execute("SELECT COUNT(*) n FROM dev_seen WHERE dev=? AND kind=? AND first_seen >= ? "
                                 "AND first_seen <= ?", (dev, kind, ref_start, since)).fetchone()["n"]
            known = conn.execute("SELECT COUNT(*) n FROM dev_seen WHERE dev=? AND kind=? AND first_seen <= ?",
                                 (dev, kind, since)).fetchone()["n"]
            rate = prior / ref_days
            if rate > allowed:
                continue
            base = {"rate": round(rate, 2), "known": known, "ref_days": round(ref_days, 1)}
            if len(rows) > 5:
                items = [r["item"] for r in rows]
                out.append({"kind": "new", "metric": kind, "item": "*%d" % (rows[0]["first_seen"] // 3600),
                            "bucket": 0, "ts": rows[0]["first_seen"], "severity": sev, "score": len(rows),
                            "title": title.replace("Neuer ", "Viele neue ").replace("Neues ", "Viele neue ")
                            .replace("Neue ", "Viele neue "),
                            "detail": dict(base, items=items[:20], total=len(items),
                                           text="%d neue Einträge: %s" % (len(items), ", ".join(items[:6])))})
                continue
            for r in rows:
                out.append({"kind": "new", "metric": kind, "item": r["item"], "bucket": 0, "ts": r["first_seen"],
                            "severity": sev, "score": 1, "title": title,
                            "detail": dict(base, items=[r["item"]], text=r["item"])})
        return out

    @staticmethod
    def _volume(b):
        out = []
        for metric, (title, floor, unit) in METRICS.items():
            st = b["stats"][metric]
            for hour, row in b["check"].items():
                v = row.get(metric) or 0
                thr = max(floor, 3 * st["p99"], 1.2 * st["max"])
                if v <= thr:
                    continue
                ref = max(st["p99"], 1)
                high = v >= max(10 * st["p99"], 2 * st["max"], 2 * floor)
                out.append({"kind": "volume", "metric": metric, "item": "", "bucket": hour, "ts": hour,
                            "severity": "high" if high else "medium", "score": round(v / ref, 1), "title": title,
                            "detail": {"value": v, "p99": st["p99"], "max": st["max"], "median": st["median"],
                                       "threshold": thr, "unit": unit, "hour": hour,
                                       "text": "%s in der Stunde ab %s, bisher höchstens %s" % (
                                           fmt(v, unit), time.strftime("%H:%M", time.localtime(hour)),
                                           fmt(st["max"], unit))}})
        return out

    @staticmethod
    def _timing(b):
        out = []
        if b["days"] < 7 or b["active_share"] >= 0.5:
            return out
        for hour, row in b["check"].items():
            flows = row.get("flows") or 0
            if flows < 30:
                continue
            hod = time.localtime(hour).tm_hour
            seen_days = b["hod"][hod]
            if seen_days > max(0, int(b["days"] * 0.05)):
                continue
            out.append({"kind": "time", "metric": "hour", "item": "", "bucket": hour, "ts": hour,
                        "severity": "low", "score": flows, "title": "Aktiv zu ungewöhnlicher Uhrzeit",
                        "detail": {"flows": flows, "hour_of_day": hod, "seen_days": seen_days, "days": b["days"],
                                   "hod": b["hod"], "hour": hour,
                                   "text": "%d Verbindungen um %d Uhr, in den letzten %d Tagen um diese Zeit an %d "
                                           "Tag(en) aktiv" % (flows, hod, b["days"], seen_days)}})
        return out

    # ---- Benachrichtigung ---------------------------------------------------------

    def notify(self, anomalies):
        """Optional: POST an eine URL (z. B. ntfy.sh/<thema> oder ein eigener Webhook)."""
        url = (self.cfg.get("anomaly_notify_url") or "").strip()
        if not url:
            return
        min_sev = SEVERITY_ORDER.get(self.cfg.get("anomaly_notify_min_severity", "medium"), 1)
        send = [a for a in anomalies if SEVERITY_ORDER.get(a["severity"], 2) <= min_sev]
        if not send:
            return
        worst = min(send, key=lambda a: SEVERITY_ORDER.get(a["severity"], 2))
        body = "\n".join("[%s] %s – %s: %s" % (a["severity"], a.get("name") or a["ip"] or a["dev"], a["title"],
                                                a["detail"].get("text", "")) for a in send[:20])
        req = urllib.request.Request(url, data=body.encode("utf-8"), method="POST", headers={
            "Title": "Suricata Dashboard: %d Anomalie(n)" % len(send),
            "Priority": "high" if worst["severity"] == "high" else "default",
            "Tags": "warning", "Content-Type": "text/plain; charset=utf-8",
            "User-Agent": "suricata-dashboard"})
        try:
            with urllib.request.urlopen(req, timeout=15):
                pass
        except Exception as e:
            log.warning("Benachrichtigung an %s fehlgeschlagen: %s", url, e)


def fmt(v, unit):
    if unit == "bytes":
        for u in ("B", "KB", "MB", "GB", "TB"):
            if v < 1024 or u == "TB":
                return ("%.0f %s" if u == "B" or v >= 10 else "%.1f %s") % (v, u)
            v /= 1024.0
    return "{:,}".format(int(v)).replace(",", ".")
