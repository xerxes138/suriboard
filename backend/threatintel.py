"""
Threat-Intel fuer das Suricata Dashboard (nur Python-Standardbibliothek).

* laedt oeffentliche Feeds (IP-Blocklisten, Domain-Blocklisten, Tranco-Top-Liste,
  IP->ASN-Zuordnung) regelmaessig im Hintergrund herunter
* speichert die Rohdaten in data/feeds/ (ueberstehen Neustarts und Offline-Phasen)
* haelt kompakte Nachschlage-Strukturen im Speicher
* bewertet IPs (inkl. der Hostnamen, die per DNS/TLS/HTTP zu einer IP gesehen wurden)

Bewertung (verdict) einer IP:
  malicious  - auf einer Blockliste fuer Botnetze/kriminelle Netze, oder ein zugeordneter
               Hostname steht auf einer Domain-Blockliste
  suspicious - auf einer Liste fuer Scanner/Angreifer oder Tor-Exit-Node
  known      - ein zugeordneter Hostname gehoert zu einem bekannten Update-/Systemdienst
               (z. B. Windows Update) und es gibt keinen Blocklisten-Treffer
  popular    - zugeordneter Hostname ist in den Tranco-Top-N
  unknown    - nichts gefunden
  local      - private/reservierte Adresse, wird nicht nachgeschlagen

TLS-Fingerabdruecke (JA3/JA3S/JA4/JA4S) werden gegen eigene Feed-Arten geprueft:
  ja3     - CSV, erste Spalte MD5-Hash, letzte Spalte Bezeichnung (z. B. abuse.ch SSLBL)
  ja4     - wie ja3, aber JA4/JA4S-Fingerabdruecke
  ja4map  - FoxIO ja4plus-mapping.csv (Anwendung/Bibliothek/Geraet je Fingerabdruck)
"""

import array
import bisect
import gzip
import io
import ipaddress
import json
import logging
import os
import re
import socket
import struct
import threading
import time
import urllib.error
import urllib.request
import zipfile

log = logging.getLogger("suricata-dashboard.intel")

USER_AGENT = "suricata-dashboard (threat-feed-updater)"
MAX_DOWNLOAD = 80 * 1024 * 1024
RETRY_AFTER_ERROR = 1800  # Sekunden bis zum naechsten Versuch nach einem Fehler

# kind:     ip | domain | rank | asn | ja3 | ja4 | ja4map
# category: malicious | suspicious (fuer ip/domain/ja3/ja4)
FEEDS = [
    {"id": "spamhaus_drop", "name": "Spamhaus DROP", "kind": "ip", "category": "malicious",
     "urls": ["https://www.spamhaus.org/drop/drop_v4.json",
              "https://www.spamhaus.org/drop/drop_v6.json"],
     "interval_h": 12, "enabled": True, "homepage": "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
     "info": "Netze, die komplett von Kriminellen betrieben werden oder gekapert sind. Sehr wenige Fehlalarme."},
    {"id": "feodo", "name": "abuse.ch Feodo Tracker", "kind": "ip", "category": "malicious",
     "urls": ["https://feodotracker.abuse.ch/downloads/ipblocklist.txt"],
     "interval_h": 6, "enabled": True, "homepage": "https://feodotracker.abuse.ch/",
     "info": "Aktive Botnetz-Command-&-Control-Server (Emotet, QakBot, …)."},
    {"id": "et_compromised", "name": "Emerging Threats Compromised", "kind": "ip", "category": "malicious",
     "urls": ["https://rules.emergingthreats.net/blockrules/compromised-ips.txt"],
     "interval_h": 12, "enabled": True, "homepage": "https://rules.emergingthreats.net/",
     "info": "Kompromittierte Hosts laut Proofpoint Emerging Threats."},
    {"id": "ipsum3", "name": "IPsum (≥ 3 Listen)", "kind": "ip", "category": "suspicious",
     "urls": ["https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"],
     "interval_h": 24, "enabled": True, "homepage": "https://github.com/stamparm/ipsum",
     "info": "IPs, die auf mindestens 3 öffentlichen Blocklisten stehen (meist Scanner und Angreifer)."},
    {"id": "cins", "name": "CINS Army", "kind": "ip", "category": "suspicious",
     "urls": ["https://cinsscore.com/list/ci-badguys.txt"],
     "interval_h": 12, "enabled": True, "homepage": "https://cinsscore.com/",
     "info": "IPs mit schlechtem Ruf aus dem Sentinel-IPS-Netzwerk (Scanner, Brute-Force)."},
    {"id": "blocklist_de", "name": "blocklist.de", "kind": "ip", "category": "suspicious",
     "urls": ["https://lists.blocklist.de/lists/all.txt"],
     "interval_h": 12, "enabled": True, "homepage": "https://www.blocklist.de/",
     "info": "Angreifer der letzten 48 Std (SSH, Mail, Web, …), gemeldet von Fail2ban-Nutzern."},
    {"id": "tor_exit", "name": "Tor-Exit-Nodes", "kind": "ip", "category": "suspicious",
     "urls": ["https://check.torproject.org/torbulkexitlist"],
     "interval_h": 6, "enabled": True, "homepage": "https://metrics.torproject.org/",
     "info": "Ausgangsknoten des Tor-Netzwerks. Nicht bösartig an sich, aber anonymer Ursprung."},
    {"id": "hagezi_tif", "name": "HaGeZi Threat-Intel", "kind": "domain", "category": "malicious",
     "urls": ["https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt"],
     "interval_h": 12, "enabled": True, "homepage": "https://github.com/hagezi/dns-blocklists",
     "info": "Malware-, Phishing- und C2-Domains aus vielen Quellen (inkl. Subdomains). ca. 25 MB RAM."},
    {"id": "sslbl_ja3", "name": "abuse.ch SSLBL JA3", "kind": "ja3", "category": "suspicious",
     "urls": ["https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"],
     "interval_h": 168, "enabled": True, "homepage": "https://sslbl.abuse.ch/blacklist/",
     "info": "JA3-Fingerabdrücke von Malware-Clients (Dridex, TrickBot, Tofsee …). Wird seit 2021 nicht mehr "
             "erweitert. JA3-Hashes sind nicht eindeutig (auch normale Programme können denselben haben), "
             "deshalb gelten Treffer nur als „auffällig“."},
    {"id": "foxio_ja4", "name": "FoxIO JA4+ Zuordnung", "kind": "ja4map",
     "urls": ["https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv"],
     "interval_h": 168, "enabled": True, "homepage": "https://github.com/FoxIO-LLC/ja4",
     "info": "Offizielle JA4-Zuordnung der JA4-Erfinder: Browser und Bibliotheken (Chromium, Firefox, Python, Go …), "
             "aber auch Malware (Cobalt Strike, IcedID, Sliver). Klein, ohne Lizenzauflagen."},
    {"id": "tranco", "name": "Tranco Top-Domains", "kind": "rank",
     "urls": ["https://tranco-list.eu/top-1m.csv.zip"],
     "interval_h": 168, "enabled": True, "homepage": "https://tranco-list.eu/",
     "info": "Rangliste der meistbesuchten Domains. Ein hoher Rang ist ein Hinweis, kein Beweis für Harmlosigkeit."},
    {"id": "asn", "name": "IP → Netzbetreiber (iptoasn.com)", "kind": "asn",
     "urls": ["https://iptoasn.com/data/ip2asn-combined.tsv.gz"],
     "interval_h": 168, "enabled": True, "homepage": "https://iptoasn.com/",
     "info": "Ordnet jeder IP ihr Autonomes System zu (z. B. AS8075 Microsoft, AS20940 Akamai). ca. 11 MB Download."},
]

# Bekannte Update-/Systemdienste (Domain-Suffix -> Dienst). Nur Domains, die ausschliesslich
# vom jeweiligen Hersteller betrieben werden (keine Hoster wie github.com oder amazonaws.com).
KNOWN_SERVICES = {
    # Microsoft / Windows
    "windowsupdate.com": "Windows Update",
    "update.microsoft.com": "Windows Update",
    "delivery.mp.microsoft.com": "Windows Update",
    "dsp.mp.microsoft.com": "Windows Update (Übermittlungsoptimierung)",
    "download.windowsupdate.com": "Windows Update",
    "wustat.windows.com": "Windows Update",
    "ntservicepack.microsoft.com": "Windows Update",
    "definitionupdates.microsoft.com": "Microsoft Defender",
    "wdcp.microsoft.com": "Microsoft Defender",
    "wd.microsoft.com": "Microsoft Defender",
    "smartscreen.microsoft.com": "Microsoft SmartScreen",
    "officecdn.microsoft.com": "Microsoft Office Update",
    "msftconnecttest.com": "Windows Netzwerktest",
    "msftncsi.com": "Windows Netzwerktest",
    "microsoft.com": "Microsoft",
    "windows.com": "Microsoft",
    "office.com": "Microsoft 365",
    "office.net": "Microsoft 365",
    "live.com": "Microsoft",
    "xboxlive.com": "Xbox Live",
    # Apple
    "apple.com": "Apple",
    "icloud.com": "Apple iCloud",
    "mzstatic.com": "Apple",
    "cdn-apple.com": "Apple",
    "aaplimg.com": "Apple",
    "apple-cloudkit.com": "Apple iCloud",
    # Google (nur eigene Dienste, nicht googleapis.com/Cloud-Storage)
    "gvt1.com": "Google/Chrome Update",
    "gvt2.com": "Google/Chrome Update",
    "update.googleapis.com": "Google/Chrome Update",
    "dl.google.com": "Google Downloads",
    "android.clients.google.com": "Android",
    # Linux / Raspberry Pi
    "debian.org": "Debian-Paketquelle",
    "ubuntu.com": "Ubuntu",
    "canonical.com": "Canonical",
    "launchpad.net": "Ubuntu Launchpad",
    "raspberrypi.com": "Raspberry Pi",
    "raspberrypi.org": "Raspberry Pi",
    "archlinux.org": "Arch Linux",
    "fedoraproject.org": "Fedora",
    "suricata.io": "Suricata",
    "openinfosecfoundation.org": "Suricata (OISF)",
    "emergingthreats.net": "Emerging-Threats-Regeln",
    # Browser / Software
    "mozilla.org": "Mozilla",
    "mozilla.net": "Mozilla",
    "mozilla.com": "Mozilla",
    "firefox.com": "Mozilla",
    "steampowered.com": "Steam",
    "steamcontent.com": "Steam Downloads",
    "steamserver.net": "Steam",
    # Zeit
    "ntp.org": "NTP-Zeitserver",
}

VERDICT_ORDER = {"malicious": 5, "suspicious": 4, "unknown": 3, "popular": 2, "known": 1, "local": 0}


# --------------------------------------------------------------------------
# IP-Hilfen (schnell, ohne ipaddress fuer Massendaten)
# --------------------------------------------------------------------------

def ip_to_int(s):
    """'1.2.3.4' / '2001:db8::1' -> (version, int) oder None."""
    try:
        if ":" in s:
            hi, lo = struct.unpack("!QQ", socket.inet_pton(socket.AF_INET6, s))
            return 6, (hi << 64) | lo
        if s.count(".") != 3:
            return None
        return 4, struct.unpack("!I", socket.inet_aton(s))[0]
    except (OSError, struct.error, ValueError):
        return None


def parse_net(token):
    """'1.2.3.0/24', '1.2.3.4', '2001:db8::/32' -> (version, prefixlen, netint) oder None."""
    addr, _, plen = token.partition("/")
    r = ip_to_int(addr)
    if not r:
        return None
    ver, n = r
    bits = 32 if ver == 4 else 128
    try:
        p = int(plen) if plen else bits
    except ValueError:
        return None
    if not 0 < p <= bits:  # /0 waere "alles" -> ignorieren
        return None
    mask = ((1 << p) - 1) << (bits - p)
    return ver, p, n & mask


_global_cache = {}


def is_global(ip):
    v = _global_cache.get(ip)
    if v is None:
        try:
            v = ipaddress.ip_address(ip).is_global
        except ValueError:
            v = False
        if len(_global_cache) > 50000:
            _global_cache.clear()
        _global_cache[ip] = v
    return v


def looks_like_ip(s):
    return ip_to_int(s) is not None


def norm_domain(name):
    if not name:
        return None
    name = name.strip().lower()
    if name.count(":") == 1:  # HTTP-Host mit Port: "example.com:8080"
        name = name.split(":")[0]
    name = name.rstrip(".")
    if not name or " " in name or looks_like_ip(name):
        return None
    return name


def domain_suffixes(name):
    """'a.b.example.com' -> ['a.b.example.com', 'b.example.com', 'example.com', 'com']"""
    parts = name.split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]


# --------------------------------------------------------------------------
# Parser fuer die Feed-Formate
# --------------------------------------------------------------------------

def parse_ip_feed(data):
    """Textliste (IP/CIDR am Zeilenanfang, Kommentare mit # oder ;) oder JSON-Zeilen mit 'cidr'."""
    nets = set()
    for raw in data.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line[0] == "{":
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            token = obj.get("cidr") or obj.get("ip")
            if not token:
                continue
        else:
            token = line.replace(",", " ").replace(";", " ").split()[0]
        n = parse_net(token)
        if n:
            nets.add(n)
    return nets


def parse_domain_feed(data):
    """Eine Domain pro Zeile, auch Hosts-Format ('0.0.0.0 domain') und Adblock ('||domain^')."""
    out = set()
    for raw in data.splitlines():
        line = raw.strip()
        if not line or line[0] in "#!;":
            continue
        parts = line.split()
        token = parts[-1] if len(parts) > 1 and looks_like_ip(parts[0]) else parts[0]
        if token.startswith("||"):
            token = token[2:].rstrip("^")
        token = token.lstrip("*.")
        d = norm_domain(token)
        if d and "." in d:
            out.add(d)
    return out


def parse_rank_zip(raw, top_n):
    ranks = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        name = z.namelist()[0]
        with z.open(name) as f:
            for i, line in enumerate(io.TextIOWrapper(f, encoding="utf-8", errors="replace")):
                if i >= top_n:
                    break
                rank, _, dom = line.strip().partition(",")
                d = norm_domain(dom)
                if d:
                    try:
                        ranks[d] = int(rank)
                    except ValueError:
                        pass
    return ranks


# --------------------------------------------------------------------------
# TLS-Fingerabdruecke
# --------------------------------------------------------------------------

FP_TYPES = ("ja3", "ja3s", "ja4", "ja4s")
RE_MD5 = re.compile(r"^[0-9a-f]{32}$")
RE_JA4 = re.compile(r"^[tqd][0-9a-z]{2}[di][0-9]{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")
RE_JA4S = re.compile(r"^[tqd][0-9a-z]{2}[0-9]{2}[0-9a-z]{2}_[0-9a-f]{4}_[0-9a-f]{12}$")

# Bezeichnungen in der FoxIO-Zuordnung, die auf Schadsoftware/Angriffswerkzeuge hinweisen
MALWARE_WORDS = ("sliver", "icedid", "cobalt strike", "qakbot", "pikabot", "darkgate", "lumma",
                 "havoc", "trickbot", "emotet", "dridex", "metasploit", "bitrat", "asyncrat",
                 "remcos", "njrat", "quasar", "brute ratel", "mythic")


def fp_type_of(value, family):
    """Typ eines Hashes bestimmen. family: 'ja3' oder 'ja4'."""
    v = value.strip().lower()
    if family == "ja3":
        return ("ja3", v) if RE_MD5.match(v) else (None, v)
    if RE_JA4.match(v):
        return ("ja4", v)
    if RE_JA4S.match(v):
        return ("ja4s", v)
    return (None, v)


def parse_fp_list(data, family, category):
    """CSV/Text: erste Spalte Hash, letzte Spalte (falls vorhanden) Bezeichnung.
    Ergebnis: {(typ, hash): [(bezeichnung, kategorie)]}"""
    out = {}
    for raw in data.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        cols = [c.strip().strip('"') for c in line.split(",")]
        t, h = fp_type_of(cols[0], family)
        if not t:
            continue
        label = cols[-1][:80] if len(cols) > 1 and cols[-1] else None
        out.setdefault((t, h), []).append((label, category))
    return out


def ja4map_category(label):
    low = label.lower()
    return "malicious" if any(w in low for w in MALWARE_WORDS) else "info"


def parse_ja4map(data):
    """FoxIO ja4plus-mapping.csv: Application,Library,Device,OS,ja4,ja4s,..."""
    import csv
    out = {}
    rows = csv.reader(io.StringIO(data))
    header = [h.strip().lower() for h in next(rows, [])]
    if "ja4" not in header:
        raise ValueError("Spalte 'ja4' fehlt (Format geändert?)")
    idx = {h: i for i, h in enumerate(header)}
    for row in rows:
        def col(name):
            i = idx.get(name)
            return row[i].strip() if i is not None and i < len(row) else ""
        app, lib, dev, os_ = col("application"), col("library"), col("device"), col("os")
        label = app or lib or dev or os_
        if lib and app and lib.lower() not in app.lower():
            label = "%s (%s)" % (app, lib)
        if not label:
            continue
        note = col("notes")
        for t in ("ja4", "ja4s"):
            v = col(t).lower()
            if v and (RE_JA4 if t == "ja4" else RE_JA4S).match(v):
                text = note if note and note.lower().startswith(label.lower()[:12]) else \
                    label + (" – " + note if note else "")
                entry = text[:120], ja4map_category(label)
                lst = out.setdefault((t, v), [])
                if entry not in lst:
                    lst.append(entry)
    return out


class AsnTable:
    """Sortierte Bereiche IP -> ASN. IPv4 als 32-Bit, IPv6 ueber die oberen 64 Bit."""

    def __init__(self):
        self.v4_start = array.array("I")
        self.v4_end = array.array("I")
        self.v4_asn = array.array("I")
        self.v6_start = array.array("Q")
        self.v6_end = array.array("Q")
        self.v6_asn = array.array("I")
        self.names = {}

    @classmethod
    def parse(cls, raw):
        """Parst ip2asn-combined.tsv.gz direkt in Arrays (spart auf dem Pi viel RAM)."""
        t = cls()
        s4, e4, a4 = array.array("I"), array.array("I"), array.array("I")
        s6, e6, a6 = array.array("Q"), array.array("Q"), array.array("I")
        names = {}
        with gzip.open(io.BytesIO(raw), "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5 or parts[2] == "0":
                    continue
                a = ip_to_int(parts[0])
                b = ip_to_int(parts[1])
                if not a or not b or a[0] != b[0]:
                    continue
                try:
                    asn = int(parts[2])
                except ValueError:
                    continue
                if asn not in names:
                    names[asn] = parts[4] + "\t" + (parts[3] if parts[3] != "None" else "")
                if a[0] == 4:
                    s4.append(a[1])
                    e4.append(b[1])
                    a4.append(asn)
                else:
                    s6.append(a[1] >> 64)
                    e6.append(b[1] >> 64)
                    a6.append(asn)
        # Die Datei ist textuell sortiert -> numerisch umsortieren
        for src, dst in (((s4, e4, a4), (t.v4_start, t.v4_end, t.v4_asn)),
                         ((s6, e6, a6), (t.v6_start, t.v6_end, t.v6_asn))):
            order = sorted(range(len(src[0])), key=src[0].__getitem__)
            for arr_in, arr_out in zip(src, dst):
                arr_out.extend(arr_in[i] for i in order)
            del order
        t.names = names
        return t

    def __len__(self):
        return len(self.v4_start) + len(self.v6_start)

    def lookup(self, ver, n):
        if ver == 4:
            starts, ends, asns = self.v4_start, self.v4_end, self.v4_asn
        else:
            starts, ends, asns, n = self.v6_start, self.v6_end, self.v6_asn, n >> 64
        i = bisect.bisect_right(starts, n) - 1
        if i < 0 or n > ends[i]:
            return None
        asn = asns[i]
        name, _, cc = self.names.get(asn, "").partition("\t")
        short = name.split(" - ", 1)[1] if " - " in name else name
        return {"asn": asn, "name": name, "short": short, "country": cc}


# --------------------------------------------------------------------------
# Hauptklasse
# --------------------------------------------------------------------------

class ThreatIntel(threading.Thread):
    def __init__(self, cfg, connect):
        super().__init__(daemon=True, name="threat-intel")
        self.cfg = cfg
        self.connect = connect
        self.dir = os.path.join(os.path.dirname(cfg["db_path"]), "feeds")
        self.top_n = int(cfg.get("tranco_top", 100000))
        self.feeds = {}
        builtin = {x["id"] for x in FEEDS}
        for f in FEEDS + list(cfg.get("custom_feeds") or []):
            f = dict(f)
            if not f.get("id") or not f.get("urls") and not f.get("url"):
                continue
            f.setdefault("urls", [f.get("url")])
            f.setdefault("kind", "ip")
            f.setdefault("category", "malicious")
            f.setdefault("interval_h", 12)
            f.setdefault("enabled", True)
            f.setdefault("name", f["id"])
            f["custom"] = f["id"] not in builtin
            self.feeds[f["id"]] = f
        self.services = dict(KNOWN_SERVICES)
        self.services.update({k.lower().strip("."): v for k, v in (cfg.get("trusted_domains") or {}).items()})
        self.enabled_global = bool(cfg.get("threat_intel", True))

        # Nachschlage-Strukturen (werden komplett ersetzt, nie veraendert -> threadsicher lesbar)
        self.nets = {}        # feed_id -> set((ver, plen, net))
        self.ip_index = {}    # (ver, plen) -> {net: (feed_id, ...)}
        self.domains = {}     # feed_id -> set(domain)
        self.fps = {}         # feed_id -> {(typ, hash): [(bezeichnung, kategorie)]}
        self.ranks = {}       # domain -> Rang
        self.asn = None
        self.meta = {}        # feed_id -> Status
        self.busy = None
        self.loaded = False
        self.wake = threading.Event()
        self.force = set()
        self.lock = threading.Lock()
        self._load_meta()

    # --- Zustand in der DB ---------------------------------------------------

    def _state_get(self, key, default):
        conn = self.connect(self.cfg["db_path"])
        try:
            row = conn.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        finally:
            conn.close()
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except ValueError:
            return default

    def _state_set(self, key, value):
        conn = self.connect(self.cfg["db_path"])
        try:
            with conn:
                conn.execute("INSERT INTO state(key, value) VALUES(?, ?) ON CONFLICT(key) "
                             "DO UPDATE SET value=excluded.value", (key, json.dumps(value)))
        finally:
            conn.close()

    def _load_meta(self):
        self.meta = self._state_get("intel:meta", {})
        overrides = self._state_get("intel:enabled", {})
        for fid, on in overrides.items():
            if fid in self.feeds:
                self.feeds[fid]["enabled"] = bool(on)

    def _save_meta(self):
        with self.lock:
            snapshot = json.loads(json.dumps(self.meta))
        self._state_set("intel:meta", snapshot)

    def set_enabled(self, fid, on):
        if fid not in self.feeds:
            raise KeyError(fid)
        self.feeds[fid]["enabled"] = bool(on)
        self._state_set("intel:enabled", {k: f["enabled"] for k, f in self.feeds.items()})
        if on:
            self.request_update(fid)
        else:
            self._unload(fid)
            self._rebuild_ip_index()

    def request_update(self, fid=None):
        ids = [fid] if fid else [k for k, f in self.feeds.items() if f["enabled"]]
        for i in ids:
            if i not in self.feeds:
                raise KeyError(i)
        with self.lock:
            self.force.update(ids)
        self.wake.set()

    # --- Hintergrund-Thread ------------------------------------------------------

    def path(self, fid):
        return os.path.join(self.dir, fid + ".dat")

    def run(self):
        os.makedirs(self.dir, exist_ok=True)
        t0 = time.time()
        for fid, f in self.feeds.items():
            if f["enabled"] and os.path.exists(self.path(fid)):
                try:
                    with open(self.path(fid), "rb") as fh:
                        self._install(fid, self._parse(f, fh.read()))
                except Exception as e:
                    log.warning("Feed %s: gespeicherte Daten unlesbar: %s", fid, e)
        self._rebuild_ip_index()
        self.loaded = True
        log.info("Threat-Feeds geladen in %.1fs", time.time() - t0)
        if not self.enabled_global:
            log.info("Threat-Feeds: automatische Updates deaktiviert (threat_intel=false)")
        while True:
            try:
                self._update_due()
            except Exception:
                log.exception("Fehler beim Aktualisieren der Threat-Feeds")
            self.wake.wait(60)
            self.wake.clear()

    def _due(self, fid, f, now):
        if fid in self.force:
            return True
        if not f["enabled"] or not self.enabled_global:
            return False
        m = self.meta.get(fid, {})
        if m.get("error") and now - m.get("last_check", 0) < RETRY_AFTER_ERROR:
            return False
        if not os.path.exists(self.path(fid)):
            return True
        return now - m.get("last_success", 0) >= f["interval_h"] * 3600

    def _update_due(self):
        now = time.time()
        for fid, f in self.feeds.items():
            with self.lock:
                due = self._due(fid, f, now)
                self.force.discard(fid)
            if due:
                self.busy = fid
                try:
                    self._update(fid, f)
                finally:
                    self.busy = None
                self._save_meta()

    def _download(self, fid, url, m, conditional):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        if conditional and os.path.exists(self.path(fid)):
            if m.get("etag"):
                req.add_header("If-None-Match", m["etag"])
            if m.get("last_modified"):
                req.add_header("If-Modified-Since", m["last_modified"])
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read(MAX_DOWNLOAD + 1)
                if len(data) > MAX_DOWNLOAD:
                    raise ValueError("Download größer als %d MB" % (MAX_DOWNLOAD // 1048576))
                if conditional:
                    m["etag"] = r.headers.get("ETag")
                    m["last_modified"] = r.headers.get("Last-Modified")
                return data
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return None
            raise

    def _update(self, fid, f):
        m = self.meta.setdefault(fid, {})
        m["last_check"] = int(time.time())
        single = len(f["urls"]) == 1
        try:
            parts = []
            for url in f["urls"]:
                d = self._download(fid, url, m, conditional=single)
                if d is None:  # 304 Not Modified
                    log.info("Feed %s: unverändert", fid)
                    m["last_success"] = int(time.time())
                    m["error"] = None
                    if not self._is_loaded(fid):
                        with open(self.path(fid), "rb") as fh:
                            self._install(fid, self._parse(f, fh.read()))
                            self._rebuild_ip_index()
                    return
                parts.append(d)
            raw = parts[0] if single else b"\n".join(parts)
            parsed = self._parse(f, raw)
            count = len(parsed)
            if not count:
                raise ValueError("keine gültigen Einträge in der Antwort (Format geändert?)")
            tmp = self.path(fid) + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(raw)
            os.replace(tmp, self.path(fid))
            if f["enabled"]:
                self._install(fid, parsed)
                self._rebuild_ip_index()
            m.update(last_success=int(time.time()), error=None, entries=count, bytes=len(raw))
            log.info("Feed %s aktualisiert: %d Einträge", fid, count)
        except Exception as e:
            m["error"] = str(e)[:300]
            log.warning("Feed %s: Aktualisierung fehlgeschlagen: %s", fid, e)

    def _is_loaded(self, fid):
        k = self.feeds[fid]["kind"]
        return (fid in self.nets or fid in self.domains or fid in self.fps or
                (k == "rank" and bool(self.ranks)) or (k == "asn" and bool(self.asn)))

    def _parse(self, f, raw):
        k = f["kind"]
        if k in ("ja3", "ja4"):
            return parse_fp_list(raw.decode("utf-8", errors="replace"), k, f.get("category", "suspicious"))
        if k == "ja4map":
            return parse_ja4map(raw.decode("utf-8", errors="replace"))
        if k == "ip":
            return parse_ip_feed(raw.decode("utf-8", errors="replace"))
        if k == "domain":
            return parse_domain_feed(raw.decode("utf-8", errors="replace"))
        if k == "rank":
            return parse_rank_zip(raw, self.top_n)
        if k == "asn":
            return AsnTable.parse(raw)
        raise ValueError("unbekannter Feed-Typ %s" % k)

    def _install(self, fid, parsed):
        k = self.feeds[fid]["kind"]
        if k == "ip":
            nets = dict(self.nets)
            nets[fid] = parsed
            self.nets = nets
        elif k == "domain":
            doms = dict(self.domains)
            doms[fid] = parsed
            self.domains = doms
        elif k in ("ja3", "ja4", "ja4map"):
            fps = dict(self.fps)
            fps[fid] = parsed
            self.fps = fps
        elif k == "rank":
            self.ranks = parsed
        elif k == "asn":
            self.asn = parsed
        with self.lock:
            self.meta.setdefault(fid, {})["entries"] = len(parsed)

    def _unload(self, fid):
        k = self.feeds[fid]["kind"]
        if k == "ip":
            self.nets = {i: v for i, v in self.nets.items() if i != fid}
        elif k == "domain":
            self.domains = {i: v for i, v in self.domains.items() if i != fid}
        elif k in ("ja3", "ja4", "ja4map"):
            self.fps = {i: v for i, v in self.fps.items() if i != fid}
        elif k == "rank":
            self.ranks = {}
        elif k == "asn":
            self.asn = None

    def _rebuild_ip_index(self):
        idx = {}
        for fid, nets in self.nets.items():
            for ver, plen, net in nets:
                d = idx.setdefault((ver, plen), {})
                d[net] = d.get(net, ()) + (fid,)
        # laengste Praefixe zuerst pruefen ist egal - wir sammeln alle Treffer
        self.ip_index = idx

    # --- Nachschlagen ------------------------------------------------------------

    def _feed_ref(self, fid, via=None):
        f = self.feeds[fid]
        r = {"id": fid, "name": f["name"], "category": f.get("category", "malicious")}
        if via:
            r["via"] = via
        return r

    def ip_lists(self, ip):
        r = ip_to_int(ip)
        if not r:
            return []
        ver, n = r
        bits = 32 if ver == 4 else 128
        hits = []
        for (v, plen), d in self.ip_index.items():
            if v != ver:
                continue
            fids = d.get(n & (((1 << plen) - 1) << (bits - plen)))
            if fids:
                for fid in fids:
                    if fid not in hits:
                        hits.append(fid)
        return [self._feed_ref(fid) for fid in hits]

    def asn_info(self, ip):
        if not self.asn:
            return None
        r = ip_to_int(ip)
        return self.asn.lookup(*r) if r else None

    def domain_info(self, name):
        d = norm_domain(name)
        if not d:
            return None
        sufs = domain_suffixes(d)
        lists = []
        for fid, s in self.domains.items():
            for x in sufs:
                if x in s:
                    lists.append(self._feed_ref(fid, via=x))
                    break
        service = None
        for x in sufs:
            if x in self.services:
                service = self.services[x]
                break
        rank = None
        for x in sufs[:-1]:  # nicht die TLD allein
            if x in self.ranks:
                rank = self.ranks[x]
                break
        return {"name": d, "lists": lists, "service": service, "rank": rank}

    def assess_ip(self, ip, names=None):
        """names: Liste von dicts {name, source, last_seen} (aus ip_names)."""
        out = {"ip": ip, "global": bool(ip) and is_global(ip), "lists": [], "asn": None,
               "names": [], "reasons": []}
        if not out["global"]:
            out["verdict"] = "local"
            return out
        out["lists"] = self.ip_lists(ip)
        out["asn"] = self.asn_info(ip)
        reasons = out["reasons"]
        for l in out["lists"]:
            reasons.append({"level": l["category"], "text": "IP steht auf " + l["name"], "feed": l["id"]})
        services, best_rank, bad_domain = [], None, False
        for n in names or []:
            info = self.domain_info(n.get("name"))
            if not info:
                continue
            info.update({k: n[k] for k in ("source", "last_seen", "count") if k in n})
            out["names"].append(info)
            for l in info["lists"]:
                bad_domain = True
                reasons.append({"level": l["category"], "feed": l["id"],
                                "text": "Hostname %s steht auf %s" % (info["name"], l["name"])})
            if info["service"] and info["service"] not in services:
                services.append(info["service"])
            if info["rank"] and (best_rank is None or info["rank"] < best_rank):
                best_rank = info["rank"]
        cats = {r["level"] for r in reasons}
        if "malicious" in cats:
            verdict = "malicious"
        elif "suspicious" in cats:
            verdict = "suspicious"
        elif services and not bad_domain:
            verdict = "known"
        elif best_rank:
            verdict = "popular"
        else:
            verdict = "unknown"
        for s in services:
            reasons.append({"level": "known", "text": "Hostname gehört zu " + s})
        if best_rank:
            reasons.append({"level": "popular", "text": "Domain in Tranco-Top-Liste (Rang %d)" % best_rank})
        if out["asn"]:
            a = out["asn"]
            reasons.append({"level": "info", "text": "Netz: AS%d %s%s" % (
                a["asn"], a["name"], " (" + a["country"] + ")" if a["country"] else "")})
        out["services"] = services
        out["rank"] = best_rank
        out["verdict"] = verdict
        return out

    def assess_fp(self, fp_type, fp):
        """Bewertung eines TLS-Fingerabdrucks.
        malicious  - nur Malware-Bezeichnungen
        suspicious - Treffer auf einer 'auffaellig'-Liste, oder Malware-Bezeichnung, die sich den
                     Fingerabdruck mit normaler Software teilt (z. B. Sliver = Go-Standardbibliothek)
        known      - nur harmlose Zuordnungen (Browser, Bibliothek, Geraet)
        unknown    - nirgends gefunden"""
        fp = (fp or "").strip().lower()
        matches = []
        for fid, d in self.fps.items():
            for label, cat in d.get((fp_type, fp), ()):
                matches.append({"feed": fid, "feed_name": self.feeds[fid]["name"],
                                "label": label, "category": cat})
        cats = {m["category"] for m in matches}
        bad = [m for m in matches if m["category"] == "malicious"]
        benign = [m for m in matches if m["category"] == "info"]
        reasons = []
        if bad and benign:
            verdict = "suspicious"
            reasons.append({"level": "suspicious", "text": "Passt zu %s (%s), wird aber auch von %s genutzt" % (
                ", ".join(sorted({m["label"] for m in bad})), bad[0]["feed_name"],
                ", ".join(sorted({m["label"] for m in benign})))})
        elif bad and fp_type in ("ja3s", "ja4s"):
            # Server-Fingerabdruecke haengen stark von der Client-Anfrage ab und sind wenig eindeutig
            verdict = "suspicious"
            for m in bad:
                reasons.append({"level": "suspicious", "text": "Server-Antwort passt zu %s (%s) – allein wenig "
                                "aussagekräftig, mit JA4 des Clients vergleichen" % (m["label"], m["feed_name"])})
        elif bad:
            verdict = "malicious"
            for m in bad:
                reasons.append({"level": "malicious", "text": "Passt zu %s (%s)" % (m["label"], m["feed_name"])})
        elif "suspicious" in cats:
            verdict = "suspicious"
            for m in matches:
                if m["category"] == "suspicious":
                    reasons.append({"level": "suspicious", "text": "Steht auf %s%s" % (
                        m["feed_name"], ": " + m["label"] if m["label"] else "")})
        elif benign:
            verdict = "known"
        else:
            verdict = "unknown"
        for m in benign:
            if not bad:
                reasons.append({"level": "known", "text": "Bekannt als %s (%s)" % (m["label"], m["feed_name"])})
        labels = []
        for m in bad + [m for m in matches if m["category"] == "suspicious"] + benign:
            if m["label"] and m["label"] not in labels:
                labels.append(m["label"])
        return {"type": fp_type, "fp": fp, "verdict": verdict, "labels": labels,
                "matches": matches, "reasons": reasons}

    def fp_feeds_loaded(self):
        return bool(self.fps)

    @staticmethod
    def combine(assessments):
        """Gesamturteil fuer einen Alert aus den Bewertungen beider IPs."""
        glob = [a for a in assessments if a and a["global"]]
        if not glob:
            return "local"
        vs = {a["verdict"] for a in glob}
        for v in ("malicious", "suspicious", "unknown"):
            if v in vs:
                return v
        return "popular" if "popular" in vs else "known"

    def status(self):
        now = int(time.time())
        feeds = []
        for fid, f in self.feeds.items():
            m = self.meta.get(fid, {})
            last = m.get("last_success")
            feeds.append({
                "id": fid, "name": f["name"], "kind": f["kind"], "category": f.get("category"),
                "info": f.get("info", ""), "homepage": f.get("homepage"), "urls": f["urls"],
                "enabled": f["enabled"], "custom": f.get("custom", False),
                "interval_h": f["interval_h"], "entries": m.get("entries"),
                "bytes": m.get("bytes"), "last_success": last, "last_check": m.get("last_check"),
                "error": m.get("error"),
                "loaded": self._is_loaded(fid),
                "next_due": (last + f["interval_h"] * 3600) if last else now,
                "updating": self.busy == fid,
                "queued": fid in self.force,
            })
        return {"enabled": self.enabled_global, "loaded": self.loaded, "busy": self.busy,
                "feeds": feeds, "trusted_domains": len(self.services), "dir": self.dir}
