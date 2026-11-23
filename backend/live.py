"""
Live-Ansicht: haelt die gerade aktiven Verbindungen im Speicher.

Der Ingestor reicht jedes eve.json-Event (und jeden fast.log-Alert) an
LiveTracker.feed weiter. Solange jemand die Live-Ansicht offen hat (Abfrage in
den letzten LIVE_TIMEOUT Sekunden), liest der Ingestor jede Sekunde statt nur
alle poll_interval_seconds.

Knoten: lokale Geraete (private Adressen) und ihre Gegenstellen. Geraetenamen
und MAC-Adressen ergaenzt die API (Tabellen hosts/macs/device_names).
Kante:  Geraet <-> Gegenstelle, zusammengefasst ueber alle Ports/Flows.
"""

import ipaddress
import threading
import time
from collections import deque

from threatintel import is_global, norm_domain

LIVE_TIMEOUT = 20        # s ohne Abfrage -> Live-Modus aus
MAX_AGE = 300            # s: aeltere Events (z. B. beim Nachlesen) ignorieren
KEEP = 600               # s: so lange bleiben Verbindungen hoechstens im Speicher
ALERT_HOLD = 120         # s: Verbindungen mit Alert bleiben mindestens so lange sichtbar
MAX_CONNS = 5000
MAX_PER_DEVICE = 40
MAX_EDGES = 400

# Event-Typen, die als Anwendungsprotokoll taugen
APP_EVENTS = {"dns", "tls", "http", "http2", "ssh", "smb", "ftp", "smtp", "quic", "dhcp", "ntp",
              "snmp", "sip", "rdp", "rfb", "mqtt", "krb5", "nfs", "tftp", "ike", "dnp3",
              "modbus", "pgsql", "bittorrent-dht", "websocket", "ldap", "mdns"}
WELL_KNOWN = {
    "224.0.0.251": "mDNS", "ff02::fb": "mDNS", "239.255.255.250": "SSDP", "ff02::c": "SSDP",
    "224.0.0.252": "LLMNR", "ff02::1:3": "LLMNR", "255.255.255.255": "Broadcast",
    "224.0.0.1": "Alle Hosts", "ff02::1": "Alle Hosts", "224.0.0.22": "IGMP",
    "ff02::16": "MLD", "ff02::2": "Router", "ff02::1:2": "DHCPv6",
}

_kind_cache = {}


def addr_kind(ip):
    """'device' (lokale Unicast-Adresse), 'group' (Multicast/Broadcast) oder 'remote'."""
    k = _kind_cache.get(ip)
    if k is not None:
        return k
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.is_multicast or ip in WELL_KNOWN or (a.version == 4 and ip.endswith(".255")):
        k = "group"
    elif a.is_unspecified:
        k = None
    elif is_global(ip):
        k = "remote"
    else:
        k = "device"
    if len(_kind_cache) > 50000:
        _kind_cache.clear()
    _kind_cache[ip] = k
    return k


def _client_first(src, dst, sp, dp):
    """Richtung so drehen, dass src der Client ist (Antworten sind oft umgedreht protokolliert)."""
    if sp is not None and dp is not None and (sp < 1024 <= dp or (sp, dp) in ((67, 68), (547, 546))):
        return dst, src, dp, sp
    return src, dst, sp, dp


def _port(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


class Conn:
    __slots__ = ("device", "peer", "dir", "first", "last", "bytes", "flows", "events",
                 "services", "names", "queries", "alerts", "alert_last", "open")

    def __init__(self, device, peer, d, now):
        self.device, self.peer, self.dir = device, peer, d
        self.first = self.last = now
        self.bytes = self.flows = self.events = 0
        self.services = {}     # "TLS 443" -> zuletzt gesehen
        self.names = {}        # SNI/HTTP-Host dieser Verbindung -> zuletzt gesehen
        self.queries = {}      # DNS-Anfragen ueber diese Verbindung
        self.alerts = {}       # sid -> dict
        self.alert_last = 0
        self.open = True       # False sobald ein flow-Event das Ende meldet


def _trim(d, n):
    if len(d) > n:
        for k in sorted(d, key=d.get)[:len(d) - n]:
            del d[k]


class LiveTracker:
    def __init__(self, alerts_from_eve=False):
        self.lock = threading.Lock()
        self.conns = {}
        self.names = {}        # globale IP -> {hostname: zuletzt gesehen}
        self.last_request = 0
        self.alerts_from_eve = alerts_from_eve
        self.rate = deque(maxlen=30)   # (zeit, events) fuer Events/s
        self.counter = 0
        self.rep_cache = {}

    # --- Zustand ---------------------------------------------------------------

    def active(self):
        return time.time() - self.last_request < LIVE_TIMEOUT

    # --- Einspeisen (aus dem Ingest-Thread) ------------------------------------

    def tick(self, n):
        """Am Ende jedes Ingest-Zyklus: Rate merken und aufraeumen."""
        now = time.time()
        with self.lock:
            self.rate.append((now, self.counter))
            if len(self.conns) > MAX_CONNS or n:
                self._expire(now)

    def _expire(self, now):
        old = [k for k, c in self.conns.items() if now - max(c.last, c.alert_last) > KEEP]
        for k in old:
            del self.conns[k]
        if len(self.conns) > MAX_CONNS:
            for k in sorted(self.conns, key=lambda k: self.conns[k].last)[:len(self.conns) - MAX_CONNS]:
                del self.conns[k]
        if len(self.names) > 20000:
            self.names.clear()

    def name(self, ip, name):
        name = norm_domain(name)
        if not ip or not name or not is_global(ip):
            return
        with self.lock:
            d = self.names.setdefault(ip, {})
            d[name] = time.time()
            _trim(d, 8)

    def feed(self, ev, t):
        """Ein eve-Event. t = Zeitpunkt des Events (bei flow: Flow-Ende)."""
        now = time.time()
        if now - t > MAX_AGE:
            return
        et = ev.get("event_type")
        src, dst = ev.get("src_ip"), ev.get("dest_ip")
        if not src or not dst or et in ("stats", "netflow"):
            return
        sp, dp = _port(ev.get("src_port")), _port(ev.get("dest_port"))
        src, dst, sp, dp = _client_first(src, dst, sp, dp)
        ks, kd = addr_kind(src), addr_kind(dst)
        if ks == "device":
            device, peer, port, d = src, dst, dp, ("lan" if kd == "device" else "out")
        elif kd == "device":
            device, peer, port, d = dst, src, dp, "in"   # Port des lokalen Dienstes
        else:
            return  # Durchgangsverkehr ohne lokales Geraet
        if kd is None and d != "in":
            return
        with self.lock:
            self.counter += 1
            key = (device, peer)
            c = self.conns.get(key)
            if c is None:
                c = self.conns[key] = Conn(device, peer, d, now)
            c.last = now
            c.events += 1
            proto = ev.get("proto") or ""
            app = ev.get("app_proto")
            if not app or app in ("failed", "unknown"):
                app = et if et in APP_EVENTS else None
            label = (app or proto or "?").upper()
            if port is not None and proto in ("TCP", "UDP", "SCTP"):
                label += " " + str(port)
            c.services[label] = now
            _trim(c.services, 6)
            if et == "flow":
                f = ev.get("flow") or {}
                c.flows += 1
                c.bytes += int(f.get("bytes_toserver") or 0) + int(f.get("bytes_toclient") or 0)
                c.open = False
            else:
                c.open = True
            if et == "tls":
                self._conn_name(c, (ev.get("tls") or {}).get("sni"), now)
            elif et == "http":
                self._conn_name(c, (ev.get("http") or {}).get("hostname"), now)
            elif et == "dns":
                dns = ev.get("dns") or {}
                q = dns.get("rrname")
                if not q:
                    qs = dns.get("queries") or []
                    q = qs[0].get("rrname") if qs and isinstance(qs[0], dict) else None
                q = norm_domain(q)
                if q:
                    c.queries[q] = now
                    _trim(c.queries, 6)
            elif et == "alert":
                self._conn_name(c, (ev.get("tls") or {}).get("sni") or (ev.get("http") or {}).get("hostname"), now)
                a = ev.get("alert") or {}
                self._alert(c, int(a.get("signature_id") or 0), a.get("signature") or "",
                            int(a.get("severity") or 3), a.get("action") or "allowed",
                            primary=self.alerts_from_eve, now=now)

    def _conn_name(self, c, name, now):
        name = norm_domain(name)
        if name:
            c.names[name] = now
            _trim(c.names, 4)

    def _alert(self, c, sid, sig, sev, action, primary, now):
        a = c.alerts.get(sid)
        if a is None:
            if len(c.alerts) >= 6:
                return
            a = c.alerts[sid] = {"sid": sid, "signature": sig, "severity": sev,
                                 "action": action, "count": 0}
        if primary or not a["count"]:
            a["count"] += 1
        a["last"] = now
        if action and action != "allowed":
            a["action"] = action
        c.alert_last = now

    def feed_fast_alert(self, a):
        """Alert aus fast.log (nur wenn fast.log die Alert-Quelle ist)."""
        now = time.time()
        if now - a["ts"] > MAX_AGE or not a.get("src_ip") or not a.get("dest_ip"):
            return
        src, dst = a["src_ip"], a["dest_ip"]
        src, dst, _, _ = _client_first(src, dst, _port(a.get("src_port")), _port(a.get("dest_port")))
        ks, kd = addr_kind(src), addr_kind(dst)
        if ks == "device":
            device, peer, d = src, dst, ("lan" if kd == "device" else "out")
        elif kd == "device":
            device, peer, d = dst, src, "in"
        else:
            return
        with self.lock:
            key = (device, peer)
            c = self.conns.get(key)
            if c is None:
                c = self.conns[key] = Conn(device, peer, d, now)
                if a.get("proto"):
                    c.services[a["proto"].upper()] = now
            c.last = now
            self._alert(c, a["sid"], a["signature"], a["severity"], a.get("action"),
                        primary=not self.alerts_from_eve, now=now)

    # --- Abfrage (aus dem API-Thread) ------------------------------------------

    def events_per_second(self):
        if len(self.rate) < 2:
            return 0
        (t0, n0), (t1, n1) = self.rate[0], self.rate[-1]
        return round((n1 - n0) / (t1 - t0), 1) if t1 > t0 else 0

    def snapshot(self, hold, alerts_only=False, show_lan=True, show_groups=True):
        now = time.time()
        self.last_request = now
        with self.lock:
            picked = []
            for c in self.conns.values():
                age = now - c.last
                has_alert = bool(c.alerts) and now - c.alert_last < max(hold, ALERT_HOLD)
                if age > hold and not has_alert:
                    continue
                if alerts_only and not has_alert:
                    continue
                kind = addr_kind(c.peer)
                if (c.dir == "lan" and not show_lan) or (kind == "group" and not show_groups):
                    continue
                picked.append((has_alert, c))
            # pro Geraet begrenzen: Alerts zuerst, dann die neuesten
            picked.sort(key=lambda x: (not x[0], -x[1].last))
            per_dev, edges, hidden = {}, [], {}
            for has_alert, c in picked:
                n = per_dev.get(c.device, 0)
                if (n >= MAX_PER_DEVICE or len(edges) >= MAX_EDGES) and not has_alert:
                    hidden[c.device] = hidden.get(c.device, 0) + 1
                    continue
                per_dev[c.device] = n + 1
                edges.append({
                    "id": c.device + ">" + c.peer, "device": c.device, "peer": c.peer, "dir": c.dir,
                    "first": int(c.first), "last": round(c.last, 1), "open": c.open,
                    "bytes": c.bytes, "flows": c.flows, "events": c.events,
                    "services": sorted(c.services, key=c.services.get, reverse=True),
                    "names": sorted(c.names, key=c.names.get, reverse=True),
                    "queries": sorted(c.queries, key=c.queries.get, reverse=True),
                    "alerts": sorted((dict(a) for a in c.alerts.values() if now - a["last"] < max(hold, ALERT_HOLD)),
                                     key=lambda a: a["severity"]),
                })
            nodes = {}
            for e in edges:
                for ip in (e["device"], e["peer"]):
                    if ip in nodes:
                        continue
                    kind = addr_kind(ip)
                    n = {"id": ip, "kind": kind}
                    if kind == "group":
                        n["name"] = WELL_KNOWN.get(ip) or ("Broadcast" if ip.endswith(".255") else "Multicast")
                    else:
                        n["names"] = sorted(self.names.get(ip, {}), key=self.names[ip].get,
                                            reverse=True) if ip in self.names else []
                    nodes[ip] = n
            for ip, cnt in hidden.items():
                if ip in nodes:
                    nodes[ip]["hidden"] = cnt
            return {
                "now": now, "hold": hold, "eps": self.events_per_second(),
                "total": len(picked), "nodes": list(nodes.values()), "edges": edges,
            }
