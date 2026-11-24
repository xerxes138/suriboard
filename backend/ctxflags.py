#!/usr/bin/env python3
"""
Suricata Dashboard - harmless marks with context

A signature can be marked as harmless as a whole (table flags) or only in a certain
context (table flag_rules), e.g. "ET INFO Packed Executable Download" only when the
peer is a known Microsoft address. Kinds of context:

  service  the peer belongs to a known update/system service ("*" = any known service)
  asn      the peer is in this autonomous system (network operator), e.g. 8075 = Microsoft
  domain   a host name of the peer is this domain or a subdomain of it
  cidr     the peer address is in this network (also works for local addresses)

Safety net: a context rule never applies when one of the alert's addresses is on a
block list or rated suspicious. Such alerts always stay visible.

The matching rule is stored per alert in alerts.ctx_flag, so all views can filter with
plain SQL. It is computed when rules change and after every ingest cycle for new and
recent alerts (host names from DNS sometimes arrive shortly after the alert).
"""

import ipaddress
import re
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS flag_rules (
    id      INTEGER PRIMARY KEY,
    gid     INTEGER NOT NULL,
    sid     INTEGER NOT NULL,
    kind    TEXT NOT NULL,
    value   TEXT NOT NULL,
    note    TEXT,
    created INTEGER
);
CREATE INDEX IF NOT EXISTS idx_flag_rules_sig ON flag_rules(gid, sid);
"""

KINDS = ("service", "asn", "domain", "cidr")
BAD = ("malicious", "suspicious")
RECHECK_SECONDS = 600          # recent alerts without a match are checked again
RE_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)*[a-z0-9-]{1,63}$")


def migrate(conn):
    conn.executescript(SCHEMA)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
    if "ctx_flag" not in cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN ctx_flag INTEGER")


def normalize(kind, value):
    """Validated, canonical value for a rule, raises ValueError."""
    v = str(value or "").strip()
    if kind == "service":
        if not v or len(v) > 80:
            raise ValueError("ungültiger Dienst")
        return v
    if kind == "asn":
        v = v.upper().removeprefix("AS")
        if not v.isdigit() or not 0 < int(v) < 2 ** 32:
            raise ValueError("ungültige AS-Nummer")
        return str(int(v))
    if kind == "domain":
        v = v.lower().strip(".")
        if v.startswith("*."):
            v = v[2:]
        if not RE_DOMAIN.match(v) or "." not in v:
            raise ValueError("ungültige Domain")
        return v
    if kind == "cidr":
        try:
            return str(ipaddress.ip_network(v, strict=False))
        except ValueError:
            raise ValueError("ungültige IP-Adresse oder ungültiges Netz")
    raise ValueError("unbekannte Art: %s" % kind)


def matches(rule, alert, reps):
    """reps: {ip: full assessment from ThreatIntel.assess_ip} for src and dest."""
    ips = [ip for ip in (alert["src_ip"], alert["dest_ip"]) if ip]
    if any((reps.get(ip) or {}).get("verdict") in BAD for ip in ips):
        return False
    kind, value = rule["kind"], rule["value"]
    if kind == "cidr":
        net = ipaddress.ip_network(value, strict=False)
        for ip in ips:
            try:
                if ipaddress.ip_address(ip) in net:
                    return True
            except ValueError:
                pass
        return False
    for ip in ips:
        r = reps.get(ip)
        if not r or not r.get("global"):
            continue
        if kind == "service":
            if value == "*" and r.get("verdict") == "known":
                return True
            if value != "*" and value.lower() in (s.lower() for s in r.get("services") or []):
                return True
        elif kind == "asn":
            if r.get("asn") and str(r["asn"].get("asn")) == value:
                return True
        elif kind == "domain":
            for n in r.get("names") or []:
                name = (n.get("name") or "").lower().rstrip(".")
                if name == value or name.endswith("." + value):
                    return True
    return False


def describe(rule):
    """Short German description (the frontend translates it)."""
    k, v = rule["kind"], rule["value"]
    if k == "service":
        return "Gegenstelle ist ein bekannter Dienst" if v == "*" else "Gegenstelle gehört zu %s" % v
    if k == "asn":
        return "Gegenstelle im Netz von AS%s" % v
    if k == "domain":
        return "Hostname der Gegenstelle endet auf %s" % v
    return "Adresse in %s" % v


class Evaluator:
    """Computes alerts.ctx_flag. assess(conn, ips) returns full IP assessments."""

    def __init__(self, assess):
        self.assess = assess
        self.last_id = 0          # 0 = full pass on the first run (e.g. after an import on the command line)

    @staticmethod
    def rules(c, gid=None, sid=None):
        sql, args = "SELECT * FROM flag_rules", []
        if sid is not None:
            sql += " WHERE gid=? AND sid=?"
            args = [gid, sid]
        out = {}
        for r in c.execute(sql + " ORDER BY id", args):
            out.setdefault((r["gid"], r["sid"]), []).append(dict(r))
        return out

    def apply(self, c, scope_sql="1", scope_args=(), gid=None, sid=None):
        """Recompute ctx_flag for the alerts in scope. Returns the number of changed alerts."""
        rules = self.rules(c, gid, sid)
        if gid is not None and sid is not None and not rules:
            cur = c.execute("UPDATE alerts SET ctx_flag=NULL WHERE gid=? AND sid=? AND ctx_flag IS NOT NULL",
                            (gid, sid))
            return cur.rowcount
        if not rules:
            return 0
        sigs = list(rules)
        changed = 0
        for i in range(0, len(sigs), 200):
            chunk = sigs[i:i + 200]
            cond = " OR ".join("(gid=? AND sid=?)" for _ in chunk)
            args = [x for s in chunk for x in s]
            rows = c.execute("SELECT id, gid, sid, src_ip, dest_ip, ctx_flag FROM alerts WHERE (%s) AND (%s)"
                             % (cond, scope_sql), args + list(scope_args)).fetchall()
            if not rows:
                continue
            reps = self.assess(c, {r["src_ip"] for r in rows} | {r["dest_ip"] for r in rows})
            updates = []
            for r in rows:
                hit = next((rule["id"] for rule in rules[(r["gid"], r["sid"])] if matches(rule, r, reps)), None)
                if hit != r["ctx_flag"]:
                    updates.append((hit, r["id"]))
            if updates:
                c.executemany("UPDATE alerts SET ctx_flag=? WHERE id=?", updates)
                changed += len(updates)
        # alerts of signatures whose rules were all deleted
        c.execute("UPDATE alerts SET ctx_flag=NULL WHERE ctx_flag IS NOT NULL AND "
                  "ctx_flag NOT IN (SELECT id FROM flag_rules)")
        return changed

    def after_flush(self, c):
        """Called by the ingest thread: new alerts plus recent ones that did not match yet."""
        top = c.execute("SELECT COALESCE(MAX(id), 0) m FROM alerts").fetchone()["m"]
        if not c.execute("SELECT 1 FROM flag_rules LIMIT 1").fetchone():
            self.last_id = top
            return 0
        with c:
            n = self.apply(c, "id > ? OR (ts >= ? AND ctx_flag IS NULL)",
                           (self.last_id, int(time.time()) - RECHECK_SECONDS))
        self.last_id = top
        return n
