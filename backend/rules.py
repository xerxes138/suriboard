#!/usr/bin/env python3
"""
Suricata Dashboard - own blocking rules (local.rules)

Creates drop/reject rules from alerts or signatures and manages them in the
user's own rules file (default /etc/suricata/rules/local.rules):

  sig     copy of the original rule with action drop/reject and a new local SID
  ip      block all traffic to/from one IP address
  domain  block DNS lookups, TLS (SNI) and HTTP requests for a domain and its subdomains

Rules written by the dashboard carry "metadata: created_by suricata_dashboard" and
can be disabled (commented out) or deleted from the web interface. Other lines in
the file are never touched.

Also checks suricata.yaml: an extra rules file is only loaded when it is listed
under "rule-files".
"""

import contextlib
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time

log = logging.getLogger("suricata-dashboard")

MARK = "created_by suricata_dashboard"
SID_MIN, SID_MAX = 1000000, 1999999          # range reserved for local rules
ACTIONS = ("drop", "reject")
RELOAD_MODES = ("suricatasc", "usr2", "none")
PIDFILES = ("/run/suricata.pid", "/var/run/suricata.pid", "/var/run/suricata/suricata.pid")

RE_RULE = re.compile(r"^\s*(#\s*)?(alert|drop|reject|rejectsrc|rejectdst|rejectboth|pass)\s+\S+\s+.*\(.*\)\s*$")
RE_SID = re.compile(r"(?<![\w.])sid\s*:\s*(\d+)\s*;")
RE_REV = re.compile(r"(?<![\w.])rev\s*:\s*\d+\s*;")
RE_GID = re.compile(r"(?<![\w.])gid\s*:\s*(\d+)\s*;")
RE_MSG = re.compile(r'(?<![\w.])msg\s*:\s*"((?:[^"\\]|\\.)*)"\s*;')
RE_META = re.compile(r"(?<![\w.])metadata\s*:\s*([^;]*);")
RE_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9_-]{1,63}\.)+[a-z0-9-]{1,63}$")


class RuleError(ValueError):
    pass


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def clean_text(s, limit=120):
    """Text for msg/metadata: no quotes, semicolons, backslashes or control characters."""
    s = re.sub(r'[";\\|\x00-\x1f\x7f]', " ", str(s or ""))
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit]


def norm_ip(value):
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        raise RuleError("ungültige IP-Adresse: %s" % value)
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        raise RuleError("diese Adresse lässt sich nicht sinnvoll sperren: %s" % ip)
    return str(ip)


def norm_domain(value):
    d = str(value or "").strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    if d.startswith("."):
        d = d[1:]
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        raise RuleError("ungültige Domain: %s" % value)
    if not RE_DOMAIN.match(d):
        raise RuleError("ungültige Domain: %s" % value)
    return d


def content_escape(s):
    """Suricata content: ; \" \\ | need escaping (domains contain none of them, but be safe)."""
    return "".join("|%02X|" % ord(ch) if ch in ';"\\|' else ch for ch in s)


def parse_line(line):
    """Return a dict for a rule line (also commented-out rules), else None."""
    m = RE_RULE.match(line)
    if not m:
        return None
    sid = RE_SID.search(line)
    if not sid:
        return None
    gid = RE_GID.search(line)
    msg = RE_MSG.search(line)
    meta = RE_META.search(line)
    text = line.strip()
    if m.group(1):
        text = text.lstrip("#").strip()
    return {
        "sid": int(sid.group(1)),
        "gid": int(gid.group(1)) if gid else 1,
        "action": m.group(2),
        "enabled": not m.group(1),
        "msg": msg.group(1).replace('\\"', '"') if msg else "",
        "managed": bool(meta and MARK in meta.group(1)),
        "created": _meta_value(meta.group(1), "created_at") if meta else None,
        "original_sid": _int(_meta_value(meta.group(1), "original_sid")) if meta else None,
        "target": _meta_value(meta.group(1), "sd_target") if meta else None,
        "text": text,
    }


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _meta_value(meta, key):
    for part in meta.split(","):
        bits = part.strip().split(None, 1)
        if len(bits) == 2 and bits[0] == key:
            return bits[1].strip()
    return None


# --------------------------------------------------------------------------
# suricata.yaml (minimal reader, only what we need, no PyYAML)
# --------------------------------------------------------------------------

def _yaml_scalar(v):
    v = v.split(" #", 1)[0].strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        v = v[1:-1]
    return v


def read_suricata_yaml(path):
    """Read default-rule-path and rule-files from suricata.yaml (and included files)."""
    out = {"path": path, "exists": False, "readable": False, "default_rule_path": None,
           "rule_files": [], "error": None}
    if not path:
        out["error"] = "kein Pfad angegeben"
        return out
    if not os.path.exists(path):
        out["error"] = "Datei nicht gefunden"
        return out
    out["exists"] = True
    try:
        _read_yaml_into(path, out, depth=0)
        out["readable"] = True
    except OSError as e:
        out["error"] = "nicht lesbar: %s" % e
    return out


def _read_yaml_into(path, out, depth):
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    in_list = False
    list_indent = 0
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if in_list:
            if line.startswith("- ") and indent >= list_indent:
                out["rule_files"].append(_yaml_scalar(line[2:]))
                continue
            if line == "-":
                continue
            in_list = False
        if indent == 0 and line.startswith("default-rule-path:"):
            out["default_rule_path"] = _yaml_scalar(line.split(":", 1)[1])
        elif indent == 0 and line.startswith("rule-files:"):
            rest = line.split(":", 1)[1].strip()
            if rest.startswith("["):        # rule-files: [a.rules, b.rules]
                out["rule_files"].extend(_yaml_scalar(x) for x in rest.strip("[]").split(",") if x.strip())
            else:
                in_list, list_indent = True, indent
        elif indent == 0 and (line.startswith("include:") or line.startswith("!include")) and depth < 3:
            # include: file.yaml  or  include:\n  - a.yaml
            target = _yaml_scalar(line.split(":", 1)[1]) if line.startswith("include:") else _yaml_scalar(line[8:])
            if target:
                inc = target if os.path.isabs(target) else os.path.join(os.path.dirname(path), target)
                with contextlib.suppress(OSError):
                    _read_yaml_into(inc, out, depth + 1)


def check_loaded(yaml_info, rules_file):
    """Is rules_file listed in rule-files? Returns (loaded, resolved_entries)."""
    base = yaml_info.get("default_rule_path") or "/var/lib/suricata/rules"
    resolved = []
    for entry in yaml_info.get("rule_files") or []:
        p = entry if os.path.isabs(entry) else os.path.join(base, entry)
        resolved.append(os.path.normpath(p))
    target = os.path.normpath(rules_file or "")
    loaded = False
    for p in resolved:
        if p == target:
            loaded = True
        else:
            with contextlib.suppress(OSError):
                if os.path.exists(p) and os.path.exists(target) and os.path.samefile(p, target):
                    loaded = True
    return loaded, resolved


# --------------------------------------------------------------------------
# Index of all known rules (for the original rule text and free SIDs)
# --------------------------------------------------------------------------

class RuleIndex:
    """sid -> (file, line) of all *.rules files in rules_dir plus the local file.
    Built lazily and rebuilt when a file changes."""

    def __init__(self):
        self._lock = threading.Lock()
        self._key = None
        self._sids = {}

    @staticmethod
    def _files(rules_dir, local_file):
        files = []
        if rules_dir and os.path.isdir(rules_dir):
            with contextlib.suppress(OSError):
                for fn in sorted(os.listdir(rules_dir)):
                    p = os.path.join(rules_dir, fn)
                    if fn.endswith(".rules") and os.path.isfile(p):
                        files.append(p)
        if local_file and os.path.isfile(local_file) and local_file not in files:
            files.append(local_file)
        return files

    def _ensure(self, rules_dir, local_file):
        files = self._files(rules_dir, local_file)
        key = []
        for p in files:
            with contextlib.suppress(OSError):
                st = os.stat(p)
                key.append((p, st.st_mtime_ns, st.st_size))
        key = tuple(key)
        with self._lock:
            if key == self._key:
                return
            sids = {}
            for p, _, _ in key:
                try:
                    with open(p, "rb") as f:
                        for no, raw in enumerate(f, 1):
                            if b"sid" not in raw:
                                continue
                            m = RE_SID.search(raw.decode("utf-8", "replace"))
                            if m:
                                sids.setdefault(int(m.group(1)), (p, no))
                except OSError as e:
                    log.warning("Regeldatei %s nicht lesbar: %s", p, e)
            self._sids, self._key = sids, key

    def files(self, rules_dir, local_file):
        self._ensure(rules_dir, local_file)
        return [k[0] for k in self._key or ()]

    def has(self, rules_dir, local_file, sid):
        self._ensure(rules_dir, local_file)
        return sid in self._sids

    def find(self, rules_dir, local_file, sid):
        """Original rule text (also from commented-out lines) or None."""
        self._ensure(rules_dir, local_file)
        hit = self._sids.get(sid)
        if not hit:
            return None
        path, no = hit
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    if i == no:
                        r = parse_line(line)
                        if r and r["sid"] == sid:
                            r["file"] = path
                            r["line"] = no
                            return r
                        return None
        except OSError:
            return None
        return None

    def count(self):
        return len(self._sids)

    def next_sid(self, rules_dir, local_file, taken=()):
        self._ensure(rules_dir, local_file)
        used = set(self._sids) | set(taken)
        local_max = max([s for s in used if SID_MIN <= s <= SID_MAX] or [SID_MIN - 1])
        sid = max(local_max + 1, SID_MIN)
        while sid in used:
            sid += 1
        if sid > SID_MAX:
            sid = SID_MIN
            while sid in used and sid <= SID_MAX:
                sid += 1
        if sid > SID_MAX:
            raise RuleError("kein freier SID im lokalen Bereich %d–%d" % (SID_MIN, SID_MAX))
        return sid


# --------------------------------------------------------------------------
# Building rules
# --------------------------------------------------------------------------

def _meta(target):
    return "metadata:%s, created_at %s, sd_target %s;" % (MARK, time.strftime("%Y_%m_%d"), target)


def build(kind, action, sid, note="", original=None, ip=None, domain=None):
    """Returns a list of (sid, rule_text). Domain rules need several SIDs (DNS, TLS, HTTP)."""
    if action not in ACTIONS:
        raise RuleError("Aktion muss drop oder reject sein")
    note = clean_text(note, 80)
    suffix = (" - " + note) if note else ""
    if kind == "sig":
        if not original:
            raise RuleError("Originalregel nicht gefunden")
        text = original["text"]
        text = re.sub(r"^\s*(alert|drop|reject|rejectsrc|rejectdst|rejectboth|pass)\b", action, text, count=1)
        text = RE_SID.sub("sid:%d;" % sid, text, count=1)
        text = RE_GID.sub("", text)
        if RE_REV.search(text):
            text = RE_REV.sub("rev:1;", text, count=1)
        else:
            text = text.rstrip()[:-1].rstrip() + " rev:1;)"
        old_msg = RE_MSG.search(text)
        new_msg = clean_text("SD %s: %s%s" % (action, original["msg"] or "SID %d" % original["sid"], suffix), 200)
        if old_msg:
            text = text[:old_msg.start()] + 'msg:"%s";' % new_msg + text[old_msg.end():]
        else:
            text = text.replace("(", '(msg:"%s"; ' % new_msg, 1)
        meta = RE_META.search(text)
        mark = "%s, created_at %s, original_sid %d" % (MARK, time.strftime("%Y_%m_%d"), original["sid"])
        if meta:   # ours first, so created_at/original_sid are found before the original values
            text = text[:meta.start()] + "metadata:%s, %s;" % (mark, meta.group(1).strip().rstrip(",")) + text[meta.end():]
        else:
            text = text.rstrip()[:-1].rstrip() + " metadata:%s;)" % mark
        return [(sid, text)]
    if kind == "ip":
        ip = norm_ip(ip)
        msg = clean_text("SD %s: IP %s%s" % (action, ip, suffix), 200)
        return [(sid, '%s ip any any <> %s any (msg:"%s"; sid:%d; rev:1; %s)' % (action, ip, msg, sid, _meta(ip)))]
    if kind == "domain":
        d = norm_domain(domain)
        c = content_escape("." + d)
        out = []
        for i, (proto, buf, what) in enumerate((("dns", "dns.query", "DNS"), ("tls", "tls.sni", "TLS"),
                                                 ("http", "http.host", "HTTP"))):
            msg = clean_text("SD %s: %s %s%s" % (action, what, d, suffix), 200)
            out.append((sid + i, '%s %s any any -> any any (msg:"%s"; %s; dotprefix; content:"%s"; endswith; '
                                 'nocase; sid:%d; rev:1; %s)' % (action, proto, msg, buf, c, sid + i, _meta(d))))
        return out
    raise RuleError("unbekannte Regelart: %s" % kind)


# --------------------------------------------------------------------------
# Rules file
# --------------------------------------------------------------------------

def file_status(path):
    info = {"path": path, "exists": False, "writable": False, "dir_writable": False, "error": None}
    if not path or not os.path.isabs(path):
        info["error"] = "Pfad muss absolut sein"
        return info
    if not path.endswith(".rules"):
        info["error"] = "Dateiname muss auf .rules enden"
        return info
    d = os.path.dirname(path)
    info["dir_writable"] = os.path.isdir(d) and os.access(d, os.W_OK)
    if os.path.isdir(path):
        info["error"] = "das ist ein Ordner"
    elif os.path.exists(path):
        info["exists"] = True
        info["writable"] = os.access(path, os.W_OK)
        if not info["writable"]:
            info["error"] = "keine Schreibrechte für den Dashboard-Prozess"
    elif not os.path.isdir(d):
        info["error"] = "Ordner %s existiert nicht" % d
    elif not info["dir_writable"]:
        info["error"] = "Datei fehlt und der Ordner ist nicht beschreibbar"
    return info


def read_rules(path):
    if not path or not os.path.isfile(path):
        return []
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for no, line in enumerate(f, 1):
            r = parse_line(line)
            if r:
                r["line"] = no
                out.append(r)
    return out


class RulesFile:
    """All changes to the rules file go through here (one lock, backup before every write)."""

    def __init__(self, backup_dir):
        self.backup_dir = backup_dir
        self.lock = threading.Lock()

    def _backup(self, path):
        if not os.path.exists(path):
            return
        with contextlib.suppress(OSError):
            os.makedirs(self.backup_dir, exist_ok=True)
            dst = os.path.join(self.backup_dir, os.path.basename(path) + ".bak")
            shutil.copyfile(path, dst)
            os.chmod(dst, 0o600)

    def _write(self, path, lines):
        """Write in place so owner, group and mode of the file stay as they are."""
        data = "".join(lines)
        if os.path.exists(path):
            with open(path, "r+", encoding="utf-8") as f:
                f.write(data)
                f.truncate()
                f.flush()
                os.fsync(f.fileno())
        else:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)

    def _lines(self, path):
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.readlines()

    def append(self, path, rules, comment):
        st = file_status(path)
        if st["error"]:
            raise RuleError("%s: %s" % (path, st["error"]))
        with self.lock:
            lines = self._lines(path)
            existing = {r["sid"] for r in (parse_line(l) for l in lines) if r}
            for sid, _ in rules:
                if sid in existing:
                    raise RuleError("SID %d steht schon in %s" % (sid, path))
            self._backup(path)
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            if comment:
                lines.append("# %s\n" % clean_text(comment, 200))
            lines.extend(text + "\n" for _, text in rules)
            self._write(path, lines)

    def modify(self, path, sid, op):
        """op: enable | disable | delete. Only for rules created by the dashboard."""
        with self.lock:
            lines = self._lines(path)
            hit = None
            for i, line in enumerate(lines):
                r = parse_line(line)
                if r and r["sid"] == sid:
                    hit = (i, r)
                    break
            if not hit:
                raise RuleError("SID %d nicht in %s gefunden" % (sid, path))
            i, r = hit
            if not r["managed"]:
                raise RuleError("SID %d wurde nicht vom Dashboard angelegt und wird hier nicht verändert" % sid)
            self._backup(path)
            if op == "delete":
                del lines[i]
                # our comment line above goes as well once no rule of its group is left below it
                if i > 0 and lines[i - 1].startswith("# SD ") and (i >= len(lines) or not parse_line(lines[i])):
                    del lines[i - 1]
            elif op == "disable":
                lines[i] = "# " + r["text"] + "\n"
            elif op == "enable":
                lines[i] = r["text"] + "\n"
            else:
                raise RuleError("unbekannte Aktion")
            self._write(path, lines)

    def restore_managed(self, path, texts):
        """Import: add managed rules whose SID is not yet in the file. Returns number added."""
        rules = [parse_line(t) for t in texts]
        rules = [r for r in rules if r and r["managed"]]
        if not rules:
            return 0
        with self.lock:
            lines = self._lines(path)
            existing = {r["sid"] for r in (parse_line(l) for l in lines) if r}
            new = [r for r in rules if r["sid"] not in existing]
            if not new:
                return 0
            st = file_status(path)
            if st["error"]:
                raise RuleError("%s: %s" % (path, st["error"]))
            self._backup(path)
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append("# SD import %s\n" % time.strftime("%Y-%m-%d %H:%M"))
            lines.extend(("" if r["enabled"] else "# ") + r["text"] + "\n" for r in new)
            self._write(path, lines)
            return len(new)


# --------------------------------------------------------------------------
# Reloading Suricata
# --------------------------------------------------------------------------

class Reloader:
    def __init__(self):
        self.lock = threading.Lock()
        self.last = None        # {"ts", "mode", "running", "ok", "message", "failed"}

    def status(self):
        return dict(self.last) if self.last else None

    def start(self, mode, local_sids=()):
        if mode not in RELOAD_MODES or mode == "none":
            self.last = {"ts": int(time.time()), "mode": "none", "running": False, "ok": None,
                         "message": "Automatisches Neuladen ist abgeschaltet. Suricata selbst neu laden, "
                                    "z. B. mit: sudo suricatasc -c reload-rules", "failed": []}
            return self.status()
        with self.lock:
            if self.last and self.last.get("running"):
                return self.status()
            self.last = {"ts": int(time.time()), "mode": mode, "running": True, "ok": None,
                         "message": "Suricata lädt die Regeln neu …", "failed": []}
        threading.Thread(target=self._run, args=(mode, set(local_sids)), name="rules-reload", daemon=True).start()
        return self.status()

    def _run(self, mode, local_sids):
        try:
            if mode == "usr2":
                res = self._usr2()
            else:
                res = self._suricatasc(local_sids)
        except Exception as e:  # noqa: never kill the thread silently
            res = {"ok": False, "message": "Fehler: %s" % e, "failed": []}
        res.update(running=False, ts=int(time.time()), mode=mode)
        self.last = res
        log.info("Regeln neu laden (%s): %s", mode, res["message"])

    @staticmethod
    def _usr2():
        for p in PIDFILES:
            with contextlib.suppress(OSError, ValueError):
                with open(p) as f:
                    pid = int(f.read().strip())
                os.kill(pid, signal.SIGUSR2)
                return {"ok": True, "failed": [],
                        "message": "Signal USR2 an Suricata (PID %d) geschickt. Ob die Regeln fehlerfrei geladen "
                                   "wurden, steht in suricata.log." % pid}
        return {"ok": False, "failed": [],
                "message": "Keine PID-Datei von Suricata gefunden (%s) oder keine Berechtigung." % ", ".join(PIDFILES)}

    @staticmethod
    def _suricatasc(local_sids):
        exe = shutil.which("suricatasc")
        if not exe:
            return {"ok": False, "failed": [],
                    "message": "suricatasc nicht gefunden. In den Einstellungen „USR2-Signal“ wählen oder Suricata "
                               "selbst neu laden."}
        try:
            p = subprocess.run([exe, "-c", "reload-rules"], capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            return {"ok": False, "failed": [], "message": "suricatasc hat nach 10 Minuten nicht geantwortet."}
        out = (p.stdout + p.stderr).strip()
        ok = p.returncode == 0 and '"return": "OK"' in out.replace("'", '"')
        if not ok:
            hint = ""
            if "socket" in out.lower() or "connect" in out.lower() or "no such file" in out.lower():
                hint = " Ist in suricata.yaml „unix-command: enabled: yes“ gesetzt?"
            return {"ok": False, "failed": [], "message": "Neu laden fehlgeschlagen: %s%s" % (out[:400] or p.returncode, hint)}
        failed = []
        with contextlib.suppress(Exception):
            q = subprocess.run([exe, "-c", "ruleset-failed-rules"], capture_output=True, text=True, timeout=60)
            txt = q.stdout
            j = json.loads(txt[txt.index("{"):]) if "{" in txt else {}
            for item in j.get("message") or []:
                rule = item.get("rule", "") if isinstance(item, dict) else str(item)
                m = RE_SID.search(rule)
                if m and (not local_sids or int(m.group(1)) in local_sids):
                    failed.append({"sid": int(m.group(1)), "rule": rule[:300]})
        if failed:
            return {"ok": False, "failed": failed,
                    "message": "Regeln neu geladen, aber %d eigene Regel(n) hat Suricata abgelehnt." % len(failed)}
        return {"ok": True, "failed": [], "message": "Suricata hat die Regeln neu geladen."}


__all__ = ["RuleError", "RuleIndex", "RulesFile", "Reloader", "build", "read_rules", "file_status",
           "read_suricata_yaml", "check_loaded", "norm_ip", "norm_domain", "ACTIONS", "RELOAD_MODES",
           "SID_MIN", "SID_MAX"]
