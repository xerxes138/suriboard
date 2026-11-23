"""
Suricata Dashboard - HTTPS

* erzeugt bei Bedarf ein selbstsigniertes Zertifikat (per openssl-Kommando,
  das auf Raspberry Pi OS / Debian vorhanden ist)
* liest Infos zum Zertifikat (Ablaufdatum, Fingerabdruck) fuer die Anzeige
* HTTPS-Server, der den TLS-Handshake im Arbeits-Thread macht (ein
  haengender Client blockiert so nicht die anderen)
"""

import ipaddress
import logging
import os
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("suricata-dashboard")

HANDSHAKE_TIMEOUT = 15


def local_names():
    """Hostname und lokale IPs fuer subjectAltName."""
    host = socket.gethostname() or "localhost"
    dns = {host, "localhost"}
    if "." not in host:
        dns.add(host + ".local")
    with_fqdn = socket.getfqdn()
    if with_fqdn and with_fqdn != "localhost":
        dns.add(with_fqdn)
    ips = {"127.0.0.1", "::1"}
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5).stdout
        for a in out.split():
            try:
                ip = ipaddress.ip_address(a.split("%")[0])
                if not ip.is_link_local:
                    ips.add(str(ip))
            except ValueError:
                pass
    except (OSError, subprocess.SubprocessError):
        pass
    try:  # Fallback: Adresse der Standardroute (es wird nichts gesendet)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    return host, sorted(dns), sorted(ips)


def generate_self_signed(cert_path, key_path):
    host, dns, ips = local_names()
    san = ",".join(["DNS:" + d for d in dns] + ["IP:" + i for i in ips])
    for p in (cert_path, key_path):
        os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
    old = os.umask(0o077)
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-nodes", "-sha256", "-days", "3650",
             "-keyout", key_path, "-out", cert_path,
             "-subj", "/CN=%s/O=Suricata Dashboard" % host,
             "-addext", "subjectAltName=" + san,
             "-addext", "basicConstraints=critical,CA:FALSE",
             "-addext", "keyUsage=critical,digitalSignature",
             "-addext", "extendedKeyUsage=serverAuth"],
            check=True, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        raise RuntimeError("Das Programm 'openssl' fehlt (sudo apt install openssl)")
    except subprocess.CalledProcessError as e:
        raise RuntimeError("openssl: " + (e.stderr or "").strip()[-300:])
    finally:
        os.umask(old)
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o644)
    log.info("Selbstsigniertes Zertifikat erzeugt: %s (gilt fuer %s)", cert_path, san)


def cert_info(cert_path):
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-subject", "-issuer", "-enddate",
             "-fingerprint", "-sha256", "-ext", "subjectAltName", "-nameopt", "oneline"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as e:
        return {"error": str(e)}
    if out.returncode:
        return {"error": (out.stderr or "nicht lesbar").strip()[-200:]}
    info = {}
    lines = out.stdout.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("subject="):
            info["subject"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            info["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            try:
                d = datetime.strptime(line.split("=", 1)[1].strip(), "%b %d %H:%M:%S %Y %Z")
                info["not_after"] = int(d.replace(tzinfo=timezone.utc).timestamp())
            except ValueError:
                pass
        elif "Fingerprint=" in line:
            info["fingerprint"] = line.split("=", 1)[1].strip()
        elif "Subject Alternative Name" in line and i + 1 < len(lines):
            info["names"] = [n.strip().split(":", 1)[-1] for n in lines[i + 1].split(",")]
    info["self_signed"] = info.get("subject") == info.get("issuer")
    return info


def make_context(cert_path, key_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


def prepare(cfg):
    """Zertifikat pruefen/erzeugen und SSL-Kontext liefern (wirft RuntimeError)."""
    cert, key = cfg["https_cert"], cfg["https_key"]
    if not (os.path.exists(cert) and os.path.exists(key)):
        if cfg.get("https_self_signed", True):
            generate_self_signed(cert, key)
        else:
            raise RuntimeError("Zertifikat %s oder Schluessel %s fehlt" % (cert, key))
    try:
        return make_context(cert, key)
    except (OSError, ssl.SSLError) as e:
        raise RuntimeError("Zertifikat/Schluessel nicht ladbar: %s" % e)


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        import sys
        e = sys.exc_info()[1]
        if isinstance(e, (ssl.SSLError, ConnectionError, TimeoutError, socket.timeout)):
            # Browser, die das selbstsignierte Zertifikat (noch) ablehnen, Port-Scanner ...
            log.debug("Verbindung von %s abgebrochen: %s", client_address[0], e)
            return
        super().handle_error(request, client_address)


class TLSServer(QuietServer):
    def __init__(self, addr, handler, ctx):
        self.ssl_ctx = ctx
        super().__init__(addr, handler)

    def finish_request(self, request, client_address):
        # laeuft im Thread der Verbindung
        request.settimeout(HANDSHAKE_TIMEOUT)
        tls = self.ssl_ctx.wrap_socket(request, server_side=True)
        tls.settimeout(None)
        try:
            super().finish_request(tls, client_address)
        finally:
            # shutdown_request() schliesst nur den rohen Socket; das TLS-Objekt hier aufraeumen
            try:
                tls.close()
            except OSError:
                pass


def redirect_handler(https_port):
    """Leitet alle HTTP-Anfragen auf HTTPS um."""

    class Redirect(BaseHTTPRequestHandler):
        server_version = "SuricataDashboard/1.0"

        def log_message(self, fmt, *args):
            log.debug("%s - %s", self.address_string(), fmt % args)

        def _go(self):
            host = self.headers.get("Host") or self.server.server_address[0]
            if host.startswith("["):
                host = host[: host.find("]") + 1]
            elif host.count(":") == 1:
                host = host.split(":")[0]
            port = "" if https_port == 443 else ":%d" % https_port
            self.send_response(301)
            self.send_header("Location", "https://%s%s%s" % (host, port, self.path))
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = do_HEAD = do_POST = do_DELETE = do_PUT = _go

    return Redirect
