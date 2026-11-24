# Suricata Dashboard

A lightweight web dashboard for Suricata (IPS/IDS) on a Raspberry Pi, similar in spirit to Pi-hole.

- **Backend:** Python 3, standard library only (no `pip install`). It reads `eve.json` and `fast.log` incrementally every few seconds, aggregates the data in SQLite and serves a JSON API.
- **Frontend:** React (with htm instead of JSX) and Chart.js. All libraries are bundled in `frontend/vendor/`, so there is **no build step**. Only the Pi itself needs internet access, to download threat feeds (optional, see below).
- **Language:** the web interface is in German. UI labels are quoted below in German with an English translation where it helps.

## Features

- **Overview („Übersicht“):** connections over time, stacked by application protocol (tls, dns, quic …) or transport protocol (TCP/UDP), switchable between flows and bytes. Plus key figures, an alert timeline and top lists (clients, destinations, ports, DNS queries, TLS SNI, HTTP hosts).
- **Alerts** (from `fast.log` or eve.json): a filterable list (search, IP, SID, blocked only) with action (blocked / would block / allowed) and severity.
- **Signatures („Signaturen“):** alerts grouped by rule (SID), with hit count, example connections and first-seen time. Signatures that appear for the first time within the last 24 h get a **NEU** (new) badge.
- **Mark as harmless („Harmlos“):** one click (with an optional note) hides the SID everywhere, including future hits, e.g. apt updates or Discord. What is left is new or potentially dangerous. The mark can be removed at any time.
- **Block („Sperren …“):** create a Suricata drop/reject rule straight from an alert or a signature, written to your own rules file (e.g. `local.rules`). See [Own blocking rules](#own-blocking-rules-localrules).
- **Alert details with eve.json context:** clicking an alert („Details“ or the signature) shows what eve.json contains around the alert:
  - **This connection:** all events with the same flow ID or the same IPs, ports and protocol (alert, flow, tls, http, fileinfo …).
  - **Name resolution:** DNS answers for the IPs involved. Host names (from DNS, TLS SNI and HTTP) are shown right next to each IP.
  - **Other events between the two hosts** and **other peers** of the IPs, to find further affected devices.
  - The time window can be set from ±1 min to −30/+60 min. Every event can be expanded and copied as JSON.
- **Copy to clipboard:** the ⧉ icon next to every IP copies it (alert list, signatures, details). The details also offer „Beide IPs“ (both IPs), „Zusammenfassung“ (alert as text), SID and flow ID.
- **Reputation (threat feeds):** public block lists are downloaded automatically and stored in `data/feeds/`. Every alert gets a rating of the external IP, so false positives such as Windows Update can be told apart from real hits quickly:
  - **⚠ Blockliste** (red, block list): the IP is on Spamhaus DROP, Feodo Tracker or ET Compromised, or one of its host names is on the HaGeZi Threat Intelligence list.
  - **! auffällig** (orange, suspicious): the IP is a known scanner/attacker (IPsum, CINS Army, blocklist.de) or a Tor exit node.
  - **✓ bekannter Dienst** (green, known service): a host name of the IP belongs to an update or system service (Windows Update, Microsoft Defender, Apple, Debian, Ubuntu, Raspberry Pi, Mozilla, Steam …) and there is no block list hit. Very likely a false positive.
  - **verbreitet** (common): host name is in the Tranco top 100,000. Only a hint.
  - **unbekannt** (unknown): only the network operator is shown (e.g. "AS8075 Microsoft", from iptoasn.com).

  Host names come from DNS answers, TLS SNI and HTTP Host in eve.json. The dashboard remembers which names belong to which IP while reading.
  - The **alert list** has a reputation column and a filter, e.g. "hide known services" or "block list hits only".
  - The **details** of an alert show the rating with its reasons, network operator and all host names.
  - On the **overview**, a tile counts open alerts with a block list hit.
  - The **Threat-Feeds** tab shows the state of every feed and has a lookup for single IPs or domains. Feeds can be disabled or refreshed there.
- **Live view („Live“):** shows the devices on the network and their current connections as a graph, updated every second. The view is off until you start it with the switch.
  - Blue circles are local devices. The name comes from DHCP, otherwise the IP is shown; the number inside is the number of connections. The small dots are the peers. Their colour shows the reputation, the label shows domain, protocol/port and network operator. Purple diamonds are multicast/broadcast (mDNS, SSDP …).
  - On an alert, device and peer get a pulsing red ring and the signature is shown at the dot. Such connections stay visible for at least 2 minutes.
  - After the last activity a connection stays for the **hold time** (10 s to 5 min) and then fades out, so the graph does not flicker. New activity makes the edge light up briefly. Dashed edges are incoming connections.
  - Edges show what is happening: for DNS the most recently queried domain (`DNS example.org +3`), for TLS and HTTP the requested host name (SNI or Host header). A new request is highlighted in blue for a moment. When space is tight, edge labels are hidden; hovering or clicking a dot shows the labels of its edges. If the same name is already shown at the target dot, it is not repeated on the edge.
  - Clicking a dot opens its details: connections, services, host names, DNS queries, alerts and reputation. Dots can be dragged; zoom with the mouse wheel or +/−; ⤢ fits the view again.
  - Filters: only connections with alerts, show/hide LAN-internal connections and multicast/broadcast.
- **Devices („Geräte“):** your own names for local devices. They appear in alerts, top lists, alert details and the live view, where a device can also be named directly in the detail panel.
  - If the **MAC address** is known, the name is tied to it. It survives a new IP from DHCP and applies to all of the device's addresses, including IPv6. Without a MAC the name is tied to the IP.
  - MAC addresses come from the `ether` field in eve.json (set `ethernet: yes` for the `eve-log` in `suricata.yaml`, Suricata 7+) and from DHCP events, which also provide the host name the device reports itself. That name is shown as long as no own name is set.
  - Priority: name of the MAC > name of the IP > DHCP host name.
  - Devices can also be added by hand via MAC or IP before they first appear.
- **Anomalies („Anomalien“):** the dashboard learns the normal behaviour of every local device and warns about significant deviations, e.g. data exfiltration, scans, new destination countries or services. See [Anomaly detection](#anomaly-detection).
- **Fingerprints:** all TLS/QUIC fingerprints seen (JA3, JA3S, JA4, JA4S), checked against public lists. See [TLS fingerprints](#tls-fingerprints-ja3--ja4).
- **Status:** read progress of the log files, database size, event types.
- **Settings („Einstellungen“):** change the paths to `eve.json` and `fast.log`, the alert source and the rules paths in the browser, manage users, enable HTTPS, export/import user data (see [Backup, restore and update](#backup-restore-and-update)).
- **Login:** like Pi-hole, the dashboard is password protected. Any number of users with the role **Administrator** or **Nur lesen** (read only). See [Login and users](#login-and-users).
- **HTTPS** with an automatically generated certificate or your own (e.g. Let's Encrypt), see [HTTPS](#https).
- Light and dark mode, automatic refresh every 30 s, works on phones.

## Installation on the Raspberry Pi

```bash
# copy the folder to the Pi, e.g.:
scp -r suricata-dashboard pi@raspberrypi:/tmp/
ssh pi@raspberrypi
sudo mv /tmp/suricata-dashboard /opt/

# test run (sudo for read access to /var/log/suricata)
cd /opt/suricata-dashboard
sudo ./start.sh
```

Then open it in a browser on another machine: **http://<pi-ip>:8080**

On first start the dashboard creates the user **admin** with a random password (like Pi-hole does on installation). The password is printed to the log and stored in `data/initial-admin-password.txt`:

```bash
sudo cat /opt/suricata-dashboard/data/initial-admin-password.txt
# or set your own right away:
sudo ./users.sh passwd admin
```

After the first login with the random password the dashboard asks for a new password and deletes the file.

The only requirement is `python3`, which is preinstalled on Raspberry Pi OS. Minimum versions: Python 3.9 and SQLite 3.24.

### Run as a service (starts automatically)

```bash
sudo cp /opt/suricata-dashboard/suricata-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now suricata-dashboard
journalctl -u suricata-dashboard -f      # follow the log
```

If the dashboard should not run as root, set `User=pi` and `SupplementaryGroups=adm` in the unit. That group must be allowed to read the logs; check with `ls -l /var/log/suricata`. Note that writing to `/etc/suricata/rules/local.rules` and reloading Suricata (see [Own blocking rules](#own-blocking-rules-localrules)) then needs extra permissions.

## Log file paths

If the logs are not in `/var/log/suricata`, change the paths in the dashboard under **Einstellungen** (settings):

- Input fields for `eve.json` and `fast.log`. While typing, the dashboard checks whether the file exists and is readable.
- **Dateien automatisch suchen** (search files): searches common locations (`/var/log`, `/opt`, `/home`, `/mnt`, `/media`, `/srv`, `/data` …) up to 4 levels deep.
- **Speichern** (save): applies the new paths immediately, without a restart, and writes them to `data/settings.json`.

The correct path is in `/etc/suricata/suricata.yaml` under `default-log-dir`. If the dashboard cannot find a log file, it shows a notice at the top with a button to fix the paths.

## Own blocking rules (local.rules)

Alerts and signatures have a **Sperren …** (block) button for administrators. It opens a dialog that creates a rule for your own rules file and can tell Suricata to reload its rules right away. Three kinds of rules are available:

| Kind | Rule |
|---|---|
| **Signatur blockieren** (block signature) | A copy of the original rule with action `drop` or `reject`, a new SID from the local range (1000000–1999999) and `rev:1`. The original rule is looked up by its SID in all `*.rules` files of the rules directory. The original rule stays as it is and keeps alerting; the copy blocks in addition. |
| **IP-Adresse sperren** (block IP) | `drop ip any any <> <IP> any`: all traffic from and to the address. External addresses are preselected; for a local address the dialog warns that the device loses all connectivity. |
| **Domain sperren** (block domain) | Three rules (DNS query, TLS SNI, HTTP Host) with `dotprefix; content:".example.com"; endswith; nocase`, so the domain and all of its subdomains are blocked. Domain suggestions come from the host names known for the IPs of the alert. |

- **drop** discards the packets silently; **reject** also sends a TCP reset or ICMP error, so programs fail fast instead of waiting for a timeout.
- The dialog shows a preview of the exact rule text before anything is written.
- Rules created by the dashboard carry `metadata: created_by suricata_dashboard` plus a comment line with date and reason. Only these rules can be disabled (commented out) or deleted in the dashboard; other lines in the file are never changed.
- The **Signaturen** tab lists your own rules („Eigene Blockier-Regeln“) with buttons to disable, enable and delete them and to reload Suricata. Signatures with an own rule get a badge.
- Before every change, a copy of the rules file is saved as `data/local.rules.bak`.
- Your own rules are part of the user data export and the automatic backups. On import, missing rules are appended (existing lines are never touched).

**Settings („Einstellungen → Suricata-Regeln“):**

| Setting | Default | Purpose |
|---|---|---|
| Rules directory | `/var/lib/suricata/rules` | Where the official/external rules live (suricata-update writes `suricata.rules` here). Used to look up the original rule text. |
| Own rules file | `/etc/suricata/rules/local.rules` | The file the dashboard writes to. Must end in `.rules`. It is created if missing. |
| suricata.yaml | `/etc/suricata/suricata.yaml` | Only read, to check whether your rules file is actually loaded. |
| Reload | `suricatasc` | `suricatasc` runs `suricatasc -c reload-rules` and then reports any rules Suricata rejected (`ruleset-failed-rules`). `usr2` sends SIGUSR2 to the Suricata process (errors only show up in `suricata.log`). `none` leaves reloading to you. |

**Important: Suricata only loads rule files listed under `rule-files` in `suricata.yaml`.** If your rules file is missing there, the dashboard shows a warning with the snippet to add:

```yaml
rule-files:
  - suricata.rules
  - /etc/suricata/rules/local.rules
```

Relative names are resolved against `default-rule-path` (usually `/var/lib/suricata/rules`), so use the full path for a file in `/etc/suricata/rules`. suricata-update does not modify `suricata.yaml`, so the entry stays. Restart Suricata once after adding it (`sudo systemctl restart suricata`).

**Further requirements and limits:**
- `drop` and `reject` only take effect when Suricata runs as an **IPS** (inline, e.g. with NFQUEUE or AF_PACKET in IPS mode). In pure IDS mode these rules only generate alerts. The dashboard shows a hint as long as it has never seen a blocked alert.
- Reloading with `suricatasc` needs the unix socket (`unix-command: enabled: yes` in `suricata.yaml`, the default on Debian/Raspberry Pi OS). Writing the rules file and reloading need root, which is the default in the provided systemd unit.
- Reloading a large rule set can take a while on a Pi. The dashboard runs it in the background and shows the result.
- Blocking an IP of a CDN (Cloudflare, Akamai …) can block many unrelated sites. Prefer blocking a domain or a signature in that case.

## Login and users

Without logging in you only see the login page; all pages and API calls are locked.

| Role | May |
|---|---|
| **Administrator** | everything: mark alerts as harmless, create blocking rules, name devices, toggle threat feeds, settings, manage users, HTTPS |
| **Nur lesen** (read only) | view all data but change nothing. The settings tab is hidden. |

- **Manage users:** tab **Einstellungen → Benutzer**: add, change role, set a new password (optionally forcing a change at next login), log out, delete. The last administrator can neither be deleted nor demoted.
- **Own password:** click the user name at the top right → „Passwort ändern“ (change password). All other sessions of that account are ended.
- **Sessions:** without „Angemeldet bleiben“ (stay logged in) a session expires after 12 h of inactivity, with it after 30 days. The cookie is `HttpOnly` and `SameSite=Strict`, plus `Secure` with HTTPS.
- **Protection against password guessing:** after 5 failed attempts the IP is locked for 30 s; every further lock doubles (at most 15 min). Failed attempts are logged.
- **Passwords** are stored as PBKDF2-SHA256 (200,000 iterations, salted) in `data/suricata.db`. The file is therefore only readable by its owner.

**On the command line** (e.g. if you forgot the password):

```bash
cd /opt/suricata-dashboard
sudo ./users.sh list                     # list users
sudo ./users.sh passwd admin             # set password (creates the user if missing)
sudo ./users.sh add anna --role viewer   # add user (admin or viewer)
sudo ./users.sh role anna admin          # change role
sudo ./users.sh del anna                 # delete user
sudo ./users.sh logout-all               # end all sessions
```

If you do not want a login (e.g. because a reverse proxy handles it), set `"auth": false` in `config.json`. Then everyone on the network has full access, and the dashboard shows a warning at the top.

## HTTPS

Under **Einstellungen → HTTPS**, turn on „HTTPS verwenden“ (use HTTPS) and click „Speichern und neu starten“ (save and restart). The dashboard

1. creates a **self-signed certificate** in `data/tls/` (valid for 10 years, for the host name, `<hostname>.local` and all IPs of the Pi; needs the `openssl` program, present on Raspberry Pi OS),
2. restarts itself and then runs at **https://<pi-ip>:8443**,
3. redirects `http://<pi-ip>:8080` there automatically (can be turned off).

Because the certificate is self-signed, the browser warns on the first visit ("connection not private"). Choose **Advanced → Proceed** once. To be sure, compare the SHA-256 fingerprint in the browser with the one in the settings. If the Pi's IP changes, „Zertifikat neu erzeugen“ (regenerate certificate) creates a matching one.

**Your own certificate** (e.g. Let's Encrypt or your own CA) goes into `config.json`:

```json
"https": true,
"https_cert": "/etc/letsencrypt/live/pi.example.org/fullchain.pem",
"https_key": "/etc/letsencrypt/live/pi.example.org/privkey.pem",
"https_self_signed": false
```

If HTTPS cannot be set up at start (certificate missing or broken), the dashboard keeps running unencrypted on `listen_port` for safety. The reason is shown in the log and in the settings, so you do not lock yourself out.

To use ports 443/80 instead of 8443/8080: `"https_port": 443, "listen_port": 80`. This works when the service runs as root (the default in the provided unit).

## Anomaly detection

The dashboard builds a behaviour profile for every device on the local network. After a learning phase it warns when a device deviates significantly. It does not use an "AI" model but simple rules: every warning can be explained with concrete numbers ("sent 200 MB in one hour, previously at most 25 KB").

**What is observed** (from `flow`, `dns` and `tls` events):
- per hour: connections, bytes sent and received, external peers, local devices contacted, distinct destination ports, DNS queries
- what a device "knows": destination ports on the internet, protocols, destination countries (via the IP→network operator table), domains (from DNS and TLS SNI), services used in the LAN and services reachable from outside

A device is its MAC address if known and not shared by several IPs, otherwise its IPv4 address. That way the profile survives a new IP from DHCP. IPv6 addresses without a known MAC are ignored because privacy addresses change daily.

**Learning phase:** `anomaly_learning_days` days (default 7) since first seen, including at least 3 active days. The „Anomalien“ tab shows the progress per device.

**Warnings:**

| Kind | When | Severity |
|---|---|---|
| Volume | An hourly value is above 3× the 99th percentile and above 1.2× the maximum of the last 14 days, and above a minimum (e.g. 50 MB sent, 10 local devices, 30 ports). Examples: data exfiltration, network or port scan, DNS flood | medium/high |
| New | A service newly reachable from outside, a new service in the LAN, a new destination port, a new destination country, a new protocol or a new domain. Only reported when the device rarely shows something new in that category. A smart plug suddenly contacting a new country triggers a warning, a laptop with new domains every day does not. | low to high |
| Time of day | Significant activity at an hour when the device was never active in the past weeks (only for devices that are not active around the clock) | low |

**In the „Anomalien“ tab:**
- open warnings with their reasons; admins can mark them as done („erledigt“) or choose „nicht mehr melden“ (stop reporting, e.g. "new domain" for the laptop)
- list of all devices with learning status
- a profile per device: active hours, the last 48 hours, typical values (median, 99 %, maximum) and everything it knows

The number on the tab shows open warnings. New warnings are also logged (`journalctl -u suricata-dashboard`). Mutes are part of the backed-up user data.

**Phone notifications (optional):** put e.g. `"anomaly_notify_url": "https://ntfy.sh/a-long-secret-topic"` in `config.json` and subscribe to the same topic in the [ntfy app](https://ntfy.sh). The dashboard sends new warnings from severity `anomaly_notify_min_severity` (default `medium`) as plain text via HTTP POST. Any other webhook that accepts plain text works too. On ntfy.sh the topic name acts like a password.

**Limits:**
- The dashboard learns what was normal during the learning phase. If a device was already compromised then, that counts as normal.
- Devices whose traffic Suricata does not see (e.g. on the same switch segment without a mirror port) have no or only a partial profile.
- Updates, new apps or holidays occasionally cause warnings. That is what "done" and "stop reporting" are for.

## TLS fingerprints (JA3 / JA4)

JA3 and JA4 describe *how* a program negotiates a TLS connection (version, ciphers, extensions). They stay the same regardless of which IP or domain the program talks to. This makes malware clients stand out even if their server is on no block list, as well as unexpected programs (e.g. a Python script on a device that otherwise only uses a browser).

**Requirement:** Suricata must compute the fingerprints and write them to the eve log. The dashboard reads `ja3`/`ja3s` (object with `hash`) and `ja4`/`ja4s` (string) from `tls` and `quic` events, e.g. with:

```yaml
app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes
      ja4-fingerprints: yes      # Suricata 7.0.4+ or 8
outputs:
  - eve-log:
      types:
        - tls:
            extended: yes
            custom: [subject, issuer, sni, version, ja3, ja3s, ja4]
```

The exact keys depend on the Suricata version (see the Suricata docs on "Eve JSON Output").

**„Fingerprints“ tab:** all fingerprints in the time range with rating, known application, devices, destinations (SNI) and number of connections. Fingerprints seen for the first time get a **NEU** badge. Admins can name a fingerprint (e.g. "Home Assistant") and mark it as harmless. The number on the tab counts suspicious or malicious fingerprints of the last 24 h that are not marked harmless. Also:

- The **alert details** show the fingerprints of the connection with their rating.
- **Reputation lookup** (Threat-Feeds tab) also accepts a JA3/JA4 hash and shows which devices used it, when and where to.

**Public lists** (Threat-Feeds tab, updated weekly):

| Feed | Content | Rating |
|---|---|---|
| [abuse.ch SSLBL JA3](https://sslbl.abuse.ch/blacklist/) | about 100 JA3 hashes of malware (Dridex, TrickBot, Tofsee …). **Not extended since 2021.** | hit = **suspicious**, because JA3 is not unique |
| [FoxIO JA4+ mapping](https://github.com/FoxIO-LLC/ja4) | official, license-free mapping by the JA4 authors: browsers, libraries, devices, but also Cobalt Strike, IcedID, Sliver | malware = **malicious**, browsers etc. = **known** |

How the dashboard rates:
- If a malware fingerprint shares its hash with normal software, it only counts as **suspicious**. Example: the JA4 of the Sliver agent is identical to that of every Go program.
- Server fingerprints (JA3S/JA4S) on their own are at most **suspicious**.

**Limits:** public lists of malicious fingerprints are small; the large JA4 database ja4db.com is no longer available. The bigger value is often noticing *new* or *unknown* fingerprints on your own network (filters "new" / "unknown"). A hit is a hint, not proof.

**Own lists** can be added via `custom_feeds` with `"kind": "ja3"` or `"kind": "ja4"`: one hash per line, optionally CSV with the label in the last column (the format of the abuse.ch list). JA4S hashes are detected automatically.

## Backup, restore and update

**What is backed up:** everything you entered yourself:
- paths, alert source, HTTPS and rules settings
- device names (by MAC or IP)
- signatures marked as harmless
- notes on TLS fingerprints
- muted anomaly warnings
- enabled and disabled threat feeds
- blocking rules created in the dashboard (from your rules file)
- optionally the users with password hash

Connections, alerts, host names and the IP-to-MAC mapping are learned again from eve.json. A MAC device name therefore reappears as soon as the device shows up on the network.

**Not included in the JSON export** are the learned profiles of the anomaly detection: hourly values, known ports, countries and domains, learning status and past warnings. They only live in `data/suricata.db`. If they are lost, the learning phase starts over (7 days). The full database backup covers them (see below).

**In the browser** (Einstellungen → „Sichern & Wiederherstellen“):
- **Export** downloads a JSON file.
- **Import** shows what the file contains before applying it. You choose the sections and whether the data is *merged* or *replaced*.
- **Automatic backups:** after every change the dashboard writes a backup to `data/backups/`. The newest 20 are kept. These JSON files do not depend on the database and survive a broken or incompletely copied `suricata.db`.
- **Notice on data loss:** if the dashboard starts with a database without own data while a backup contains some, it does not write an empty backup. Instead it shows the notice „Eigene Daten fehlen?“ (own data missing?) at the top with a button to restore.

**On the command line:**

```bash
sudo ./userdata.sh export ~/dashboard-backup.json      # --no-users to leave out users
sudo ./userdata.sh import ~/dashboard-backup.json      # --mode replace, --only devices,settings,rules
sudo ./userdata.sh list                                # automatic backups
```

Restart the service after an import on the command line.

**Full database backup** (including the anomaly profiles, connections and alerts):

```bash
sudo ./userdata.sh db-backup ~/dashboard-db-$(date +%F).db.gz    # works while the service is running
sudo systemctl stop suricata-dashboard
sudo ./userdata.sh db-restore ~/dashboard-db-2026-11-24.db.gz    # only with the service stopped
sudo systemctl start suricata-dashboard
```

- `db-backup` uses SQLite's backup API. The copy is therefore complete and consistent even while the service is running, including entries still in `suricata.db-wal`. With a `.gz` file name the copy is compressed. Afterwards the copy is checked for corruption.
- `db-restore` checks the file first and refuses to run while the service is active. The previous database is kept as `data/suricata.db.vor-restore-<timestamp>`; delete it once everything works.
- `settings.json`, feeds and the TLS certificate are not in the database. They are covered by the JSON export and the automatic backups, or are recreated.

### Updating the program

Everything you set in the browser lives in the `data/` folder (since version 1.8). Paths and the HTTPS setting are stored in `data/settings.json`, not in `config.json`. The safe way to update:

```bash
sudo ./userdata.sh db-backup ~/dashboard-db-$(date +%F).db.gz   # backup incl. anomaly profiles
sudo ./userdata.sh export ~/dashboard-backup.json      # additional backup of your own input (optional)
sudo systemctl stop suricata-dashboard          # important: stop before copying
# copy the new program files; do NOT overwrite data/ (and your own config.json), e.g.:
sudo rsync -a --exclude data --exclude config.json /tmp/suricata-dashboard/ /opt/suricata-dashboard/
sudo systemctl start suricata-dashboard
```

Why stopping matters: the database runs in WAL mode. New entries first go to `suricata.db-wal` and only later into `suricata.db`. Since 1.8 the dashboard moves everything into `suricata.db` when it shuts down. Copying the database while it is running, or copying only `suricata.db` without the `-wal` file, can lose the latest changes.

The learned anomaly profiles are preserved because they live in `data/suricata.db` and `data/` is not touched. Detection simply continues after the start. The `db-backup` file is only meant for emergencies, e.g. if `data/` was overwritten by accident while copying.

The shipped configuration is called `config.example.json`, so copying the program folder never overwrites your `config.json`. On the first start of 1.8 the dashboard moves paths previously changed in the browser from `config.json` to `data/settings.json` automatically.

## Configuration (`config.json`, optional)

`config.json` is optional. Without it the defaults apply. Copy `config.example.json` to `config.json` as a template. Values from `data/settings.json` (saved in the browser) take precedence over `config.json`.

| Key | Default | Meaning |
|---|---|---|
| `listen_port` | `8080` | Port of the web server |
| `eve_json` / `fast_log` | `/var/log/suricata/...` | Paths to the log files |
| `alert_source` | `fastlog` | `fastlog` reads alerts from fast.log, `eve` from eve.json (`event_type: alert`, also provides the app protocol) |
| `retention_days` | `30` | Older data is deleted hourly |
| `start_at_end` | `false` | `true` skips existing log data on the very first start |
| `new_signature_hours` | `24` | Time span in which a signature counts as "new" |
| `poll_interval_seconds` | `5` | Read interval |
| `threat_intel` | `true` | Download threat feeds automatically. With `false`, feeds already stored are still used, and "refresh" in the Threat-Feeds tab still works. |
| `tranco_top` | `100000` | How many top domains to load from the Tranco list |
| `trusted_domains` | `{}` | Your own trusted domains, e.g. `{"my-company.com": "Company VPN"}` (subdomains included) |
| `auth` | `true` | Login required. `false` = everyone on the network has full access |
| `https` | `false` | Enable HTTPS (also possible in the settings) |
| `https_port` | `8443` | HTTPS port |
| `http_redirect` | `true` | With HTTPS active, `listen_port` redirects to HTTPS |
| `https_cert` / `https_key` | `data/tls/cert.pem` / `key.pem` | Certificate and private key (PEM) |
| `https_self_signed` | `true` | Generate missing files as a self-signed certificate |
| `anomaly_detection` | `true` | Behaviour profiles and anomaly warnings |
| `anomaly_learning_days` | `7` | Learning phase per device in days (at least 3 active days) |
| `anomaly_notify_url` | `""` | Optional: send new warnings via HTTP POST (e.g. ntfy.sh) |
| `anomaly_notify_min_severity` | `medium` | Minimum severity to send: `low`, `medium` or `high` |
| `rules_dir` | `/var/lib/suricata/rules` | Directory with the official/external rules (also in the settings) |
| `local_rules` | `/etc/suricata/rules/local.rules` | Your own rules file the dashboard writes to (also in the settings) |
| `suricata_yaml` | `/etc/suricata/suricata.yaml` | Read to check `rule-files` (also in the settings) |
| `rules_reload` | `suricatasc` | `suricatasc`, `usr2` or `none` (also in the settings) |
| `custom_feeds` | `[]` | Your own lists, e.g. `[{"id": "mine", "name": "My list", "url": "https://…/ips.txt", "kind": "ip", "category": "malicious", "interval_h": 12}]`. `kind` is `ip` (IP/CIDR per line), `domain`, `ja3` or `ja4` (hash per line, optionally `,label`); `category` is `malicious` or `suspicious`. |

The database is `data/suricata.db`. It also contains your harmless marks, device names and users. For backups, the export (see above) is better suited than a copy of the database.

### So that all charts are filled

In `/etc/suricata/suricata.yaml` these types should be enabled in the `eve-log` (the default in most installations): `flow`, `dns`, `tls`, `http`, `dhcp` for device names (and `ethernet: yes` for MAC addresses), and `alert` for `alert_source: eve`. With `alert_source: fastlog`, `fast` (fast.log) must be enabled as well.

## Notes

- **eve.json context:** while reading, the program remembers the byte offset in eve.json for every minute (a few KB in the database). For the details only the matching slice is read, at most 64 MB. After log rotation it searches `eve.json.1`, `eve.json-<date>` etc. in the same folder. Logs that are already **compressed** (`.gz`) or deleted cannot be searched. The retention in logrotate therefore decides how far back the context goes.
- **Copying:** over `http://` browsers block the modern clipboard API. There is a fallback, and if that is blocked too, a window with the selected text opens for copying with Ctrl+C. With HTTPS copying works directly.
- Even with login and HTTPS: do not expose the port to the internet. A VPN (e.g. WireGuard) is the better choice for remote access.
- Log rotation (move or copytruncate) is detected. The read position is stored in the database, so nothing is counted twice after a restart.
- With very large logs the program reads at most 32 MB per cycle and catches up step by step. The progress is shown in the Status tab.
- **Threat feeds:**
  - The Pi downloads about 25 MB on first start, then every 6 h to 7 days depending on the feed. For single-URL feeds it first asks whether anything changed (ETag/Last-Modified) and otherwise downloads nothing.
  - All feeds together need about 80 MB of RAM. The largest is the HaGeZi list with about 25 MB; it can be disabled in the Threat-Feeds tab.
  - If a download fails or returns unusable data, the old data stays active. The next attempt follows after 30 minutes.
  - Licences: Spamhaus DROP may only be used non-commercially or at small scale. For the other feeds the terms on the linked pages apply.
- **Live view:**
  - While it is open, the Pi reads eve.json every second instead of every `poll_interval_seconds` and writes to the database more often. 20 seconds after closing it or switching tabs it returns to the normal interval. In tests, connection tracking cost about 2 µs per event; the browser does the drawing.
  - At most 40 peers per device and 400 connections in total are shown. Connections with alerts are always shown.
  - Suricata writes `flow` events only at the end of a flow. Connections without a detected application protocol (no DNS/TLS/HTTP event) therefore only appear once they have ended. Very long connections can disappear in between until another event arrives. A longer hold time helps.
  - Device names only exist if Suricata sees DHCP (`dhcp` in the eve log) and a device requests its address again. They are stored in the database.
- **Device names:**
  - MAC addresses are only visible in the same network segment as the sensor. If a router sits between sensor and devices, all packets carry the router's MAC. The dashboard detects this when at least 4 IPv4 addresses share one MAC ("shared MAC") and then assigns names per IP.
  - Phones and laptops often use a "private" Wi-Fi MAC (badge "private MAC"). It usually stays the same per network. If it is set to "rotating", it changes and the name has to be set again.
  - Names refer to the current mapping: an old alert shows the name of the device that has the IP now.
- **Limits of the rating:** host names are assigned to an IP from all observed DNS answers. For CDN addresses (Akamai, Cloudflare …) serving many domains, an IP can therefore carry both "Windows Update" and a listed domain. The block list always wins. "Known service" does not mean "guaranteed harmless"; a look at the details is still worthwhile.

## Layout

```
backend/server.py           reader, SQLite, API, web server
backend/threatintel.py      download/store threat feeds, rate reputation
backend/live.py             active connections for the live view
backend/auth.py             users, login, sessions (also a command line tool)
backend/tls.py              HTTPS, self-signed certificate, redirect
backend/userdata.py         export/import and automatic backup of user data, database backup
backend/anomaly.py          behaviour profiles of local devices and anomaly detection
backend/rules.py            own blocking rules: build, read/write local.rules, check suricata.yaml, reload
frontend/index.html         entry point
frontend/login.html         login page
frontend/app.js             React app
frontend/style.css          styles (light/dark)
frontend/vendor/            React 18.3.1, htm 3.1.1, Chart.js 4.4.1
config.example.json         template for config.json (optional)
data/                       database, settings.json, backups (data/backups/), feeds (data/feeds/), certificate (data/tls/)
start.sh                    start script
users.sh                    manage users on the command line
userdata.sh                 export/import user data, database backup/restore
suricata-dashboard.service  systemd unit
```

### API

All calls except `POST /api/login` need the session cookie (otherwise `401`). Modifying calls (`POST`/`DELETE`) and the settings/user/rules queries are restricted to administrators (otherwise `403`).

`POST /api/login {"username":"admin","password":"…","remember":true}` · `POST /api/logout` · `GET /api/me` · `POST /api/me/password {"old":"…","new":"…"}`
`GET /api/users` · `POST /api/users {"op":"add|role|password|delete|logout","username":"…","password":"…","role":"admin|viewer","must_change":true}`
`GET /api/rules` · `GET /api/rules/suggest?alert_id=<id>` or `?gid=1&sid=<sid>` · `POST /api/rules/build` (preview, writes nothing) and `POST /api/rules/add {"kind":"sig|ip|domain","action":"drop|reject","sid":2013028,"ip":"…","domain":"…","note":"…","reload":true}` · `POST /api/rules/modify {"sid":1000002,"op":"enable|disable|delete"}` · `POST /api/rules/reload` · `POST /api/rules/settings {"rules_dir":"…","local_rules":"…","suricata_yaml":"…","rules_reload":"suricatasc|usr2|none"}`
`GET /api/anomalies?status=open|all&days=30` · `GET /api/anomalies/device?dev=<MAC|IP>` · `POST /api/anomalies/ack {"ids":[1,2]}` or `{"all":true}` · `POST /api/anomalies/mute {"dev":"…","kind":"new|volume|time","metric":"domain","mute":true}` · `POST /api/anomalies/check`
`GET /api/userdata/export?users=0|1` · `POST /api/userdata/import {"data":{…export…},"sections":["device_names","settings"],"mode":"merge|replace"}` · `GET /api/userdata/backups` · `GET /api/userdata/backup?name=…` · `POST /api/userdata/backup_now`
`GET /api/fingerprints?hours=24` · `POST /api/fingerprints/note {"type":"ja4","fp":"t13d…","label":"Home Assistant","harmless":true}` · `GET /api/intel/lookup?q=<IP|domain|JA3|JA4>`
`GET /api/https` · `POST /api/https {"enabled":true,"https_port":8443,"http_redirect":true,"regenerate":false}` (restarts the service)

`GET /api/summary|traffic|protocols|top|alerts|alerts/timeline|signatures|flags|status|event_types?hours=24`
`GET /api/alert_context?id=<alert-id>&before=60&after=300` · `GET /api/settings` · `GET /api/settings/check?path=…` · `GET /api/settings/find` · `POST /api/settings {"eve_json":"…","fast_log":"…","alert_source":"fastlog"}`
`GET /api/live?hold=30&alerts=0&lan=1&groups=1` (enables the one-second interval for 20 s) · `GET /api/devices` · `GET /api/devices/names` · `POST /api/devices {"kind":"mac","key":"3c:22:fb:12:34:56","name":"Printer"}` (empty name deletes) · `POST /api/flags {"gid":1,"sid":2013504,"note":"apt"}` · `DELETE /api/flags?gid=1&sid=2013504`
