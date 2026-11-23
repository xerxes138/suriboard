# Suricata Dashboard

Ein schlankes Web-Dashboard für Suricata (IPS/IDS) auf dem Raspberry Pi, ähnlich wie beim Pi-hole.

- **Backend:** Python 3, nur die Standardbibliothek (kein `pip install`). Es liest `eve.json` und `fast.log` alle paar Sekunden inkrementell ein, verdichtet die Daten in SQLite und stellt eine JSON-API bereit.
- **Frontend:** React (mit htm statt JSX) und Chart.js. Alle Bibliotheken liegen in `frontend/vendor/`, es gibt also **keinen Build-Schritt**. Internet braucht nur der Pi selbst, um die Threat-Feeds zu laden (optional, siehe unten).

## Funktionen

- **Übersicht:** Verbindungen über die Zeit, gestapelt nach Anwendungsprotokoll (tls, dns, quic …) oder Transportprotokoll (TCP/UDP), umschaltbar zwischen Flows und Bytes. Dazu Kennzahlen, ein Alert-Zeitverlauf und Top-Listen (Clients, Ziele, Ports, DNS-Anfragen, TLS-SNI, HTTP-Hosts).
- **Alerts** (aus `fast.log`): eine filterbare Liste (Suche, IP, SID, nur blockierte) mit Aktion (blockiert / würde blockieren / erlaubt) und Schweregrad.
- **Signaturen:** Alerts gruppiert nach Regel (SID), mit Trefferzahl, Beispiel-Verbindungen und Zeitpunkt des ersten Auftretens. Signaturen, die zum ersten Mal in den letzten 24 Std auftauchen, bekommen das Badge **NEU**.
- **Als harmlos markieren:** Ein Klick auf „Harmlos“ (mit optionaler Notiz) blendet die SID überall aus, also auch künftige Treffer, z. B. apt-Updates oder Discord. Übrig bleibt nur, was neu oder potenziell gefährlich ist. Die Markierung lässt sich jederzeit aufheben.
- **Alert-Details mit eve.json-Kontext:** Ein Klick auf einen Alert („Details“ oder die Signatur) zeigt, was eve.json rund um den Alert enthält:
  - **Diese Verbindung:** alle Events mit gleicher Flow-ID bzw. gleichen IPs, Ports und Protokoll (alert, flow, tls, http, fileinfo …).
  - **Namensauflösung:** DNS-Antworten zu den beteiligten IPs. Dazu werden die Hostnamen (aus DNS, TLS-SNI und HTTP) direkt neben der IP angezeigt.
  - **Weitere Ereignisse zwischen den beiden Hosts** und **andere Gesprächspartner** der IPs, um weitere betroffene Geräte zu finden.
  - Das Zeitfenster lässt sich zwischen ±1 Min und −30/+60 Min wählen. Jedes Event kannst du aufklappen und als JSON kopieren.
- **In die Zwischenablage kopieren:** Das ⧉-Symbol neben jeder IP kopiert sie (Alert-Liste, Signaturen, Details). In den Details gibt es außerdem „Beide IPs“, „Zusammenfassung“ (Alert als Text), SID und Flow-ID zum Kopieren.
- **Reputation (Threat-Feeds):** Öffentliche Blocklisten werden automatisch geladen und in `data/feeds/` gespeichert. Jeder Alert bekommt eine Bewertung der externen IP, damit sich Fehlalarme wie Windows-Updates schnell von echten Treffern unterscheiden lassen:
  - **⚠ Blockliste** (rot): IP steht auf Spamhaus DROP, Feodo Tracker oder ET Compromised, oder ein Hostname dieser IP steht auf der HaGeZi-Threat-Intel-Liste.
  - **! auffällig** (orange): IP ist ein bekannter Scanner/Angreifer (IPsum, CINS Army, blocklist.de) oder ein Tor-Exit-Node.
  - **✓ bekannter Dienst** (grün): Ein Hostname der IP gehört zu einem Update- oder Systemdienst (Windows Update, Microsoft Defender, Apple, Debian, Ubuntu, Raspberry Pi, Mozilla, Steam …) und es gibt keinen Blocklisten-Treffer. Das ist sehr wahrscheinlich ein Fehlalarm.
  - **verbreitet**: Hostname in den Tranco-Top-100.000. Das ist nur ein Hinweis.
  - **unbekannt**: Es wird nur der Netzbetreiber angezeigt (z. B. „AS8075 Microsoft“, aus iptoasn.com).
  
  Die Hostnamen stammen aus DNS-Antworten, TLS-SNI und HTTP-Host in eve.json. Das Dashboard merkt sich beim Einlesen, welche Namen zu welcher IP gehören.
  - Die **Alert-Liste** hat eine Spalte „Reputation“ und einen Filter, z. B. „bekannte Dienste ausblenden“ oder „nur Blocklisten-Treffer“.
  - Die **Details** eines Alerts zeigen die Bewertung mit Begründung, Netzbetreiber und allen Hostnamen.
  - In der **Übersicht** zählt eine Kachel die offenen Alerts mit Blocklisten-Treffer.
  - Der Tab **Threat-Feeds** zeigt den Stand jedes Feeds und hat eine Suche für einzelne IPs oder Domains. Dort lassen sich Feeds auch abschalten oder sofort aktualisieren.
- **Live-Ansicht (Tab „Live“):** Zeigt die Geräte im Netz und ihre aktuellen Verbindungen als Graph, sekündlich aktualisiert. Die Ansicht ist aus, bis du sie mit dem Schalter startest.
  - Blaue Kreise sind lokale Geräte. Der Name kommt aus DHCP, sonst steht dort die IP, und die Zahl im Kreis gibt die Anzahl der Verbindungen an. Die kleinen Punkte sind die Gegenstellen. Ihre Farbe zeigt die Reputation, die Beschriftung Domain, Protokoll/Port und Netzbetreiber. Violette Rauten sind Multicast/Broadcast (mDNS, SSDP …).
  - Bei einem Alert bekommen Gerät und Gegenstelle einen pulsierenden roten Ring, die Signatur steht direkt am Punkt. Solche Verbindungen bleiben mindestens 2 Minuten sichtbar.
  - Eine Verbindung bleibt nach der letzten Aktivität so lange stehen, wie es die **Haltezeit** angibt (10 s bis 5 Min), und blendet dann weich aus. So flackert der Graph nicht. Neue Aktivität lässt die Kante kurz aufleuchten. Gestrichelte Kanten sind eingehende Verbindungen.
  - An den Kanten steht, was gerade passiert: bei DNS die zuletzt angefragte Domain (`DNS example.org +3`), bei TLS und HTTP der aufgerufene Hostname (SNI bzw. Host-Header). Eine neue Anfrage wird kurz blau hervorgehoben. Ist es eng, werden Kantentexte ausgeblendet; beim Darüberfahren oder Anklicken eines Punktes erscheinen die Texte an seinen Kanten. Steht derselbe Name schon am Zielpunkt, wird er an der Kante nicht wiederholt.
  - Ein Klick auf einen Punkt öffnet die Details: Verbindungen, Dienste, Hostnamen, DNS-Anfragen, Alerts und Reputation. Punkte lassen sich verschieben, mit dem Mausrad oder mit +/− zoomen, ⤢ passt den Ausschnitt wieder automatisch an.
  - Filter: nur Verbindungen mit Alert, LAN-interne Verbindungen und Multicast/Broadcast ein- oder ausblenden.
- **Geräte (Tab „Geräte“):** Eigene Namen für lokale Geräte. Sie erscheinen bei Alerts, in den Top-Listen, in den Alert-Details und in der Live-Ansicht. Dort lässt sich ein Gerät auch direkt im Detail-Panel benennen.
  - Ist die **MAC-Adresse** bekannt, hängt der Name an ihr. Er bleibt also auch dann erhalten, wenn das Gerät per DHCP eine neue IP bekommt, und gilt für alle seine Adressen einschließlich IPv6. Ohne MAC hängt der Name an der IP.
  - MAC-Adressen kommen aus dem `ether`-Feld in eve.json (in `suricata.yaml` beim `eve-log` die Option `ethernet: yes` setzen, ab Suricata 7) und aus DHCP-Events. Diese liefern auch den Hostnamen, den das Gerät selbst meldet. Er wird angezeigt, solange kein eigener Name vergeben ist.
  - Reihenfolge: Name der MAC > Name der IP > DHCP-Hostname.
  - Geräte lassen sich auch von Hand per MAC oder IP eintragen, bevor sie zum ersten Mal auftauchen.
- **Anomalien:** Das Dashboard lernt das normale Verhalten jedes lokalen Geräts und warnt bei deutlichen Abweichungen, z. B. Datenabfluss, Scans, neue Zielländer oder Dienste. Siehe [Anomalieerkennung](#anomalieerkennung).
- **Fingerprints:** alle gesehenen TLS-/QUIC-Fingerabdrücke (JA3, JA3S, JA4, JA4S), geprüft gegen öffentliche Listen. Siehe [TLS-Fingerprints](#tls-fingerprints-ja3--ja4).
- **Status:** Lesefortschritt der Logdateien, Größe der Datenbank, Event-Typen.
- **Einstellungen:** Pfade zu `eve.json` und `fast.log` sowie die Quelle für Alerts direkt im Browser ändern, Benutzer verwalten, HTTPS einschalten, Nutzerdaten exportieren/importieren (siehe [Sichern, Wiederherstellen und Aktualisieren](#sichern-wiederherstellen-und-aktualisieren)).
- **Anmeldung:** Wie beim Pi-hole ist das Dashboard passwortgeschützt. Es gibt beliebig viele Benutzer mit der Rolle **Administrator** oder **Nur lesen**. Siehe [Anmeldung und Benutzer](#anmeldung-und-benutzer).
- **HTTPS** mit automatisch erzeugtem Zertifikat oder eigenem (z. B. Let's Encrypt), siehe [HTTPS](#https).
- Hell- und Dunkelmodus, automatische Aktualisierung alle 30 s, funktioniert auch auf dem Handy.

## Installation auf dem Raspberry Pi

```bash
# Ordner auf den Pi kopieren, z. B.:
scp -r suricata-dashboard pi@raspberrypi:/tmp/
ssh pi@raspberrypi
sudo mv /tmp/suricata-dashboard /opt/

# Testlauf (sudo wegen Leserechten auf /var/log/suricata)
cd /opt/suricata-dashboard
sudo ./start.sh
```

Danach im Browser auf einem anderen Rechner aufrufen: **http://<IP-des-Pi>:8080**

Beim ersten Start legt das Dashboard den Benutzer **admin** mit einem Zufallspasswort an (wie der Pi-hole bei der Installation). Das Passwort steht im Log und in `data/initial-admin-password.txt`:

```bash
sudo cat /opt/suricata-dashboard/data/initial-admin-password.txt
# oder gleich ein eigenes setzen:
sudo ./users.sh passwd admin
```

Nach der ersten Anmeldung mit dem Zufallspasswort fragt das Dashboard nach einem eigenen Passwort. Die Datei wird dann gelöscht.

Voraussetzung ist nur `python3`; auf Raspberry Pi OS ist es vorinstalliert. Mindestversion: Python 3.9 und SQLite 3.24.

### Als Dienst einrichten (startet automatisch)

```bash
sudo cp /opt/suricata-dashboard/suricata-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now suricata-dashboard
journalctl -u suricata-dashboard -f      # Log ansehen
```

Wenn das Dashboard nicht als root laufen soll, trage in der Unit `User=pi` und `SupplementaryGroups=adm` ein. Diese Gruppe muss die Logs lesen dürfen; prüfe das mit `ls -l /var/log/suricata`.

## Pfade zu den Logdateien

Liegen die Logs nicht unter `/var/log/suricata`, kannst du die Pfade direkt im Dashboard unter **Einstellungen** ändern. Dort findest du:

- Eingabefelder für `eve.json` und `fast.log`. Beim Tippen wird sofort geprüft, ob die Datei existiert und lesbar ist.
- **Dateien automatisch suchen**: durchsucht übliche Orte (`/var/log`, `/opt`, `/home`, `/mnt`, `/media`, `/srv`, `/data` …) bis zu 4 Ebenen tief.
- **Speichern**: übernimmt die neuen Pfade sofort, ohne Neustart, und schreibt sie in `data/settings.json`.

Den richtigen Pfad findest du in `/etc/suricata/suricata.yaml` unter `default-log-dir`. Findet das Dashboard eine Logdatei nicht, zeigt es oben einen Hinweis mit dem Button „Pfade einstellen“.

## Anmeldung und Benutzer

Ohne Anmeldung sieht man nur die Login-Seite; alle Seiten und API-Aufrufe sind gesperrt.

| Rolle | Darf |
|---|---|
| **Administrator** | alles: Alerts als harmlos markieren, Geräte benennen, Threat-Feeds schalten, Einstellungen, Benutzer verwalten, HTTPS |
| **Nur lesen** | alle Daten ansehen, aber nichts ändern. Der Tab „Einstellungen“ ist ausgeblendet. |

- **Benutzer verwalten:** Tab **Einstellungen → Benutzer**: anlegen, Rolle ändern, Passwort neu setzen (optional mit Pflicht zur Änderung bei der nächsten Anmeldung), abmelden, löschen. Der letzte Administrator lässt sich weder löschen noch herabstufen.
- **Eigenes Passwort:** oben rechts auf den Benutzernamen → „Passwort ändern“. Dabei werden alle anderen Sitzungen dieses Kontos beendet.
- **Sitzungen:** Ohne „Angemeldet bleiben“ läuft eine Sitzung nach 12 Std Inaktivität ab, mit nach 30 Tagen. Das Cookie ist `HttpOnly` und `SameSite=Strict`, bei HTTPS zusätzlich `Secure`.
- **Schutz gegen Passwort-Raten:** Nach 5 Fehlversuchen wird die IP 30 s gesperrt, jede weitere Sperre dauert doppelt so lang (höchstens 15 Min). Fehlversuche stehen im Log.
- **Passwörter** werden als PBKDF2-SHA256 (200 000 Runden, mit Salt) in `data/suricata.db` gespeichert. Die Datei ist deshalb nur noch für ihren Besitzer lesbar.

**Auf der Kommandozeile** (z. B. wenn du das Passwort vergessen hast):

```bash
cd /opt/suricata-dashboard
sudo ./users.sh list                     # Benutzer anzeigen
sudo ./users.sh passwd admin             # Passwort setzen (legt den Benutzer an, falls er fehlt)
sudo ./users.sh add anna --role viewer   # Benutzer anlegen (admin oder viewer)
sudo ./users.sh role anna admin          # Rolle ändern
sudo ./users.sh del anna                 # Benutzer löschen
sudo ./users.sh logout-all               # alle Sitzungen beenden
```

Wer keine Anmeldung will (z. B. weil ein Reverse-Proxy sich darum kümmert), setzt in `config.json` `"auth": false`. Dann hat jeder im Netz vollen Zugriff, und das Dashboard zeigt oben einen Warnhinweis.

## HTTPS

Unter **Einstellungen → HTTPS** den Schalter „HTTPS verwenden“ einschalten und „Speichern und neu starten“ klicken. Das Dashboard

1. erzeugt ein **selbstsigniertes Zertifikat** in `data/tls/` (gültig 10 Jahre, für Hostname, `<hostname>.local` und alle IPs des Pi; braucht das Programm `openssl`, auf Raspberry Pi OS vorhanden),
2. startet sich selbst neu und läuft dann unter **https://<IP-des-Pi>:8443**,
3. leitet `http://<IP-des-Pi>:8080` automatisch dorthin um (abschaltbar).

Da das Zertifikat selbstsigniert ist, warnt der Browser beim ersten Aufruf („Verbindung nicht privat“). Einmal **Erweitert → Trotzdem fortfahren** wählen. Wer sichergehen will, vergleicht den SHA-256-Fingerabdruck im Browser mit dem in den Einstellungen. Ändert sich die IP des Pi, erzeugt **Zertifikat neu erzeugen** ein passendes.

**Eigenes Zertifikat** (z. B. Let's Encrypt oder von der eigenen CA) in `config.json` eintragen:

```json
"https": true,
"https_cert": "/etc/letsencrypt/live/pi.example.de/fullchain.pem",
"https_key": "/etc/letsencrypt/live/pi.example.de/privkey.pem",
"https_self_signed": false
```

Lässt sich HTTPS beim Start nicht einrichten (Zertifikat fehlt oder ist kaputt), läuft das Dashboard zur Sicherheit unverschlüsselt auf `listen_port` weiter. Den Grund zeigen das Log und die Einstellungen. So sperrst du dich nicht aus.

Auf Port 443/80 statt 8443/8080 laufen: `"https_port": 443, "listen_port": 80`. Das klappt so, wenn der Dienst als root läuft (Standard in der mitgelieferten Unit).

## Anomalieerkennung

Das Dashboard legt für jedes Gerät im lokalen Netz ein Verhaltensprofil an. Nach einer Lernphase warnt es, wenn ein Gerät deutlich davon abweicht. Es nutzt dafür kein „KI“-Modell, sondern einfache Regeln: Jede Warnung lässt sich mit konkreten Zahlen begründen („200 MB in einer Stunde gesendet, bisher höchstens 25 KB“).

**Was beobachtet wird** (aus `flow`-, `dns`- und `tls`-Events):
- pro Stunde: Verbindungen, gesendete und empfangene Daten, externe Gegenstellen, kontaktierte lokale Geräte, verschiedene Ziel-Ports, DNS-Anfragen
- was ein Gerät „kennt“: Ziel-Ports im Internet, Protokolle, Zielländer (über die IP→Netzbetreiber-Tabelle), Domains (aus DNS und TLS-SNI), genutzte Dienste im LAN und Dienste, die von außen erreichbar sind

Ein Gerät ist die MAC-Adresse, wenn bekannt und nicht von mehreren IPs geteilt, sonst die IPv4-Adresse. So bleibt das Profil auch bei einer neuen IP per DHCP erhalten. IPv6-Adressen ohne bekannte MAC werden ignoriert, weil Privacy-Adressen täglich wechseln.

**Lernphase:** `anomaly_learning_days` Tage (Standard 7) seit dem ersten Auftauchen, davon mindestens 3 aktive Tage. Den Fortschritt zeigt der Tab „Anomalien“ pro Gerät.

**Warnungen:**

| Art | Wann | Schwere |
|---|---|---|
| Menge | Ein Stundenwert liegt über dem 3-fachen 99-%-Wert und über dem 1,2-fachen Maximum der letzten 14 Tage sowie über einem Mindestwert (z. B. 50 MB gesendet, 10 lokale Geräte, 30 Ports). Beispiele: Datenabfluss, Netzwerk- oder Port-Scan, DNS-Flut | mittel/hoch |
| Neu | Ein neu von außen erreichbarer Dienst, ein neuer Dienst im LAN, ein neuer Ziel-Port, ein neues Zielland, ein neues Protokoll oder eine neue Domain. Gemeldet wird nur, wenn das Gerät in dieser Kategorie sonst selten Neues zeigt. Ein Smart-Plug, der plötzlich ein neues Land kontaktiert, löst eine Warnung aus, ein Laptop mit täglich neuen Domains nicht. | niedrig bis hoch |
| Uhrzeit | Deutliche Aktivität zu einer Uhrzeit, zu der das Gerät in den letzten Wochen nie aktiv war (nur bei Geräten, die nicht rund um die Uhr aktiv sind) | niedrig |

**Im Tab „Anomalien“:**
- offene Warnungen mit Begründung; Admins können sie als „erledigt“ markieren oder „nicht mehr melden“ wählen (z. B. „Neue Domain“ für den Laptop)
- Liste aller Geräte mit Lernstatus
- pro Gerät ein Profil: zu welchen Uhrzeiten es aktiv ist, die letzten 48 Stunden, übliche Werte (Median, 99 %, Maximum) und alles, was es kennt

Die Zahl am Tab zeigt die offenen Warnungen. Neue Warnungen stehen außerdem im Log (`journalctl -u suricata-dashboard`). Stummschaltungen gehören zu den gesicherten Nutzerdaten.

**Benachrichtigung aufs Handy (optional):** In `config.json` z. B. `"anomaly_notify_url": "https://ntfy.sh/ein-langes-geheimes-thema"` eintragen und in der [ntfy-App](https://ntfy.sh) dasselbe Thema abonnieren. Das Dashboard schickt neue Warnungen ab der Schwere `anomaly_notify_min_severity` (Standard `medium`) per HTTP-POST als Text. Jeder andere Webhook, der einfachen Text annimmt, funktioniert ebenso. Der Name des Themas wirkt bei ntfy.sh wie ein Passwort.

**Grenzen:**
- Gelernt wird, was im Lernzeitraum normal war. War ein Gerät da schon kompromittiert, gilt das als normal.
- Geräte, deren Verkehr Suricata nicht sieht (z. B. im selben Switch-Segment ohne Spiegelport), haben kein oder nur ein lückenhaftes Profil.
- Updates, neue Apps oder Urlaub erzeugen gelegentlich Warnungen. Dafür gibt es „erledigt“ und „nicht mehr melden“.

## TLS-Fingerprints (JA3 / JA4)

JA3 und JA4 beschreiben, *wie* ein Programm eine TLS-Verbindung aushandelt (Version, Cipher, Erweiterungen). Sie bleiben gleich, egal mit welcher IP oder Domain das Programm spricht. Damit fallen Malware-Clients auf, auch wenn ihr Server auf keiner Blockliste steht, und ebenso unerwartete Programme (z. B. ein Python-Skript auf einem Gerät, das sonst nur einen Browser nutzt).

**Voraussetzung:** Suricata muss die Fingerprints berechnen und ins eve-log schreiben. Das Dashboard liest `ja3`/`ja3s` (Objekt mit `hash`) und `ja4`/`ja4s` (Text) aus `tls`- und `quic`-Events, z. B. mit:

```yaml
app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes
      ja4-fingerprints: yes      # ab Suricata 7.0.4 bzw. 8
outputs:
  - eve-log:
      types:
        - tls:
            extended: yes
            custom: [subject, issuer, sni, version, ja3, ja3s, ja4]
```

Die genauen Schlüssel hängen von der Suricata-Version ab (siehe Suricata-Doku zu „Eve JSON Output“).

**Tab „Fingerprints“:** Alle Fingerprints im Zeitraum mit Bewertung, bekannter Anwendung, Geräten, Zielen (SNI) und Anzahl der Verbindungen. Fingerprints, die zum ersten Mal auftauchen, bekommen das Badge **NEU**. Admins können einen Fingerprint benennen (z. B. „Home Assistant“) und als harmlos markieren. Die Zahl am Tab zählt auffällige oder bösartige Fingerprints der letzten 24 Std, die nicht als harmlos markiert sind. Zusätzlich:

- Im **Alert-Detail** stehen die Fingerprints der Verbindung mit Bewertung.
- **Reputation prüfen** (Tab Threat-Feeds) nimmt auch einen JA3-/JA4-Hash an und zeigt, welche Geräte ihn wann und wohin benutzt haben.

**Öffentliche Listen** (Tab Threat-Feeds, wöchentlich aktualisiert):

| Feed | Inhalt | Bewertung |
|---|---|---|
| [abuse.ch SSLBL JA3](https://sslbl.abuse.ch/blacklist/) | ca. 100 JA3-Hashes von Malware (Dridex, TrickBot, Tofsee …). **Seit 2021 nicht mehr erweitert.** | Treffer = **auffällig**, weil JA3 nicht eindeutig ist |
| [FoxIO JA4+ Zuordnung](https://github.com/FoxIO-LLC/ja4) | offizielle, lizenzfreie Zuordnung der JA4-Erfinder: Browser, Bibliotheken, Geräte, aber auch Cobalt Strike, IcedID, Sliver | Malware = **bösartig**, Browser usw. = **bekannt** |

So bewertet das Dashboard:
- Teilt sich ein Malware-Fingerprint den Hash mit normaler Software, gilt er nur als **auffällig**. Beispiel: Der JA4 des Sliver-Agents ist identisch mit dem jedes Go-Programms.
- Server-Fingerprints (JA3S/JA4S) allein sind ebenfalls höchstens **auffällig**.

**Grenzen:** Öffentliche Listen mit bösartigen Fingerprints sind klein; die große JA4-Datenbank ja4db.com ist nicht mehr erreichbar. Der größere Nutzen liegt oft darin, *neue* oder *unbekannte* Fingerprints im eigenen Netz zu bemerken (Filter „Neu“ / „Unbekannt“). Ein Treffer ist ein Hinweis, kein Beweis.

**Eigene Listen** gehen über `custom_feeds` mit `"kind": "ja3"` oder `"kind": "ja4"`: eine Zeile pro Hash, optional CSV mit der Bezeichnung in der letzten Spalte (so wie die abuse.ch-Liste aufgebaut ist). JA4S-Hashes erkennt das Dashboard automatisch.

## Sichern, Wiederherstellen und Aktualisieren

**Was gesichert wird:** alles, was du selbst eingegeben hast:
- Pfade, Alert-Quelle und HTTPS-Einstellung
- Gerätenamen (per MAC oder IP)
- harmlos markierte Signaturen
- Notizen zu TLS-Fingerprints
- ein- und ausgeschaltete Threat-Feeds
- optional die Benutzer mit Passwort-Hash

Verbindungen, Alerts, Hostnamen und die IP-zu-MAC-Zuordnung lernt das Dashboard aus eve.json neu. Ein MAC-Gerätename erscheint deshalb wieder, sobald das Gerät im Netz auftaucht.

**Im Browser** (Einstellungen → Sichern & Wiederherstellen):
- **Exportieren** lädt eine JSON-Datei herunter.
- **Importieren** zeigt vor dem Übernehmen, was in der Datei steht. Du wählst die Bereiche und ob die Daten *zusammengeführt* oder *ersetzt* werden.
- **Automatische Sicherungen:** Nach jeder Änderung legt das Dashboard eine Sicherung in `data/backups/` an. Die neuesten 20 bleiben erhalten. Diese JSON-Dateien hängen nicht an der Datenbank und überstehen auch eine kaputte oder unvollständig kopierte `suricata.db`.
- **Hinweis bei Verlust:** Startet das Dashboard mit einer Datenbank ohne eigene Daten, während eine Sicherung welche enthält, legt es keine leere Sicherung an. Stattdessen zeigt es oben den Hinweis „Eigene Daten fehlen?“ mit einem Button zum Wiederherstellen.

**Auf der Kommandozeile:**

```bash
sudo ./userdata.sh export ~/dashboard-sicherung.json      # mit --no-users ohne Benutzer
sudo ./userdata.sh import ~/dashboard-sicherung.json      # --mode replace, --only devices,settings
sudo ./userdata.sh list                                   # automatische Sicherungen
```

Nach einem Import auf der Kommandozeile den Dienst neu starten.

### Programm aktualisieren

Alles, was du im Browser einstellst, liegt seit Version 1.8 im Ordner `data/`. Die Pfade und die HTTPS-Einstellung stehen dort in `data/settings.json` und nicht mehr in `config.json`. So geht es sicher:

```bash
sudo systemctl stop suricata-dashboard          # wichtig: erst stoppen
sudo ./userdata.sh export ~/dashboard-sicherung.json   # zusätzliche Sicherung (optional)
# neue Programmdateien kopieren; data/ (und eine eigene config.json) dabei NICHT überschreiben, z. B.:
sudo rsync -a --exclude data --exclude config.json /tmp/suricata-dashboard/ /opt/suricata-dashboard/
sudo systemctl start suricata-dashboard
```

Warum das Stoppen wichtig ist: Die Datenbank läuft im WAL-Modus. Neue Einträge stehen zunächst in `suricata.db-wal` und wandern erst später in `suricata.db`. Seit 1.8 übernimmt das Dashboard beim Beenden alles in `suricata.db`. Kopiert man die Datenbank im laufenden Betrieb oder nur `suricata.db` ohne die `-wal`-Datei, können die letzten Änderungen fehlen. Das ist wahrscheinlich der Grund, warum früher Gerätenamen verloren gingen.

Die mitgelieferte Konfiguration heißt jetzt `config.example.json`. Ein Kopieren des Programmordners überschreibt deine `config.json` also nicht mehr. Beim ersten Start von 1.8 übernimmt das Dashboard bisher im Browser geänderte Pfade aus `config.json` automatisch nach `data/settings.json`.

## Konfiguration (`config.json`, optional)

`config.json` ist optional. Ohne die Datei gelten die Standardwerte. Als Vorlage dient `config.example.json`, die du nach `config.json` kopierst. Werte aus `data/settings.json` (im Browser gespeichert) haben Vorrang vor `config.json`.

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `listen_port` | `8080` | Port des Webservers |
| `eve_json` / `fast_log` | `/var/log/suricata/...` | Pfade zu den Logdateien |
| `alert_source` | `fastlog` | `fastlog` liest Alerts aus fast.log, `eve` liest sie aus eve.json (`event_type: alert`, liefert zusätzlich das App-Protokoll) |
| `retention_days` | `30` | Ältere Daten werden stündlich gelöscht |
| `start_at_end` | `false` | `true` überspringt beim allerersten Start vorhandene Logdaten |
| `new_signature_hours` | `24` | Zeitraum, in dem eine Signatur als „NEU“ gilt |
| `poll_interval_seconds` | `5` | Einleseintervall |
| `threat_intel` | `true` | Threat-Feeds automatisch laden. Bei `false` werden bereits gespeicherte Feeds weiter genutzt, und „aktualisieren“ im Tab Threat-Feeds funktioniert weiterhin. |
| `tranco_top` | `100000` | Wie viele Top-Domains aus der Tranco-Liste geladen werden |
| `trusted_domains` | `{}` | Eigene vertrauenswürdige Domains, z. B. `{"meine-firma.de": "Firmen-VPN"}` (gilt inkl. Subdomains) |
| `auth` | `true` | Anmeldung erforderlich. `false` = jeder im Netz hat vollen Zugriff |
| `https` | `false` | HTTPS einschalten (geht auch unter Einstellungen) |
| `https_port` | `8443` | Port für HTTPS |
| `http_redirect` | `true` | Bei aktivem HTTPS leitet `listen_port` auf HTTPS um |
| `https_cert` / `https_key` | `data/tls/cert.pem` / `key.pem` | Zertifikat und privater Schlüssel (PEM) |
| `anomaly_detection` | `true` | Verhaltensprofile und Anomalie-Warnungen |
| `anomaly_learning_days` | `7` | Lernphase pro Gerät in Tagen (mind. 3 aktive Tage) |
| `anomaly_notify_url` | `""` | Optional: neue Warnungen per HTTP-POST verschicken (z. B. ntfy.sh) |
| `anomaly_notify_min_severity` | `medium` | Ab welcher Schwere verschickt wird: `low`, `medium` oder `high` |
| `https_self_signed` | `true` | Fehlende Dateien automatisch als selbstsigniertes Zertifikat erzeugen |
| `custom_feeds` | `[]` | Eigene Listen, z. B. `[{"id": "meine", "name": "Meine Liste", "url": "https://…/ips.txt", "kind": "ip", "category": "malicious", "interval_h": 12}]`. `kind` ist `ip` (IP/CIDR je Zeile), `domain`, `ja3` oder `ja4` (Hash je Zeile, optional `,Bezeichnung`), `category` ist `malicious` oder `suspicious`. |

Die Datenbank liegt in `data/suricata.db`. Sie enthält auch deine Harmlos-Markierungen, Gerätenamen und die Benutzer. Zum Sichern eignet sich der Export (siehe oben) besser als eine Kopie der Datenbank.

### Damit alle Grafiken gefüllt sind

In `/etc/suricata/suricata.yaml` sollten im `eve-log` diese Typen aktiv sein (Standard in den meisten Installationen): `flow`, `dns`, `tls`, `http`, für Gerätenamen `dhcp` (und `ethernet: yes` für MAC-Adressen) und für `alert_source: eve` auch `alert`. Zusätzlich muss `fast` (fast.log) aktiviert sein.

## Hinweise

- **eve.json-Kontext:** Beim Einlesen merkt sich das Programm für jede Minute die Byte-Position in eve.json (wenige KB in der Datenbank). Für die Details wird deshalb nur der passende Ausschnitt gelesen, höchstens 64 MB. Nach einer Logrotation sucht es in `eve.json.1`, `eve.json-<Datum>` usw. im selben Ordner. Bereits **komprimierte** (`.gz`) oder gelöschte Logs lassen sich nicht mehr durchsuchen. Die Aufbewahrungsdauer in logrotate bestimmt also, wie weit der Kontext zurückreicht.
- **Kopieren:** Über `http://` sperren Browser die moderne Zwischenablage-API. Deshalb gibt es einen Fallback, und falls auch der blockiert ist, öffnet sich ein Fenster mit dem markierten Text zum Kopieren mit Strg+C. Mit HTTPS klappt das Kopieren direkt.

- Auch mit Login und HTTPS: Gib den Port nicht ins Internet frei. Für den Zugriff von unterwegs ist ein VPN (z. B. WireGuard) die bessere Wahl.
- Logrotation (move oder copytruncate) wird erkannt. Die gelesene Position merkt sich das Programm in der Datenbank, deshalb wird nach einem Neustart nichts doppelt gezählt.
- Bei sehr großen Logs liest das Programm höchstens 32 MB pro Durchlauf und holt einen Rückstand schrittweise auf. Den Fortschritt siehst du im Tab „Status“.
- **Threat-Feeds:**
  - Der Pi lädt rund 25 MB beim ersten Start, danach je nach Feed alle 6 Std bis 7 Tage. Bei Feeds mit nur einer Adresse fragt er vorher, ob sich etwas geändert hat (ETag/Last-Modified), und lädt sonst nichts neu.
  - Alle Feeds zusammen brauchen etwa 80 MB RAM. Der größte Posten ist die HaGeZi-Liste mit ca. 25 MB, sie lässt sich im Tab Threat-Feeds abschalten.
  - Schlägt ein Download fehl oder liefert er eine unbrauchbare Antwort, bleiben die alten Daten aktiv. Der nächste Versuch folgt nach 30 Minuten.
  - Lizenzen: Spamhaus DROP darf nur nicht-kommerziell bzw. in kleinem Umfang genutzt werden. Für die übrigen Feeds gelten die Bedingungen auf den verlinkten Seiten.
- **Live-Ansicht:**
  - Solange sie offen ist, liest der Pi eve.json jede Sekunde statt alle `poll_interval_seconds` und schreibt entsprechend öfter in die Datenbank. 20 Sekunden nach dem Schließen oder einem Tab-Wechsel geht er wieder in den normalen Takt. Im Test kostete die Verbindungsverfolgung etwa 2 µs pro Event, das Zeichnen übernimmt der Browser.
  - Pro Gerät werden höchstens 40 Gegenstellen gezeigt, insgesamt 400 Verbindungen. Verbindungen mit Alert werden immer gezeigt.
  - Suricata schreibt `flow`-Events erst am Ende eines Flows. Verbindungen ohne erkanntes Anwendungsprotokoll (kein DNS/TLS/HTTP-Event) tauchen deshalb erst auf, wenn sie beendet sind. Sehr lange Verbindungen können zwischendurch verschwinden, bis wieder ein Event kommt. Eine längere Haltezeit hilft.
  - Gerätenamen gibt es nur, wenn Suricata DHCP sieht (`dhcp` im eve-log) und ein Gerät seine Adresse neu anfragt. Sie werden in der Datenbank gespeichert.
- **Gerätenamen:**
  - MAC-Adressen sind nur im selben Netzsegment wie der Sensor sichtbar. Liegt ein Router zwischen Sensor und Geräten, tragen alle Pakete die MAC des Routers. Das Dashboard erkennt das, wenn an einer MAC mindestens 4 IPv4-Adressen hängen („geteilte MAC“), und vergibt Namen dann pro IP.
  - Handys und Laptops nutzen oft eine „private“ WLAN-MAC (Badge „private MAC“). Sie bleibt pro WLAN meist gleich. Steht die Funktion auf „rotierend“, ändert sie sich, und der Name muss neu vergeben werden.
  - Namen beziehen sich auf die aktuelle Zuordnung: Ein alter Alert zeigt den Namen des Geräts, das die IP jetzt hat.
- **Grenzen der Bewertung:** Hostnamen werden der IP über alle beobachteten DNS-Antworten zugeordnet. Bei CDN-Adressen (Akamai, Cloudflare …), die viele Domains bedienen, kann eine IP deshalb sowohl „Windows Update“ als auch eine gelistete Domain tragen. Dann gewinnt immer die Blockliste. „Bekannter Dienst“ heißt nicht „garantiert harmlos“; ein Blick in die Details lohnt sich trotzdem.

## Aufbau

```
backend/server.py           Einleser, SQLite, API, Webserver
backend/threatintel.py      Threat-Feeds laden/speichern, Reputation bewerten
backend/live.py             Aktive Verbindungen für die Live-Ansicht
backend/auth.py             Benutzer, Anmeldung, Sitzungen (auch als Kommandozeile)
backend/tls.py              HTTPS, selbstsigniertes Zertifikat, Umleitung
frontend/index.html         Einstieg
frontend/login.html         Anmeldeseite
frontend/app.js             React-App
frontend/style.css          Styles (Hell/Dunkel)
frontend/vendor/            React 18.3.1, htm 3.1.1, Chart.js 4.4.1
config.example.json         Vorlage für config.json (optional)
backend/userdata.py         Export/Import und automatische Sicherung der Nutzerdaten
backend/anomaly.py          Verhaltensprofile lokaler Geräte und Anomalieerkennung
data/                       Datenbank, settings.json, Sicherungen (data/backups/), Feeds (data/feeds/), Zertifikat (data/tls/)
start.sh                    Startskript
users.sh                    Benutzer auf der Kommandozeile verwalten
userdata.sh                 Nutzerdaten exportieren/importieren
suricata-dashboard.service  systemd-Unit
```

### API

Alle Aufrufe außer `POST /api/login` brauchen das Sitzungs-Cookie (sonst `401`). Ändernde Aufrufe (`POST`/`DELETE`) und die Einstellungs-/Benutzer-Abfragen sind Administratoren vorbehalten (sonst `403`).

`POST /api/login {"username":"admin","password":"…","remember":true}` · `POST /api/logout` · `GET /api/me` · `POST /api/me/password {"old":"…","new":"…"}`
`GET /api/users` · `POST /api/users {"op":"add|role|password|delete|logout","username":"…","password":"…","role":"admin|viewer","must_change":true}`
`GET /api/anomalies?status=open|all&days=30` · `GET /api/anomalies/device?dev=<MAC|IP>` · `POST /api/anomalies/ack {"ids":[1,2]}` bzw. `{"all":true}` · `POST /api/anomalies/mute {"dev":"…","kind":"new|volume|time","metric":"domain","mute":true}` · `POST /api/anomalies/check`
`GET /api/userdata/export?users=0|1` · `POST /api/userdata/import {"data":{…Export…},"sections":["device_names","settings"],"mode":"merge|replace"}` · `GET /api/userdata/backups` · `GET /api/userdata/backup?name=…` · `POST /api/userdata/backup_now`
`GET /api/fingerprints?hours=24` · `POST /api/fingerprints/note {"type":"ja4","fp":"t13d…","label":"Home Assistant","harmless":true}` · `GET /api/intel/lookup?q=<IP|Domain|JA3|JA4>`
`GET /api/https` · `POST /api/https {"enabled":true,"https_port":8443,"http_redirect":true,"regenerate":false}` (startet den Dienst neu)

`GET /api/summary|traffic|protocols|top|alerts|alerts/timeline|signatures|flags|status|event_types?hours=24`
`GET /api/alert_context?id=<alert-id>&before=60&after=300` · `GET /api/settings` · `GET /api/settings/check?path=…` · `GET /api/settings/find` · `POST /api/settings {"eve_json":"…","fast_log":"…","alert_source":"fastlog"}`
`GET /api/live?hold=30&alerts=0&lan=1&groups=1` (aktiviert für 20 s den Sekunden-Takt) · `GET /api/devices` · `GET /api/devices/names` · `POST /api/devices {"kind":"mac","key":"3c:22:fb:12:34:56","name":"Drucker"}` (leerer Name löscht) · `POST /api/flags {"gid":1,"sid":2013504,"note":"apt"}` · `DELETE /api/flags?gid=1&sid=2013504`
