#!/bin/sh
# Nutzerdaten (Gerätenamen, Einstellungen, Markierungen, Benutzer) sichern/wiederherstellen
#   sudo ./userdata.sh export sicherung.json [--no-users]
#   sudo ./userdata.sh import sicherung.json [--mode merge|replace] [--only devices,settings]
#   sudo ./userdata.sh list
#   sudo ./userdata.sh db-backup sicherung.db.gz     # komplette DB inkl. Anomalie-Lernprofilen
#   sudo ./userdata.sh db-restore sicherung.db.gz    # Dienst vorher stoppen
cd "$(dirname "$0")" || exit 1
exec python3 backend/userdata.py --config config.json "$@"
