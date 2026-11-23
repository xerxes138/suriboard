#!/bin/sh
# Startet das Suricata Dashboard (Python 3 Standardbibliothek, keine Abhaengigkeiten)
cd "$(dirname "$0")" || exit 1
exec python3 backend/server.py --config config.json "$@"
