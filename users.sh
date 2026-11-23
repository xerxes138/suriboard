#!/bin/sh
# Benutzer des Suricata Dashboards verwalten (wie "pihole setpassword")
#   sudo ./users.sh list
#   sudo ./users.sh passwd admin
#   sudo ./users.sh add name --role admin|viewer
#   sudo ./users.sh role name viewer
#   sudo ./users.sh del name
#   sudo ./users.sh logout-all
cd "$(dirname "$0")" || exit 1
exec python3 backend/auth.py --config config.json "$@"
