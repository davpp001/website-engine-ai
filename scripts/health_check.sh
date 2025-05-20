#!/bin/bash
# Health-Check für Monitoring/Prometheus
if pgrep -f ionos_wp_manager >/dev/null; then
  echo '{"status": "ok"}'
  exit 0
else
  echo '{"status": "error"}'
  exit 2
fi
