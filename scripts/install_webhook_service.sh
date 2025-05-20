#!/bin/bash
# scripts/install_webhook_service.sh
# Installiert und aktiviert den Webhook-Server als systemd-Service

set -e

# Installiere FastAPI und Uvicorn, falls nicht vorhanden
pip install --upgrade fastapi uvicorn

# Setze das Arbeitsverzeichnis (anpassen, falls nötig)
WORKDIR="/root/website-engine-ai"
if [ ! -d "$WORKDIR" ]; then
  echo "WARNUNG: Arbeitsverzeichnis $WORKDIR existiert nicht. Passe das Skript ggf. an."
fi

# Setze das Secret (anpassen!)
WEBHOOK_SECRET="dein-geheimes-token"

# Erstelle systemd-Service-Datei
cat <<EOF | sudo tee /etc/systemd/system/webhook_server.service
[Unit]
Description=Webhook Server (FastAPI/Uvicorn)
After=network.target

[Service]
User=root
WorkingDirectory=$WORKDIR
ExecStart=/usr/bin/env uvicorn webhook_server:app --host 0.0.0.0 --port 8000
Restart=always
Environment=WEBHOOK_SECRET=$WEBHOOK_SECRET

[Install]
WantedBy=multi-user.target
EOF

# Service aktivieren und starten
sudo systemctl daemon-reload
sudo systemctl enable webhook_server
sudo systemctl restart webhook_server

echo "Webhook-Server als systemd-Service installiert und gestartet."
echo "Logs: sudo journalctl -u webhook_server -f"
