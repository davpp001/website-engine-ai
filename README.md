# IONOS WordPress Manager

Eine sichere, idempotente Automations-CLI für IONOS Cloud, Cloudflare, Let’s Encrypt, S3 und WordPress.

## Features
- Vollautomatisierte Server- und Site-Provisionierung
- Sicheres Secrets-Management
- Backups & Snapshots mit Rotation
- Idempotenz, Locking, Dry-Run, Rollback
- Strukturierte JSON-Logs
- CI/CD mit Tests und Linting

## Quickstart
```bash
pip install -r requirements.txt
python3 src/ionos_wp_manager.py --help
```

## Security
- Secrets verschlüsselt in `~/.config/ionos_wp_manager/credentials`
- chmod 600 für alle sensiblen Dateien
- Least-Privilege-API-Tokens, SSH-Key-Only, UFW, Fail2Ban

## Doku & Runbook
Siehe [docs/runbook.md](docs/runbook.md)

## Änderungen
- Cloudflare-CLI wird **nicht** mehr benötigt. DNS-Änderungen erfolgen direkt per Cloudflare-API (integriert im Python-Code).
- Für DNS- und SSL-Funktionen ist ein gültiges Cloudflare-API-Token erforderlich (siehe `init`).
