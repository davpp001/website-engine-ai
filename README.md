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

**Wichtige Konfigurationsoptionen:**
- `base_domain`: Deine Hauptdomain (z.B. example.com)
- `s3_bucket`: S3-Bucket für Backups
- `s3_endpoint`: S3-kompatibler Endpoint (z.B. für IONOS S3, MinIO, AWS)
- `ionos_server_id`: IONOS Server-ID für Snapshots
- `ionos_volume_id`: IONOS Volume-ID (optional, für Volumen-Snapshots)
- `log_level`: Logging-Level (INFO/DEBUG)

## Security
- Secrets verschlüsselt in `~/.config/ionos_wp_manager/credentials`
- chmod 600 für alle sensiblen Dateien
- Least-Privilege-API-Tokens, SSH-Key-Only, UFW, Fail2Ban

## Doku & Runbook
Siehe [docs/runbook.md](docs/runbook.md)

## Änderungen
- Cloudflare-CLI wird **nicht** mehr benötigt. DNS-Änderungen erfolgen direkt per Cloudflare-API (integriert im Python-Code).
- Für DNS- und SSL-Funktionen ist ein gültiges Cloudflare-API-Token erforderlich (siehe `init`).
