# IONOS WordPress Manager – Runbook

## Initial Setup
1. `python3 src/ionos_wp_manager.py init`
   - Ab sofort werden auch S3 Endpoint, S3 Bucket, IONOS Server ID und Volume ID abgefragt und in die Config geschrieben.
2. `python3 src/ionos_wp_manager.py server-setup`

## Site Management
- Neue Site: `python3 src/ionos_wp_manager.py create-site demo`
- Site löschen: `python3 src/ionos_wp_manager.py delete-site demo`

## Backup & Snapshot
- Backup: `python3 src/ionos_wp_manager.py backup --manual`
  - Nutzt jetzt beliebigen S3-kompatiblen Endpoint (AWS, IONOS S3, MinIO, ...)
- Snapshot: `python3 src/ionos_wp_manager.py snapshot`
  - Nutzt die IONOS Server/Volume IDs aus der Config

## Fehlerbehebung
- Logs: `/var/log/ionos_wp_manager/`
- Config: `~/.config/ionos_wp_manager/credentials` und `~/.config/ionos_wp_manager/config.yml`

## Recovery
- Rollback: Siehe Logs und Backup-Archive

## Monitoring
- Health-Check: `python3 src/ionos_wp_manager.py health`

## Cronjobs
- Backup: `0 2 * * * /usr/local/bin/ionos_wp_manager backup --auto`
- Snapshot: `0 3 * * 0 /usr/local/bin/ionos_wp_manager snapshot`
