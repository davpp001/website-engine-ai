import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '')))

import typer
from utils.config import (load_config, save_credentials, validate_prefix, load_credentials)
from utils.locking import with_lock
from utils.logging import setup_logging, log_json
from utils.api import (
    cloudflare_create_dns, cloudflare_delete_dns, certbot_issue_ssl,
    s3_upload_backup, ionos_create_snapshot, ionos_rotate_snapshots
)
from utils.security import ensure_permissions, encrypt_secrets

app = typer.Typer()

@app.command()
def init(dry_run: bool = typer.Option(False, '--dry-run'), config: str = typer.Option(None, '--config')):
    """Interaktive Ersteinrichtung der Config/Credentials"""
    setup_logging()
    typer.echo("Willkommen zum IONOS WP Manager Init-Wizard!")
    cf_token = typer.prompt("Cloudflare API Token", hide_input=True)
    ionos_token = typer.prompt("IONOS API Token", hide_input=True)
    ssh_key_path = typer.prompt("Pfad zum SSH Private Key", default=os.path.expanduser("~/.ssh/id_rsa"))
    # Validierung
    if not cf_token or not ionos_token:
        typer.echo("API-Tokens dürfen nicht leer sein.")
        raise typer.Exit(code=2)
    if not os.path.exists(ssh_key_path):
        typer.echo(f"SSH-Key nicht gefunden: {ssh_key_path}")
        raise typer.Exit(code=2)
    creds = {
        'CF_API_TOKEN': cf_token,
        'IONOS_API_TOKEN': ionos_token,
        'SSH_KEY_PATH': ssh_key_path
    }
    if dry_run:
        log_json({"dry-run": True, "creds": list(creds.keys())}, level='INFO')
        typer.echo("[DRY-RUN] Credentials würden gespeichert.")
        raise typer.Exit(code=0)
    save_credentials(creds, encrypt=True)
    typer.echo("Credentials wurden sicher gespeichert.")
    log_json({"status": "ok", "stored": list(creds.keys())}, level='INFO')

@app.command()
def server_setup(dry_run: bool = typer.Option(False, '--dry-run'), config: str = typer.Option(None, '--config')):
    """Server-Grundinstallation und Härtung"""
    setup_logging()
    summary = {}
    cmds = [
        'sudo apt update && sudo apt upgrade -y',
        'sudo ufw allow OpenSSH',
        'sudo ufw allow http',
        'sudo ufw allow https',
        'sudo ufw --force enable',
        'sudo apt install -y fail2ban nginx php8.2-fpm mariadb-server',
        'sudo systemctl enable --now fail2ban',
        'sudo systemctl enable --now nginx',
        'sudo systemctl enable --now php8.2-fpm',
        'sudo systemctl enable --now mariadb',
        'sudo apt install -y python3-pip',
        'sudo pip3 install awscli',
        'sudo apt install -y certbot',
        'sudo apt install -y wp-cli',
        # cloudflare-cli entfernt, stattdessen Cloudflare-API in Python
        'sudo apt install -y ionosctl || sudo pip3 install ionosctl',
    ]
    cronjobs = [
        '0 2 * * * /usr/local/bin/ionos_wp_manager backup --auto',
        '0 3 * * 0 /usr/local/bin/ionos_wp_manager snapshot'
    ]
    if dry_run:
        log_json({"dry-run": True, "commands": cmds, "cronjobs": cronjobs}, level='INFO')
        typer.echo("[DRY-RUN] Server-Setup-Befehle würden ausgeführt.")
        raise typer.Exit(code=0)
    for cmd in cmds:
        typer.echo(f"Führe aus: {cmd}")
        ret = os.system(cmd)
        summary[cmd] = ret
    # Cronjobs anlegen (crontab -l; echo ... | crontab -)
    for job in cronjobs:
        os.system(f'(crontab -l 2>/dev/null; echo "{job}") | sort -u | crontab -')
    log_json({"status": "ok", "summary": summary, "cronjobs": cronjobs}, level='INFO')
    typer.echo("Server-Setup abgeschlossen.")

@app.command()
def create_site(prefix: str, dry_run: bool = typer.Option(False, '--dry-run'), config: str = typer.Option(None, '--config')):
    """Neue WP-Site anlegen (DNS, SSL, DB, WP)"""
    setup_logging()
    try:
        validate_prefix(prefix)
    except Exception as e:
        typer.echo(f"Ungültiger Prefix: {e}")
        raise typer.Exit(code=2)
    try:
        cfg = load_config(config)
    except Exception as e:
        typer.echo(str(e))
        raise typer.Exit(code=2)
    base_domain = cfg.get('base_domain')
    if not base_domain:
        typer.echo("[ERROR] base_domain fehlt in der Config. Bitte Setup-Skript ausführen oder Config ergänzen.")
        raise typer.Exit(code=2)
    full_domain = f"{prefix}.{base_domain}"
    try:
        creds = load_credentials()
    except Exception as e:
        typer.echo(str(e))
        raise typer.Exit(code=2)
    lockfile = f"/tmp/ionos_wp_manager_create_{prefix}.lock"
    db_name = f"wp_{prefix}"
    db_user = f"wp_{prefix}_user"
    @with_lock(lockfile)
    def do_create():
        # DNS
        if dry_run:
            log_json({"dry-run": True, "action": "create-site", "domain": full_domain}, level='INFO')
            typer.echo(f"[DRY-RUN] DNS, SSL, DB, WP würden für {full_domain} angelegt.")
            return
        from utils.api import get_public_ip
        public_ip = get_public_ip()
        if not public_ip:
            typer.echo("[ERROR] Konnte öffentliche Server-IP nicht ermitteln. DNS-Setup abgebrochen.")
            raise typer.Exit(code=2)
        try:
            cf_result = cloudflare_create_dns(full_domain, public_ip, creds['CF_API_TOKEN'])
            log_json({"cloudflare_dns_result": cf_result}, level='INFO')
        except Exception as e:
            typer.echo(f"[ERROR] Cloudflare DNS-Setup fehlgeschlagen: {e}")
            raise typer.Exit(code=2)
        # SSL-Zertifikat
        try:
            ssl_result = certbot_issue_ssl(full_domain, creds['CF_API_TOKEN'])
            log_json({"certbot_result": ssl_result}, level='INFO')
        except Exception as e:
            typer.echo(f"[ERROR] SSL-Zertifikat konnte nicht ausgestellt werden: {e}")
            raise typer.Exit(code=2)
        # SSL in Nginx einbinden
        ssl_conf = f"""
server {{
    listen 443 ssl;
    server_name {full_domain};
    root /var/www/{prefix};
    index index.php index.html index.htm;
    ssl_certificate /etc/letsencrypt/live/{full_domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{full_domain}/privkey.pem;
    include snippets/fastcgi-php.conf;
    location / {{
        try_files $uri $uri/ /index.php?$args;
    }}
    location ~ \.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
    }}
    location ~ /\.ht {{
        deny all;
    }}
}}
"""
        ssl_conf_path = f"/etc/nginx/sites-available/{full_domain}_ssl"
        with open(ssl_conf_path, 'w') as f:
            f.write(ssl_conf)
        os.system(f"ln -sf {ssl_conf_path} /etc/nginx/sites-enabled/{full_domain}_ssl")
        os.system("nginx -t && systemctl reload nginx")
        webroot = f"/var/www/{prefix}"
        os.makedirs(webroot, exist_ok=True)
        os.chmod(webroot, 0o750)
        # DB anlegen (MariaDB)
        db_pass = os.urandom(12).hex()
        os.system(f"sudo mysql -e \"CREATE DATABASE IF NOT EXISTS `{db_name}`; CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{db_pass}'; GRANT ALL ON `{db_name}`.* TO '{db_user}'@'localhost'; FLUSH PRIVILEGES;\"")
        # WP-CLI (immer mit --allow-root, falls root)
        wp_root = "--allow-root" if os.geteuid() == 0 else ""
        os.system(f"wp core download {wp_root} --path={webroot}")
        os.system(f"wp config create {wp_root} --dbname={db_name} --dbuser={db_user} --dbpass={db_pass} --path={webroot} --skip-check")
        admin_pass = os.urandom(12).hex()
        os.system(f"wp core install {wp_root} --url=https://{full_domain} --title='{prefix}' --admin_user=admin_{prefix} --admin_password={admin_pass} --admin_email=admin@{base_domain} --path={webroot}")
        # Nach WP-Install: Rechte setzen
        os.system(f"chown -R www-data:www-data {webroot}")
        os.system(f"chmod -R 755 {webroot}")
        log_json({"url": f"https://{full_domain}", "admin_user": f"admin_{prefix}", "admin_password": admin_pass}, level='INFO')
        typer.echo(f"Site {full_domain} erfolgreich angelegt.")
        # Nginx-Konfiguration
        nginx_conf = f"""
server {{
    listen 80;
    server_name {full_domain};
    root /var/www/{prefix};
    index index.php index.html index.htm;

    location / {{
        try_files $uri $uri/ /index.php?$args;
    }}

    location ~ \.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
    }}

    location ~ /\.ht {{
        deny all;
    }}
}}
"""
        conf_path = f"/etc/nginx/sites-available/{full_domain}"
        with open(conf_path, 'w') as f:
            f.write(nginx_conf)
        os.system(f"ln -sf {conf_path} /etc/nginx/sites-enabled/{full_domain}")
        os.system("nginx -t && systemctl reload nginx")
    try:
        do_create()
    except Exception as e:
        # Rollback: DB, FS, DNS
        db_name = f"wp_{prefix}"
        db_user = f"wp_{prefix}_user"
        os.system(f"sudo mysql -e \"DROP DATABASE IF EXISTS `{db_name}`; DROP USER IF EXISTS '{db_user}'@'localhost';\"")
        os.system(f"rm -rf /var/www/{prefix}")
        cloudflare_delete_dns(full_domain, creds['CF_API_TOKEN'])
        log_json({"status": "rollback", "error": str(e)}, level='ERROR')
        typer.echo(f"Fehler, Rollback durchgeführt: {e}")
        raise typer.Exit(code=2)

@app.command()
def delete_site(prefix: str, dry_run: bool = typer.Option(False, '--dry-run'), config: str = typer.Option(None, '--config')):
    """Site und Ressourcen löschen"""
    setup_logging()
    try:
        validate_prefix(prefix)
    except Exception as e:
        typer.echo(f"Ungültiger Prefix: {e}")
        raise typer.Exit(code=2)
    cfg = load_config(config)
    base_domain = cfg.get('base_domain', os.getenv('BASE_DOMAIN'))
    full_domain = f"{prefix}.{base_domain}"
    creds = load_credentials()
    lockfile = f"/tmp/ionos_wp_manager_delete_{prefix}.lock"
    @with_lock(lockfile)
    def do_delete():
        if dry_run:
            log_json({"dry-run": True, "action": "delete-site", "domain": full_domain}, level='INFO')
            typer.echo(f"[DRY-RUN] Site {full_domain} würde gelöscht.")
            return
        db_name = f"wp_{prefix}"
        db_user = f"wp_{prefix}_user"
        os.system(f"sudo mysql -e \"DROP DATABASE IF EXISTS `{db_name}`; DROP USER IF EXISTS '{db_user}'@'localhost'; FLUSH PRIVILEGES;\"")
        # Webroot löschen
        os.system(f"rm -rf /var/www/{prefix}")
        # Nginx-Konfig löschen
        os.system(f"rm -f /etc/nginx/sites-available/{full_domain} /etc/nginx/sites-enabled/{full_domain}")
        os.system(f"rm -f /etc/nginx/sites-available/{full_domain}_ssl /etc/nginx/sites-enabled/{full_domain}_ssl")
        os.system("nginx -t && systemctl reload nginx")
        # DNS löschen
        cloudflare_delete_dns(full_domain, creds['CF_API_TOKEN'])
        log_json({"status": "deleted", "domain": full_domain}, level='INFO')
        typer.echo(f"Site {full_domain} gelöscht.")
    do_delete()

@app.command()
def backup(auto: bool = typer.Option(False, '--auto'), manual: bool = typer.Option(False, '--manual'), dry_run: bool = typer.Option(False, '--dry-run'), config: str = typer.Option(None, '--config')):
    """Backup aller Sites und DBs"""
    setup_logging()
    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d')
    creds = load_config(os.path.expanduser('~/.config/ionos_wp_manager/credentials'))
    cfg = load_config(config)
    s3_bucket = cfg.get('s3_bucket', os.getenv('S3_BUCKET'))
    lockfile = f"/tmp/ionos_wp_manager_backup.lock"
    @with_lock(lockfile)
    def do_backup():
        db_file = f"/tmp/db-{now}.sql"
        wp_tar = f"/tmp/wp-content-{now}.tar.gz"
        log_path = f"/var/log/ionos_wp_manager/backup-{now}.log"
        if dry_run:
            log_json({"dry-run": True, "db_file": db_file, "wp_tar": wp_tar, "s3_bucket": s3_bucket}, level='INFO')
            typer.echo("[DRY-RUN] Backup würde durchgeführt.")
            return
        os.system(f"mysqldump --all-databases > {db_file}")
        os.system(f"tar czf {wp_tar} /var/www/*/wp-content")
        s3_upload_backup(db_file, s3_bucket, creds.get('AWS_ACCESS_KEY_ID'), creds.get('AWS_SECRET_ACCESS_KEY'))
        s3_upload_backup(wp_tar, s3_bucket, creds.get('AWS_ACCESS_KEY_ID'), creds.get('AWS_SECRET_ACCESS_KEY'))
        os.makedirs('/var/log/ionos_wp_manager', exist_ok=True)
        with open(log_path, 'w') as lf:
            lf.write(f"Backup {now} erfolgreich\n")
        log_json({"s3_paths": [db_file, wp_tar], "log_path": log_path}, level='INFO')
        typer.echo(f"Backup abgeschlossen. Log: {log_path}")
    do_backup()

@app.command()
def snapshot(dry_run: bool = typer.Option(False, '--dry-run'), config: str = typer.Option(None, '--config')):
    """Server-Snapshot erstellen und rotieren"""
    setup_logging()
    creds = load_config(os.path.expanduser('~/.config/ionos_wp_manager/credentials'))
    cfg = load_config(config)
    server_id = cfg.get('server_id', os.getenv('IONOS_SERVER_ID'))
    lockfile = f"/tmp/ionos_wp_manager_snapshot.lock"
    @with_lock(lockfile)
    def do_snapshot():
        if dry_run:
            log_json({"dry-run": True, "action": "snapshot", "server_id": server_id}, level='INFO')
            typer.echo("[DRY-RUN] Snapshot würde erstellt und rotiert.")
            return
        snap_id = ionos_create_snapshot(server_id, creds['IONOS_API_TOKEN'])
        ionos_rotate_snapshots(server_id, creds['IONOS_API_TOKEN'], retention_days=28)
        log_json({"snapshot_id": snap_id, "status": "ok"}, level='INFO')
        typer.echo(f"Snapshot {snap_id} erstellt und Rotation durchgeführt.")
    do_snapshot()

if __name__ == "__main__":
    app()
