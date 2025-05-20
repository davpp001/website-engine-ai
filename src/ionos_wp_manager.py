#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '')))

import typer
from utils.config import (load_config, save_credentials, validate_prefix, load_credentials)
from utils.locking import with_lock
from utils.logging import setup_logging, log_json
from utils.api import (
    cloudflare_create_dns, cloudflare_delete_dns, certbot_issue_ssl,
    s3_upload_backup, ionos_create_snapshot, ionos_rotate_snapshots, run_restic_backup
)
from utils.security import ensure_permissions, encrypt_secrets

app = typer.Typer()

@app.command()
def init(dry_run: bool = typer.Option(False, '--dry-run'), config: str = typer.Option(None, '--config'), show_credentials: bool = typer.Option(False, '--show-credentials', help='Credentials sichtbar eingeben')):
    """Interaktive Ersteinrichtung der Config/Credentials (Multi-Cloud-ready, Restic-ready)"""
    setup_logging()
    typer.echo("Willkommen zum IONOS WP Manager Init-Wizard!")
    prompt_kwargs = {'hide_input': not show_credentials}
    cf_token = typer.prompt("Cloudflare API Token", **prompt_kwargs)
    ionos_token = typer.prompt("IONOS API Token", **prompt_kwargs)
    aws_key = typer.prompt("S3 Access Key ID (AWS/IONOS/MinIO)", **prompt_kwargs)
    aws_secret = typer.prompt("S3 Secret Access Key (AWS/IONOS/MinIO)", **prompt_kwargs)
    s3_endpoint = typer.prompt("S3 Endpoint (z.B. https://s3.eu-central-3.ionoscloud.com)", default="https://s3.amazonaws.com")
    s3_bucket = typer.prompt("S3 Bucket Name")
    restic_password = typer.prompt("Restic-Repo-Passwort (wird für alle Backups benötigt)", **prompt_kwargs)
    ionos_server_id = typer.prompt("IONOS Server ID (für Snapshots)")
    ionos_volume_id = typer.prompt("IONOS Volume ID (optional, für Volumen-Snapshots)", default="")
    ssh_key_path = typer.prompt("Pfad zum SSH Private Key", default=os.path.expanduser("~/.ssh/id_rsa"))
    base_domain = typer.prompt("Base Domain (z.B. example.com)")
    ssl_email = typer.prompt("E-Mail-Adresse für SSL/Certbot (z.B. admin@example.com)", default=f"admin@{base_domain}")
    # Validierung
    if not all([cf_token, ionos_token, aws_key, aws_secret, s3_bucket, s3_endpoint, ionos_server_id, restic_password, base_domain, ssl_email]):
        typer.echo("API-Tokens, S3-, Restic-, IONOS-Parameter und E-Mail dürfen nicht leer sein.")
        raise typer.Exit(code=2)
    if not os.path.exists(ssh_key_path):
        typer.echo(f"SSH-Key nicht gefunden: {ssh_key_path}")
        raise typer.Exit(code=2)
    creds = {
        'CF_API_TOKEN': cf_token,
        'IONOS_API_TOKEN': ionos_token,
        'AWS_ACCESS_KEY_ID': aws_key,
        'AWS_SECRET_ACCESS_KEY': aws_secret,
        'S3_ENDPOINT': s3_endpoint,
        'RESTIC_PASSWORD': restic_password,
        'SSH_KEY_PATH': ssh_key_path
    }
    config_data = {
        's3_bucket': s3_bucket,
        's3_endpoint': s3_endpoint,
        'ionos_server_id': ionos_server_id,
        'ionos_volume_id': ionos_volume_id,
        'base_domain': base_domain,
        'ssl_email': ssl_email
    }
    config_file = config or os.path.expanduser('~/.config/ionos_wp_manager/config.yml')
    import yaml
    os.makedirs(os.path.dirname(config_file), exist_ok=True)
    with open(config_file, 'w') as f:
        yaml.dump(config_data, f)
    if dry_run:
        log_json({"dry-run": True, "creds": list(creds.keys()), "config": config_data}, level='INFO')
        typer.echo("[DRY-RUN] Credentials und Config würden gespeichert.")
        raise typer.Exit(code=0)
    save_credentials(creds, encrypt=True)
    typer.echo("Credentials und Config wurden sicher gespeichert.")
    log_json({"status": "ok", "stored": list(creds.keys()), "config": config_data}, level='INFO')

@app.command()
def server_setup(dry_run: bool = typer.Option(False, '--dry-run'), config: str = typer.Option(None, '--config')):
    """Server-Grundinstallation und Härtung (inkl. Python-Abhängigkeiten, Restic, Tools, S3-Bucket-Check)"""
    setup_logging()
    summary = {}
    # Cronjobs für Backup und Snapshot
    cronjobs = [
        '0 2 * * * /usr/local/bin/ionos_wp_manager backup --auto',
        '0 3 * * 0 /usr/local/bin/ionos_wp_manager snapshot'
    ]
    cmds = [
        'sudo apt update && sudo apt upgrade -y',
        # Systempakete und Tools
        'sudo apt install -y fail2ban nginx php8.2-fpm mariadb-server python3-pip python3-venv restic certbot wp-cli ionosctl tar curl git unzip',
        'sudo systemctl enable --now fail2ban',
        'sudo systemctl enable --now nginx',
        'sudo systemctl enable --now php8.2-fpm',
        'sudo systemctl enable --now mariadb',
        # Python requirements (im Projektverzeichnis!)
        'pip3 install --upgrade pip',
        'pip3 install --upgrade -r requirements.txt',
        # Optional: Symlink CLI
        'sudo ln -sf $(pwd)/src/ionos_wp_manager.py /usr/local/bin/ionos_wp_manager',
    ]
    # S3-Bucket-Check und Anlage (wenn möglich)
    try:
        import yaml
        cfg = load_config(config)
        creds = load_credentials()
        s3_endpoint = cfg.get('s3_endpoint', creds.get('S3_ENDPOINT'))
        s3_bucket = cfg.get('s3_bucket')
        aws_key = creds.get('AWS_ACCESS_KEY_ID')
        aws_secret = creds.get('AWS_SECRET_ACCESS_KEY')
        if s3_endpoint and s3_bucket and aws_key and aws_secret:
            import boto3
            from botocore.client import Config
            s3 = boto3.client(
                's3',
                aws_access_key_id=aws_key,
                aws_secret_access_key=aws_secret,
                endpoint_url=s3_endpoint,
                config=Config(signature_version='s3v4', s3={'addressing_style': 'path'})
            )
            buckets = [b['Name'] for b in s3.list_buckets().get('Buckets', [])]
            if s3_bucket not in buckets:
                s3.create_bucket(Bucket=s3_bucket)
                typer.echo(f"[OK] S3-Bucket '{s3_bucket}' wurde angelegt.")
            else:
                typer.echo(f"[OK] S3-Bucket '{s3_bucket}' existiert bereits.")
    except Exception as e:
        typer.echo(f"[WARN] S3-Bucket-Check/Anlage übersprungen: {e}")
    # Restic-Repo-Init (optional, falls Passwort vorhanden)
    try:
        creds = load_credentials()
        cfg = load_config(config)
        restic_password = creds.get('RESTIC_PASSWORD')
        s3_endpoint = cfg.get('s3_endpoint', creds.get('S3_ENDPOINT'))
        s3_bucket = cfg.get('s3_bucket')
        if restic_password and s3_endpoint and s3_bucket:
            import subprocess
            import shlex
            repo = f"s3:{s3_endpoint.replace('https://','').replace('http://','')}/{s3_bucket}"
            env = os.environ.copy()
            env['RESTIC_PASSWORD'] = restic_password
            env['AWS_ACCESS_KEY_ID'] = creds.get('AWS_ACCESS_KEY_ID')
            env['AWS_SECRET_ACCESS_KEY'] = creds.get('AWS_SECRET_ACCESS_KEY')
            # Prüfe, ob Repo schon initialisiert ist
            check = subprocess.run(["restic", "snapshots", "-r", repo], env=env, capture_output=True, text=True)
            if 'Is there a repository at the following location?' in check.stderr or 'config file does not exist' in check.stderr:
                init = subprocess.run(["restic", "init", "-r", repo], env=env, capture_output=True, text=True)
                if init.returncode == 0:
                    typer.echo(f"[OK] Restic-Repo '{repo}' wurde initialisiert.")
                else:
                    typer.echo(f"[WARN] Restic-Repo-Init fehlgeschlagen: {init.stderr}")
            else:
                typer.echo(f"[OK] Restic-Repo '{repo}' ist bereits initialisiert.")
    except Exception as e:
        typer.echo(f"[WARN] Restic-Repo-Init übersprungen: {e}")
    # Home-Verzeichnis-Check
    home_dir = os.path.expanduser('~')
    if not os.path.isdir(home_dir) or not os.access(home_dir, os.W_OK):
        typer.echo(f"[ERROR] Home-Verzeichnis {home_dir} existiert nicht oder ist nicht beschreibbar. Bitte prüfen!")
        raise typer.Exit(code=2)
    # Nach der Installation: Tool-Checks
    required_tools = [
        ('restic', '--version'),
        ('wp', '--info'),
        ('ionosctl', '--version'),
        ('certbot', '--version'),
        ('mariadb', '--version'),
        ('nginx', '-v'),
        ('fail2ban-client', '--version')
    ]
    missing_tools = []
    restic_version = None
    for tool, arg in required_tools:
        ret = os.system(f"which {tool} > /dev/null 2>&1")
        if ret != 0:
            missing_tools.append(tool)
        if tool == 'restic' and ret == 0:
            import subprocess
            result = subprocess.run([tool, '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                import re
                m = re.search(r'restic ([0-9]+\.[0-9]+\.[0-9]+)', result.stdout)
                if m:
                    restic_version = m.group(1)
    if missing_tools:
        typer.echo(f"[WARN] Folgende Tools fehlen oder sind nicht im PATH: {', '.join(missing_tools)}")
    else:
        typer.echo("[OK] Alle benötigten Tools sind installiert und im PATH.")
    # Restic-Versionscheck
    def version_tuple(v):
        return tuple(map(int, (v.split("."))))
    if restic_version and version_tuple(restic_version) < (0, 15, 0):
        typer.echo(f"[WARN] Restic-Version {restic_version} ist veraltet (<0.15.0). Für S3/IONOS wird >=0.15.0 empfohlen. Update mit: sudo apt install -y restic")
    elif restic_version:
        typer.echo(f"[OK] Restic-Version {restic_version} ist ausreichend.")
    # Cronjobs anlegen (crontab -l; echo ... | crontab -)
    for job in cronjobs:
        os.system(f'(crontab -l 2>/dev/null; echo "{job}") | sort -u | crontab -')
    log_json({"status": "ok", "summary": summary, "cronjobs": cronjobs}, level='INFO')
    typer.echo("Server-Setup abgeschlossen.")
    typer.echo("\n[HINWEIS] Teste die Installation mit:\n  ionos_wp_manager create-site test123\n  ionos_wp_manager backup --dry-run\n  ionos_wp_manager delete-site test123 --dry-run\n")

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

    # --- Automatische Suffix-Nummerierung ---
    import glob
    import re
    orig_prefix = prefix
    def resource_exists(pfx):
        webroot = f"/var/www/{pfx}"
        db_name = f"wp_{pfx}"
        db_user = f"wp_{pfx}_user"
        # Webroot
        if os.path.exists(webroot):
            return True
        # DB
        db_check = os.popen(f"sudo mysql -N -e \"SHOW DATABASES LIKE '{db_name}';\"").read().strip()
        if db_check:
            return True
        # User
        user_check = os.popen(f"sudo mysql -N -e \"SELECT User FROM mysql.user WHERE User='{db_user}';\"").read().strip()
        if user_check:
            return True
        # Nginx config
        conf_path = f"/etc/nginx/sites-available/{pfx}.{base_domain}"
        if os.path.exists(conf_path):
            return True
        # DNS (Cloudflare): nicht geprüft, da API-Call nötig
        return False
    # Suffix-Logik
    suffix = 0
    candidate = prefix
    while resource_exists(candidate):
        suffix += 1
        candidate = f"{orig_prefix}{suffix+1 if suffix > 0 else ''}"
    if candidate != prefix:
        typer.echo(f"[INFO] Prefix '{prefix}' existiert bereits, verwende stattdessen '{candidate}'.")
    prefix = candidate
    full_domain = f"{prefix}.{base_domain}"
    try:
        creds = load_credentials()
    except Exception as e:
        typer.echo(str(e))
        raise typer.Exit(code=2)
    lockfile = f"/tmp/ionos_wp_manager_create_{prefix}.lock"
    @with_lock(lockfile)
    def do_create():
        db_name = f"wp_{prefix}"
        db_user = f"wp_{prefix}_user"
        db_pass = os.urandom(12).hex()
        print(f"DEBUG: db_name={db_name}, db_user={db_user}, db_pass={db_pass}")
        sql = f'''
CREATE DATABASE IF NOT EXISTS `{db_name}`;
CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{db_pass}';
GRANT ALL ON `{db_name}`.* TO '{db_user}'@'localhost';
FLUSH PRIVILEGES;
'''
        with open('/tmp/wp_create.sql', 'w') as f:
            f.write(sql)
        print(f"DEBUG: SQL-File written to /tmp/wp_create.sql:")
        print(sql)
        os.system("sudo mysql < /tmp/wp_create.sql")
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
        db_name = f"wp_{prefix}"
        db_user = f"wp_{prefix}_user"
        sql = f'''
DROP DATABASE IF EXISTS `{db_name}`;
DROP USER IF EXISTS '{db_user}'@'localhost';
FLUSH PRIVILEGES;
'''
        with open('/tmp/wp_delete.sql', 'w') as f:
            f.write(sql)
        os.system("sudo mysql < /tmp/wp_delete.sql")
        os.system(f"rm -rf /var/www/{prefix}")
        cloudflare_delete_dns(full_domain, creds['CF_API_TOKEN'])
        log_json({"status": "rollback", "error": str(e)}, level='ERROR')
        typer.echo(f"Fehler, Rollback durchgeführt: {e}")
        raise typer.Exit(code=2)

@app.command()
def delete_site(prefix: str, dry_run: bool = typer.Option(False, '--dry-run'), config: str = typer.Option(None, '--config'), force: bool = typer.Option(False, '--force')):
    """Site und Ressourcen löschen (löscht auch SSL-Zertifikate und prüft alle Reste)"""
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
        status = {}
        if dry_run:
            log_json({"dry-run": True, "action": "delete-site", "domain": full_domain}, level='INFO')
            typer.echo(f"[DRY-RUN] Site {full_domain} würde gelöscht.")
            return
        db_name = f"wp_{prefix}"
        db_user = f"wp_{prefix}_user"
        # 1. DB & User löschen
        try:
            sql = f'''
DROP DATABASE IF EXISTS `{db_name}`;
DROP USER IF EXISTS '{db_user}'@'localhost';
FLUSH PRIVILEGES;
'''
            with open('/tmp/wp_delete.sql', 'w') as f:
                f.write(sql)
            ret = os.system("sudo mysql < /tmp/wp_delete.sql")
            status['db'] = 'ok' if ret == 0 else 'error'
        except Exception as e:
            status['db'] = f'error: {e}'
            if not force:
                log_json({"step": "delete-db", "status": "error", "error": str(e)}, level='ERROR')
                typer.echo(f"[ERROR] DB/User-Löschung fehlgeschlagen: {e}")
                return
        # 2. Webroot löschen
        webroot = f"/var/www/{prefix}"
        try:
            if os.path.exists(webroot):
                os.system(f"rm -rf {webroot}")
                if os.path.exists(webroot):
                    typer.echo(f"[WARN] Webroot {webroot} konnte nicht gelöscht werden!")
                    status['webroot'] = 'error'
                else:
                    typer.echo(f"[OK] Webroot {webroot} gelöscht.")
                    status['webroot'] = 'ok'
            else:
                typer.echo(f"[INFO] Webroot {webroot} war nicht vorhanden.")
                status['webroot'] = 'notfound'
        except Exception as e:
            status['webroot'] = f'error: {e}'
            if not force:
                log_json({"step": "delete-webroot", "status": "error", "error": str(e)}, level='ERROR')
                return
        # 3. Nginx-Konfig löschen
        try:
            os.system(f"rm -f /etc/nginx/sites-available/{full_domain} /etc/nginx/sites-enabled/{full_domain}")
            os.system(f"rm -f /etc/nginx/sites-available/{full_domain}_ssl /etc/nginx/sites-enabled/{full_domain}_ssl")
            os.system("nginx -t && systemctl reload nginx")
            status['nginx'] = 'ok'
        except Exception as e:
            status['nginx'] = f'error: {e}'
            if not force:
                log_json({"step": "delete-nginx", "status": "error", "error": str(e)}, level='ERROR')
                return
        # 4. SSL-Zertifikate löschen
        try:
            ssl_live = f"/etc/letsencrypt/live/{full_domain}"
            ssl_archive = f"/etc/letsencrypt/archive/{full_domain}"
            ssl_renew = f"/etc/letsencrypt/renewal/{full_domain}.conf"
            for path in [ssl_live, ssl_archive, ssl_renew]:
                if os.path.exists(path):
                    os.system(f"rm -rf {path}")
            status['ssl'] = 'ok'
        except Exception as e:
            status['ssl'] = f'error: {e}'
            if not force:
                log_json({"step": "delete-ssl", "status": "error", "error": str(e)}, level='ERROR')
                return
        # 5. DNS löschen
        try:
            cloudflare_delete_dns(full_domain, creds['CF_API_TOKEN'])
            status['dns'] = 'ok'
        except Exception as e:
            status['dns'] = f'error: {e}'
            if not force:
                log_json({"step": "delete-dns", "status": "error", "error": str(e)}, level='ERROR')
                return
        log_json({"status": "deleted", "domain": full_domain, "details": status}, level='INFO')
        typer.echo(f"Site {full_domain} gelöscht. Details: {status}")
    do_delete()

@app.command()
def backup(auto: bool = typer.Option(False, '--auto'), manual: bool = typer.Option(False, '--manual'), dry_run: bool = typer.Option(False, '--dry-run'), config: str = typer.Option(None, '--config')):
    """Backup aller Sites und DBs"""
    setup_logging()
    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d')
    creds = load_credentials()
    cfg = load_config(config)
    # Debug-Ausgabe der geladenen Credentials (ohne Secrets)
    debug_creds = {k: (v if 'SECRET' not in k else '***') for k, v in creds.items()}
    typer.echo(f"[DEBUG] Geladene Credentials: {debug_creds}")
    typer.echo(f"[DEBUG] Geladene Config: {cfg}")
    s3_bucket = cfg.get('s3_bucket', os.getenv('S3_BUCKET'))
    s3_endpoint = cfg.get('s3_endpoint', creds.get('S3_ENDPOINT'))
    lockfile = f"/tmp/ionos_wp_manager_backup.lock"
    @with_lock(lockfile)
    def do_backup():
        db_file = f"/tmp/db-{now}.sql"
        wp_tar = f"/tmp/wp-content-{now}.tar.gz"
        log_path = f"/var/log/ionos_wp_manager/backup-{now}.log"
        if dry_run:
            log_json({"dry-run": True, "db_file": db_file, "wp_tar": wp_tar, "s3_bucket": s3_bucket, "s3_endpoint": s3_endpoint}, level='INFO')
            typer.echo("[DRY-RUN] Backup würde durchgeführt.")
            return
        # DB-Backup
        ret_db = os.system(f"mysqldump --all-databases > {db_file}")
        if ret_db != 0 or not os.path.exists(db_file):
            log_json({"status": "error", "step": "mysqldump", "file": db_file}, level='ERROR')
            typer.echo(f"[ERROR] DB-Backup fehlgeschlagen: {db_file}")
            return
        # WP-Content-Backup
        ret_tar = os.system(f"tar czf {wp_tar} /var/www/*/wp-content")
        if ret_tar != 0 or not os.path.exists(wp_tar):
            log_json({"status": "error", "step": "tar", "file": wp_tar}, level='ERROR')
            typer.echo(f"[ERROR] WP-Content-Backup fehlgeschlagen: {wp_tar}")
            if os.path.exists(db_file):
                os.remove(db_file)
            return
        # S3-Upload DB
        try:
            s3_upload_backup(db_file, s3_bucket, creds.get('AWS_ACCESS_KEY_ID'), creds.get('AWS_SECRET_ACCESS_KEY'), s3_endpoint=s3_endpoint)
        except Exception as e:
            log_json({"status": "error", "step": "s3_upload_db", "error": str(e)}, level='ERROR')
            typer.echo(f"[ERROR] S3-Upload DB fehlgeschlagen: {e}")
            if os.path.exists(db_file):
                os.remove(db_file)
            if os.path.exists(wp_tar):
                os.remove(wp_tar)
            return
        # S3-Upload WP-Content
        try:
            s3_upload_backup(wp_tar, s3_bucket, creds.get('AWS_ACCESS_KEY_ID'), creds.get('AWS_SECRET_ACCESS_KEY'), s3_endpoint=s3_endpoint)
        except Exception as e:
            log_json({"status": "error", "step": "s3_upload_wp", "error": str(e)}, level='ERROR')
            typer.echo(f"[ERROR] S3-Upload WP-Content fehlgeschlagen: {e}")
            if os.path.exists(db_file):
                os.remove(db_file)
            if os.path.exists(wp_tar):
                os.remove(wp_tar)
            return
        # Aufräumen
        if os.path.exists(db_file):
            os.remove(db_file)
        if os.path.exists(wp_tar):
            os.remove(wp_tar)
        os.makedirs('/var/log/ionos_wp_manager', exist_ok=True)
        with open(log_path, 'w') as lf:
            lf.write(f"Backup {now} erfolgreich\n")
        log_json({"s3_paths": [db_file, wp_tar], "log_path": log_path, "status": "ok"}, level='INFO')
        typer.echo(f"Backup abgeschlossen. Log: {log_path}")
    do_backup()

@app.command()
def snapshot(dry_run: bool = typer.Option(False, '--dry-run'), config: str = typer.Option(None, '--config')):
    """Server-Snapshot erstellen und rotieren"""
    setup_logging()
    creds = load_credentials()
    cfg = load_config(config)
    server_id = cfg.get('ionos_server_id', os.getenv('IONOS_SERVER_ID'))
    volume_id = cfg.get('ionos_volume_id', os.getenv('IONOS_VOLUME_ID'))
    lockfile = f"/tmp/ionos_wp_manager_snapshot.lock"
    @with_lock(lockfile)
    def do_snapshot():
        if dry_run:
            log_json({"dry-run": True, "action": "snapshot", "server_id": server_id, "volume_id": volume_id}, level='INFO')
            typer.echo("[DRY-RUN] Snapshot würde erstellt und rotiert.")
            return
        snap_id = ionos_create_snapshot(server_id, creds['IONOS_API_TOKEN'])
        ionos_rotate_snapshots(server_id, creds['IONOS_API_TOKEN'], retention_days=28)
        log_json({"snapshot_id": snap_id, "status": "ok"}, level='INFO')
        typer.echo(f"Snapshot {snap_id} erstellt und Rotation durchgeführt.")
    do_snapshot()

@app.command()
def backup_restic(
    sources: str = typer.Option("/etc/hosts", help="Kommagetrennte Liste der Backup-Quellen (z.B. /etc,/var/www)"),
    repo: str = typer.Option(None, help="Restic-Repo (z.B. s3:s3.eu-central-3.ionoscloud.com/my-backups)"),
    password: str = typer.Option(None, help="Restic-Repo-Passwort"),
    config: str = typer.Option(None, '--config'),
    dry_run: bool = typer.Option(False, '--dry-run'),
):
    """Backup per Restic zu S3-kompatiblem Backend (empfohlen für IONOS S3)"""
    setup_logging()
    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d')
    creds = load_credentials()
    cfg = load_config(config)
    s3_endpoint = cfg.get('s3_endpoint', creds.get('S3_ENDPOINT'))
    aws_key = creds.get('AWS_ACCESS_KEY_ID')
    aws_secret = creds.get('AWS_SECRET_ACCESS_KEY')
    backup_sources = [x.strip() for x in sources.split(",") if x.strip()]
    restic_repo = repo or f"s3:{s3_endpoint.replace('https://','').replace('http://','')}/{cfg.get('s3_bucket')}"
    restic_password = password or os.getenv('RESTIC_PASSWORD') or "changeme123"
    log_path = f"/var/log/ionos_wp_manager/restic-backup-{now}.log"
    if dry_run:
        typer.echo(f"[DRY-RUN] Restic-Backup würde ausgeführt: {restic_repo} -> {backup_sources}")
        return
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        out = run_restic_backup(
            repo=restic_repo,
            password=restic_password,
            sources=backup_sources,
            aws_key=aws_key,
            aws_secret=aws_secret,
            endpoint=s3_endpoint,
            log_path=log_path
        )
        typer.echo(f"[OK] Restic-Backup abgeschlossen. Log: {log_path}")
        typer.echo(out)
    except Exception as e:
        typer.echo(f"[ERROR] Restic-Backup fehlgeschlagen: {e}")

if __name__ == "__main__":
    app()
