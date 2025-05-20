import requests
import os
import time
import boto3
from botocore.client import Config

def get_public_ip():
    try:
        return requests.get('https://api.ipify.org').text.strip()
    except Exception:
        return None

def cloudflare_create_dns(domain, ip, token):
    # Cloudflare API: Create A record
    zone_id = get_cloudflare_zone_id(domain, token)
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    data = {
        "type": "A",
        "name": domain,
        "content": ip,
        "ttl": 120,
        "proxied": False
    }
    # Prüfe, ob der Record schon existiert
    existing = get_cloudflare_record_id(domain, token, zone_id)
    if existing:
        # Update statt create
        url_update = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{existing}"
        resp = requests.put(url_update, headers=headers, json=data)
        if not resp.ok:
            raise Exception(f"Cloudflare DNS update failed: {resp.text}")
        return resp.json()
    resp = requests.post(url, headers=headers, json=data)
    if not resp.ok:
        raise Exception(f"Cloudflare DNS create failed: {resp.text}")
    return resp.json()

def cloudflare_delete_dns(domain, token):
    # Cloudflare API: Delete A record
    zone_id = get_cloudflare_zone_id(domain, token)
    record_id = get_cloudflare_record_id(domain, token, zone_id)
    if not record_id:
        return
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.delete(url, headers=headers)
    if not resp.ok:
        raise Exception(f"Cloudflare DNS delete failed: {resp.text}")
    return resp.json()

def get_cloudflare_zone_id(domain, token):
    # Get the base domain (zone)
    base = ".".join(domain.split(".")[-2:])
    url = "https://api.cloudflare.com/client/v4/zones"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"name": base, "per_page": 50}
    resp = requests.get(url, headers=headers, params=params)
    if not resp.ok or not resp.json().get("result"):
        raise Exception(f"Cloudflare zone lookup failed: {resp.text}")
    # Suche nach exakter Zone
    for zone in resp.json()["result"]:
        if zone["name"] == base:
            return zone["id"]
    raise Exception(f"Cloudflare zone {base} nicht gefunden. Bitte prüfe, ob die Domain in deinem Cloudflare-Account existiert.")

def get_cloudflare_record_id(domain, token, zone_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"name": domain}
    resp = requests.get(url, headers=headers, params=params)
    if not resp.ok or not resp.json().get("result"):
        return None
    return resp.json()["result"][0]["id"]

def certbot_issue_ssl(domain, cf_token):
    import subprocess
    import os
    # Schreibe temporäre Cloudflare-API-Token-Datei
    cf_creds_path = f"/tmp/cf_{domain}.ini"
    with open(cf_creds_path, 'w') as f:
        f.write(f'dns_cloudflare_api_token = {cf_token}\n')
    os.chmod(cf_creds_path, 0o600)
    cmd = [
        'certbot', 'certonly', '--dns-cloudflare', f'--dns-cloudflare-credentials={cf_creds_path}',
        '--dns-cloudflare-propagation-seconds=60', '-d', domain, '--non-interactive', '--agree-tos', '-m', f'admin@{domain}', '--keep-until-expiring'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(f'Certbot-Fehler: {result.stderr}')
    return result.stdout

def s3_upload_backup(file_path, bucket, aws_key, aws_secret, s3_endpoint=None):
    import logging
    import traceback
    from botocore.exceptions import ClientError
    region = None
    if s3_endpoint and 'ionoscloud.com' in s3_endpoint:
        import re
        m = re.search(r's3\.(eu-central-\d)\.', s3_endpoint)
        if m:
            region = m.group(1)
        else:
            region = 'eu-central-1'
    try:
        logging.info(f"[DEBUG] S3-Upload: file={file_path}, bucket={bucket}, endpoint={s3_endpoint}, region={region}, key={aws_key[:4]}***, secret=***")
        config = Config(signature_version='s3v4', s3={'addressing_style': 'path'})
        if s3_endpoint:
            s3 = boto3.client(
                's3',
                aws_access_key_id=aws_key,
                aws_secret_access_key=aws_secret,
                endpoint_url=s3_endpoint,
                region_name=region,
                use_ssl=True,
                config=config
            )
        else:
            s3 = boto3.client(
                's3',
                aws_access_key_id=aws_key,
                aws_secret_access_key=aws_secret,
                config=config
            )
        with open(file_path, 'rb') as f:
            data = f.read()  # <-- WICHTIG: Bytes statt File-Objekt!
            s3.put_object(Bucket=bucket, Key=os.path.basename(file_path), Body=data, ContentType='application/octet-stream')
    except ClientError as e:
        logging.error(f"[S3-Upload-Error] {e.response}")
        raise Exception(f"Failed to upload {file_path} to {bucket}/{os.path.basename(file_path)}: {e}")
    except Exception as e:
        logging.error(traceback.format_exc())
        raise Exception(f"Failed to upload {file_path} to {bucket}/{os.path.basename(file_path)}: {e}")

def ionos_create_snapshot(server_id, token):
    # ionos-cli or REST
    pass

def ionos_rotate_snapshots(server_id, token, retention_days=28):
    # Delete old snapshots
    pass

def run_restic_backup(
    repo: str,
    password: str,
    sources: list,
    aws_key: str,
    aws_secret: str,
    endpoint: str = None,
    extra_env: dict = None,
    log_path: str = None
):
    """
    Führt ein Restic-Backup zu einem S3-kompatiblen Backend aus.
    sources: Liste der zu sichernden Verzeichnisse/Dateien
    """
    import subprocess
    import shlex
    import logging
    env = os.environ.copy()
    env["RESTIC_REPOSITORY"] = repo
    env["RESTIC_PASSWORD"] = password
    env["AWS_ACCESS_KEY_ID"] = aws_key
    env["AWS_SECRET_ACCESS_KEY"] = aws_secret
    if endpoint:
        # Restic erwartet nur Host, kein https://
        endpoint_host = endpoint.replace("https://", "").replace("http://", "")
        env["RESTIC_REPOSITORY"] = f"s3:{endpoint_host}/{repo.split('/')[-1]}"
    if extra_env:
        env.update(extra_env)
    cmd = ["restic", "backup"] + sources
    try:
        logging.info(f"[Restic] Starte Backup: {' '.join(shlex.quote(x) for x in cmd)}")
        result = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if log_path:
            with open(log_path, "a") as lf:
                lf.write(result.stdout)
                lf.write(result.stderr)
        if result.returncode != 0:
            raise Exception(f"Restic-Backup fehlgeschlagen: {result.stderr}")
        return result.stdout
    except Exception as e:
        logging.error(f"[Restic-Backup-Error] {e}")
        raise
