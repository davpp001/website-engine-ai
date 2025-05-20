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
    if s3_endpoint:
        s3 = boto3.client(
            's3',
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret,
            endpoint_url=s3_endpoint,
            config=Config(signature_version='s3v4', s3={'addressing_style': 'path'})
        )
    else:
        s3 = boto3.client(
            's3',
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret,
            config=Config(signature_version='s3v4')
        )
    s3.upload_file(file_path, bucket, os.path.basename(file_path))

def ionos_create_snapshot(server_id, token):
    # ionos-cli or REST
    pass

def ionos_rotate_snapshots(server_id, token, retention_days=28):
    # Delete old snapshots
    pass
