#!/bin/bash
# Vollständiges Server-Setup für IONOS WP Manager (Ubuntu 22.04+)
# Führt alle Installationen und Konfigurationen durch, inkl. cloudflare-cli
set -e

# 1. System-Update
apt update && apt upgrade -y

# 2. Repos für PHP 8.2 und ggf. Nginx
apt install -y software-properties-common curl
add-apt-repository ppa:ondrej/php -y
apt update

# 3. Hauptpakete
apt install -y php8.2-fpm php8.2-mysql nginx mariadb-server fail2ban python3-pip git snapd
systemctl enable --now nginx php8.2-fpm mariadb fail2ban

# 4. Certbot + Cloudflare DNS Plugin
apt install -y certbot python3-certbot-dns-cloudflare

# 5. WP-CLI
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar
mv wp-cli.phar /usr/local/bin/wp

# 6. AWS CLI
pip3 install awscli

# 7. ionosctl
snap install ionosctl

# 8. Node.js & npm (für cloudflare-cli)
apt install -y npm
# cloudflare-cli wird nicht mehr installiert, stattdessen API-Integration in Python

# 9. Teste alle Tools
php -v
nginx -v
mariadb --version
fail2ban-client --version
wp --info
ionosctl --version

# 10. Fertig

echo "\n[OK] Server-Setup abgeschlossen. Alle Tools installiert."

# 11. Config-Setup (interaktiv, falls nicht vorhanden)
CONFIG_DIR="$HOME/.config/ionos_wp_manager"
CONFIG_FILE="$CONFIG_DIR/config.yml"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "[INFO] Lege initiale Konfigurationsdatei an: $CONFIG_FILE"
  mkdir -p "$CONFIG_DIR"
  read -p "Bitte gib deine BASE_DOMAIN (z.B. example.com) ein: " BASE_DOMAIN
  read -p "Bitte gib deinen S3-Bucket-Namen ein: " S3_BUCKET
  read -p "Bitte gib das gewünschte Log-Level ein [INFO]: " LOG_LEVEL
  LOG_LEVEL=${LOG_LEVEL:-INFO}
  cat > "$CONFIG_FILE" <<EOF
base_domain: $BASE_DOMAIN
s3_bucket: $S3_BUCKET
log_level: $LOG_LEVEL
EOF
  echo "[OK] Konfigurationsdatei wurde erstellt."
else
  echo "[INFO] Konfigurationsdatei existiert bereits: $CONFIG_FILE"
fi
