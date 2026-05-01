#!/usr/bin/env bash
# End-to-end VPS deploy for the SIEM arcade-game stack.
# Run as a user in the docker group, from the repo root. Requires sudo for
# nginx/certbot/ufw steps. Idempotent.
set -euo pipefail

DOMAIN="${DOMAIN:?export DOMAIN=yourdomain.tld first}"
EMAIL="${EMAIL:?export EMAIL=you@example.com first (Let's Encrypt contact)}"
GRAYLOG_USER="${GRAYLOG_USER:-socadmin}"
: "${GRAYLOG_PASSWORD:?export GRAYLOG_PASSWORD before running this script}"
GRAYLOG_SUB="graylog"
SOC_SUB="soc"
GAME_SUB="game"

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

echo "── [1/7] sanity checks"
command -v docker >/dev/null || { echo "install docker first"; exit 1; }
[[ -f .env ]] || { echo ".env missing — copy from docker/.env.example"; exit 1; }

echo "── [2/7] rotate GRAYLOG_PASSWORD_SECRET if placeholder"
if grep -q "^GRAYLOG_PASSWORD_SECRET=ChangeMe" .env; then
  SECRET=$(head -c 96 /dev/urandom | base64 | tr -d '/+=\n' | head -c 96)
  sed -i "s|^GRAYLOG_PASSWORD_SECRET=.*|GRAYLOG_PASSWORD_SECRET=$SECRET|" .env
  echo "   rotated."
fi
sed -i "s|^GRAYLOG_HTTP_EXTERNAL_URI=.*|GRAYLOG_HTTP_EXTERNAL_URI=https://$GRAYLOG_SUB.$DOMAIN/|" .env

echo "── [3/7] docker compose up"
docker compose -f docker-compose.ha.yml up -d
echo "   waiting for Graylog leader..."
for i in {1..60}; do
  curl -sf -u "$GRAYLOG_USER:$GRAYLOG_PASSWORD" -H 'X-Requested-By: cli' \
      http://127.0.0.1:9001/api/system/lbstatus 2>/dev/null | grep -q alive && break
  sleep 5
done

echo "── [4/7] provision streams + dashboards"
python3 scripts/provision-graylog.py   --url http://127.0.0.1:9000 --soc-secret "${SOC_SHARED_SECRET:-demo-secret}" || true
python3 scripts/provision-dashboards.py --url http://127.0.0.1:9000 || true

echo "── [5/7] start log-server + soc-server under systemd"
sudo tee /etc/systemd/system/siem-log.service >/dev/null <<EOF
[Unit]
Description=SIEM log relay (game + GELF forwarder)
After=docker.service
[Service]
User=$USER
WorkingDirectory=$REPO_DIR
ExecStart=/usr/bin/python3 -u log-server.py --port 8080 --gelf http://127.0.0.1:12201/gelf --gelf-tcp 127.0.0.1:12202 --gelf-host $(hostname)
Restart=always
[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/siem-soc.service >/dev/null <<EOF
[Unit]
Description=SIEM SOC Console
After=docker.service
[Service]
User=$USER
WorkingDirectory=$REPO_DIR
Environment=SOC_SHARED_SECRET=demo-secret
ExecStart=/usr/bin/python3 -u soc-server.py --port 8090 --shared-secret demo-secret
Restart=always
[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now siem-log.service siem-soc.service

echo "── [6/7] nginx reverse proxy"
sudo tee /etc/nginx/sites-available/siem >/dev/null <<EOF
server { listen 80; server_name $GRAYLOG_SUB.$DOMAIN;
  location / { proxy_pass http://127.0.0.1:9000; proxy_set_header Host \$host;
               proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
               proxy_set_header X-Graylog-Server-URL https://\$host/; } }
server { listen 80; server_name $SOC_SUB.$DOMAIN;
  location / { proxy_pass http://127.0.0.1:8090; proxy_set_header Host \$host;
               proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
               proxy_http_version 1.1; proxy_set_header Connection ""; proxy_buffering off; } }
server { listen 80; server_name $GAME_SUB.$DOMAIN;
  location / { proxy_pass http://127.0.0.1:8080; proxy_set_header Host \$host;
               proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; } }
EOF
sudo ln -sf /etc/nginx/sites-available/siem /etc/nginx/sites-enabled/siem
sudo nginx -t && sudo systemctl reload nginx

echo "── [7/7] TLS via Let's Encrypt"
sudo certbot --nginx --non-interactive --agree-tos -m "$EMAIL" \
     -d "$GRAYLOG_SUB.$DOMAIN" -d "$SOC_SUB.$DOMAIN" -d "$GAME_SUB.$DOMAIN"

echo
echo "✓ Deployed."
echo "   Graylog: https://$GRAYLOG_SUB.$DOMAIN"
echo "   SOC:     https://$SOC_SUB.$DOMAIN"
echo "   Game:    https://$GAME_SUB.$DOMAIN"
echo
echo "   Login uses the credentials you set in .env."
