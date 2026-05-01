#!/usr/bin/env bash
# IP-only deploy (no domain, no TLS). Runs as root from the repo root.
set -euo pipefail

PUBLIC_IP="${PUBLIC_IP:?export PUBLIC_IP=your.vps.ip first}"
GRAYLOG_USER="${GRAYLOG_USER:-socadmin}"
: "${GRAYLOG_PASSWORD:?export GRAYLOG_PASSWORD before running this script}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

echo "── [1/6] install prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y docker.io docker-compose-plugin python3 python3-pip ufw curl

echo "── [2/6] .env — rotate secret, set external URI"
[[ -f .env ]] || cp docker/.env.example .env
if grep -q "^GRAYLOG_PASSWORD_SECRET=ChangeMe" .env; then
  SECRET=$(head -c 96 /dev/urandom | base64 | tr -d '/+=\n' | head -c 96)
  sed -i "s|^GRAYLOG_PASSWORD_SECRET=.*|GRAYLOG_PASSWORD_SECRET=$SECRET|" .env
fi
sed -i "s|^GRAYLOG_HTTP_EXTERNAL_URI=.*|GRAYLOG_HTTP_EXTERNAL_URI=http://$PUBLIC_IP:9000/|" .env

echo "── [3/6] bind nginx LB to 0.0.0.0 (already is) and start stack"
docker compose -f docker-compose.ha.yml up -d
echo "   waiting for Graylog leader..."
for i in {1..60}; do
  curl -sf -u "$GRAYLOG_USER:$GRAYLOG_PASSWORD" -H 'X-Requested-By: cli' \
      http://127.0.0.1:9001/api/system/lbstatus 2>/dev/null | grep -q alive && break
  sleep 5
done

echo "── [4/6] provision streams + dashboards"
python3 scripts/provision-graylog.py   --url http://127.0.0.1:9000 \
        --soc-url "http://$PUBLIC_IP:8090/api/soc/ingest-event" \
        --soc-secret "${SOC_SHARED_SECRET:-demo-secret}" || true
python3 scripts/provision-dashboards.py --url http://127.0.0.1:9000 || true

echo "── [5/6] systemd units for log-server + soc-server"
cat >/etc/systemd/system/siem-log.service <<EOF
[Unit]
Description=SIEM log relay (game + GELF forwarder)
After=docker.service
[Service]
User=root
WorkingDirectory=$REPO_DIR
ExecStart=/usr/bin/python3 -u log-server.py --port 8080 --gelf http://127.0.0.1:12201/gelf --gelf-tcp 127.0.0.1:12202 --gelf-host $(hostname)
Restart=always
[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/siem-soc.service <<EOF
[Unit]
Description=SIEM SOC Console
After=docker.service
[Service]
User=root
WorkingDirectory=$REPO_DIR
Environment=SOC_SHARED_SECRET=demo-secret
ExecStart=/usr/bin/python3 -u soc-server.py --port 8090 --shared-secret demo-secret
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now siem-log.service siem-soc.service

echo "── [6/6] firewall — open SSH + 3 public services"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 39741/tcp    # SSH
ufw allow 9000/tcp     # Graylog UI
ufw allow 8080/tcp     # Game
ufw allow 8090/tcp     # SOC Console
ufw allow 12201/tcp    # GELF HTTP (optional — only if external forwarders send here)
ufw allow 12202/tcp    # GELF TCP  (optional)
ufw --force enable

echo
echo "✓ Deployed on http://$PUBLIC_IP"
echo "   Graylog: http://$PUBLIC_IP:9000"
echo "   SOC:     http://$PUBLIC_IP:8090"
echo "   Game:    http://$PUBLIC_IP:8080"
echo
echo "   Login uses the credentials you set in .env (GRAYLOG_ROOT_USERNAME +"
echo "   GRAYLOG_ROOT_PASSWORD_SHA2)."
