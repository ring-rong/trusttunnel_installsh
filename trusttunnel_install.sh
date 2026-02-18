#!/bin/bash

# ==============================================================================
# TrustTunnel — Автоматическая установка VPN endpoint
# Совместимо как с чистым сервером, так и с сервером где уже стоит 3x-ui-pro
#
# Использование:
#   sudo bash trusttunnel_install.sh
#
# Опциональные аргументы:
#   --domain    vpn.example.com    Домен для подключения к VPN
#   --username  alice              Логин VPN-пользователя
#   --password  s3cr3t             Пароль VPN-пользователя
#   --email     me@example.com     Email для Let's Encrypt
#   --install-dir /opt/trusttunnel Каталог установки
#   --protocol  all                all | http1 | http2 | quic (через запятую)
# ==============================================================================

set -euo pipefail

# ── Цвета ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[1;34m'; GRY='\033[0;90m'; NC='\033[0m'
ok()   { echo -e "${GRN}  ✔  $1${NC}"; }
err()  { echo -e "${RED}  ✘  $1${NC}" >&2; }
inf()  { echo -e "${BLU}  →  $1${NC}"; }
warn() { echo -e "${YLW}  ⚠  $1${NC}"; }
sep()  { echo -e "${GRY}──────────────────────────────────────────────────────────${NC}"; }

# ── Баннер ───────────────────────────────────────────────────────────────────
clear
echo -e "${BLU}"
cat << 'BANNER'
  _____ ____  _   _ ____ _____   _____ _   _ _   _ _   _ _____ _
 |_   _|  _ \| | | / ___|_   _| |_   _| | | | \ | | \ | | ____| |
   | | | |_) | | | \___ \ | |     | | | | | |  \| |  \| |  _| | |
   | | |  _ <| |_| |___) || |     | | | |_| | |\  | |\  | |___| |___
   |_| |_| \_\\___/|____/ |_|     |_|  \___/|_| \_|_| \_|_____|_____|

BANNER
echo -e "${NC}"
sep

# ── Проверка прав ─────────────────────────────────────────────────────────────
if [ "$(id -u)" != "0" ]; then
    err "Запустите от root: sudo bash $0"
    exit 1
fi

if ! command -v apt &>/dev/null; then
    err "Поддерживается только Ubuntu/Debian (apt)."
    exit 1
fi

# ── Парсинг аргументов ────────────────────────────────────────────────────────
DOMAIN=""
USERNAME=""
PASSWORD=""
EMAIL=""
INSTALL_DIR="/opt/trusttunnel"
PROTOCOL="all"

while [[ $# -gt 0 ]]; do
    case $1 in
        --domain)      DOMAIN="$2";      shift 2 ;;
        --username)    USERNAME="$2";    shift 2 ;;
        --password)    PASSWORD="$2";    shift 2 ;;
        --email)       EMAIL="$2";       shift 2 ;;
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        --protocol)    PROTOCOL="$2";    shift 2 ;;
        *) shift ;;
    esac
done

# ── Определение режима: есть ли уже nginx (x-ui-pro) ─────────────────────────
HAS_NGINX=0
HAS_XRAY_STREAM=0

if systemctl is-active --quiet nginx 2>/dev/null; then
    HAS_NGINX=1
    inf "Обнаружен работающий nginx."
fi

if [ -f /etc/nginx/stream-enabled/stream.conf ]; then
    HAS_XRAY_STREAM=1
    inf "Обнаружена конфигурация nginx stream (3x-ui-pro)."
fi

# ── Определяем IP сервера ──────────────────────────────────────────────────────
SERVER_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || true)
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "неизвестен")
fi

# ── Интерактивные вопросы ─────────────────────────────────────────────────────
sep
echo -e "${GRN}Настройка TrustTunnel VPN${NC}"
sep
echo

if [ -z "$DOMAIN" ]; then
    echo -e "${YLW}Укажите домен (поддомен), через который клиенты будут"
    echo -e "подключаться к вашему VPN-серверу."
    echo -e ""
    echo -e "Требования:"
    echo -e "  • Это должен быть отдельный поддомен (например, vpn.yourdomain.com)"
    echo -e "  • DNS A-запись этого домена должна вести на IP вашего сервера ($SERVER_IP)"
    echo -e "  • Домен нужен для выпуска SSL-сертификата и идентификации сервера"
    echo -e ""
    echo -e "Пример: vpn.example.com, trust.mysite.com${NC}"
    echo
    read -rp "  Домен для подключения к VPN: " DOMAIN
    echo
fi

DOMAIN="${DOMAIN// /}"
if [ -z "$DOMAIN" ]; then
    err "Домен не указан. Выход."
    exit 1
fi

if [ -z "$EMAIL" ]; then
    echo -e "${YLW}Email нужен для Let's Encrypt (уведомления об истечении сертификата).${NC}"
    read -rp "  Email для Let's Encrypt: " EMAIL
    echo
fi

if [ -z "$USERNAME" ]; then
    USERNAME="user_$(openssl rand -hex 4)"
    inf "Сгенерирован логин VPN-пользователя: ${YLW}$USERNAME${NC}"
fi

if [ -z "$PASSWORD" ]; then
    PASSWORD=$(openssl rand -base64 16 | tr -d '/+=')
    inf "Сгенерирован пароль VPN-пользователя: ${YLW}$PASSWORD${NC}"
fi

echo

# ── Проверка DNS ──────────────────────────────────────────────────────────────
sep
inf "Проверка DNS для $DOMAIN..."
DOMAIN_IP=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1{print $1}' || echo "")
if [ -z "$DOMAIN_IP" ]; then
    warn "Не удалось разрезолвить $DOMAIN — DNS-запись может ещё не распространиться."
    warn "Убедитесь, что A-запись $DOMAIN → $SERVER_IP существует, иначе certbot упадёт."
elif [ "$DOMAIN_IP" != "$SERVER_IP" ]; then
    warn "$DOMAIN указывает на $DOMAIN_IP, но IP этого сервера — $SERVER_IP"
    warn "Если DNS неверный, Let's Encrypt не выдаст сертификат."
    read -rp "  Продолжить всё равно? [y/N]: " _ANS
    [[ "$_ANS" =~ ^[yY]$ ]] || { err "Отменено."; exit 1; }
else
    ok "DNS: $DOMAIN → $SERVER_IP ✓"
fi

# ── Установка зависимостей ────────────────────────────────────────────────────
sep
inf "Установка зависимостей..."
apt-get update -qq
apt-get install -y -q curl wget openssl certbot netcat-openbsd

ok "Зависимости установлены."

# ── Установка TrustTunnel endpoint ────────────────────────────────────────────
sep
inf "Установка TrustTunnel endpoint в $INSTALL_DIR..."

mkdir -p "$INSTALL_DIR"
curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh \
    | sh -s - -o "$INSTALL_DIR" -a y

if [ ! -f "$INSTALL_DIR/trusttunnel_endpoint" ]; then
    err "Установка не удалась: бинарный файл не найден."
    exit 1
fi
ok "TrustTunnel endpoint установлен."

# ── Выпуск SSL-сертификата ────────────────────────────────────────────────────
sep
CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

if [ -f "$CERT_PATH" ]; then
    ok "Сертификат для $DOMAIN уже существует, пропускаем выпуск."
else
    inf "Выпуск Let's Encrypt сертификата для $DOMAIN..."

    # Если nginx запущен — используем webroot, иначе standalone
    if [ "$HAS_NGINX" -eq 1 ]; then
        inf "Nginx запущен, используем webroot-режим certbot..."

        # Убедимся, что nginx отдаёт challenge для нашего домена
        ACME_CONF="/etc/nginx/sites-available/_acme_${DOMAIN}.conf"
        mkdir -p /var/www/html
        cat > "$ACME_CONF" <<NGINXCONF
server {
    listen 80;
    server_name ${DOMAIN};
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
}
NGINXCONF
        ln -sf "$ACME_CONF" /etc/nginx/sites-enabled/ 2>/dev/null || true
        nginx -t -q && nginx -s reload
        sleep 1

        certbot certonly \
            --webroot -w /var/www/html \
            -d "$DOMAIN" \
            --non-interactive --agree-tos --email "$EMAIL" --quiet \
        || {
            warn "Webroot не сработал, пробуем standalone (nginx остановится на ~30 сек)..."
            systemctl stop nginx
            certbot certonly \
                --standalone \
                -d "$DOMAIN" \
                --non-interactive --agree-tos --email "$EMAIL" --quiet
            systemctl start nginx
        }
    else
        inf "Nginx не запущен, используем standalone-режим certbot..."
        certbot certonly \
            --standalone \
            -d "$DOMAIN" \
            --non-interactive --agree-tos --email "$EMAIL" --quiet
    fi
fi

if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    err "Файлы сертификата не найдены после выпуска."
    exit 1
fi
ok "SSL-сертификат готов."

# ── Пользователь для сервиса ──────────────────────────────────────────────────
if ! id "trusttunnel" &>/dev/null; then
    useradd -r -s /bin/false -d "$INSTALL_DIR" trusttunnel
fi

# Даём пользователю доступ к сертификатам
chmod 0755 /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
find /etc/letsencrypt/archive -name "*.pem" -exec chmod 644 {} \; 2>/dev/null || true
chgrp -R trusttunnel /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true

chown -R trusttunnel:trusttunnel "$INSTALL_DIR"

# ── Определяем порт TrustTunnel ───────────────────────────────────────────────
# Если nginx/x-ui уже занял 443 — TrustTunnel слушает на внутреннем порту,
# а nginx роутит на него по SNI. Если сервер чистый — слушаем на 443 напрямую.

FORBIDDEN_PORTS=(22 80 443 7443 8080 8443 9443 54321 2053 2096)

find_free_port() {
    local min=$1 max=$2
    local attempts=0
    while [ $attempts -lt 300 ]; do
        local p=$(( RANDOM % (max - min + 1) + min ))
        local busy=0
        for f in "${FORBIDDEN_PORTS[@]}"; do
            [ "$p" -eq "$f" ] && busy=1 && break
        done
        if [ $busy -eq 0 ] && ! ss -tuln 2>/dev/null | grep -q ":${p}[[:space:]]"; then
            echo "$p"; return 0
        fi
        attempts=$(( attempts + 1 ))
    done
    echo "0"
}

# Определяем режим прослушивания
if [ "$HAS_NGINX" -eq 1 ]; then
    # Сосуществование с nginx: внутренний порт, nginx проксирует по SNI
    TT_LISTEN_ADDR="127.0.0.1"
    TT_PORT=$(find_free_port 11000 19999)
    TT_PUBLIC_PORT=443
    COEXIST_MODE=1
    inf "Режим сосуществования с nginx: внутренний порт $TT_PORT, публичный — 443 (через SNI proxy)"
else
    # Чистый сервер: слушаем на 443 напрямую
    TT_LISTEN_ADDR="0.0.0.0"
    TT_PORT=443
    TT_PUBLIC_PORT=443
    COEXIST_MODE=0
    inf "Режим standalone: TrustTunnel слушает на 0.0.0.0:443"
fi

if [ "$TT_PORT" = "0" ]; then
    err "Не удалось найти свободный внутренний порт."
    exit 1
fi

# ── Генерация конфигурационных файлов ─────────────────────────────────────────
sep
inf "Генерация конфигов..."

# vpn.toml
cat > "$INSTALL_DIR/vpn.toml" <<EOF
listen_address = "${TT_LISTEN_ADDR}:${TT_PORT}"
ipv6_available = true
allow_private_network_connections = false
tls_handshake_timeout_secs = 10
client_listener_timeout_secs = 600
connection_establishment_timeout_secs = 30
tcp_connections_timeout_secs = 604800
udp_connections_timeout_secs = 300
credentials_file = "${INSTALL_DIR}/credentials.toml"
rules_file = "${INSTALL_DIR}/rules.toml"

[listen_protocols]

EOF

IFS=',' read -ra PROTOS <<< "$PROTOCOL"
for proto in "${PROTOS[@]}"; do
    proto="${proto// /}"
    if [[ "$proto" == "http1" || "$proto" == "all" ]]; then
        cat >> "$INSTALL_DIR/vpn.toml" <<EOF
[listen_protocols.http1]
upload_buffer_size = 32768

EOF
    fi
    if [[ "$proto" == "http2" || "$proto" == "all" ]]; then
        cat >> "$INSTALL_DIR/vpn.toml" <<EOF
[listen_protocols.http2]
initial_connection_window_size = 8388608
initial_stream_window_size = 131072
max_concurrent_streams = 1000
max_frame_size = 16384
header_table_size = 65536

EOF
    fi
    if [[ "$proto" == "quic" || "$proto" == "all" ]]; then
        cat >> "$INSTALL_DIR/vpn.toml" <<EOF
[listen_protocols.quic]
recv_udp_payload_size = 1350
send_udp_payload_size = 1350
initial_max_data = 104857600
initial_max_stream_data_bidi_local = 1048576
initial_max_stream_data_bidi_remote = 1048576
initial_max_stream_data_uni = 1048576
initial_max_streams_bidi = 4096
initial_max_streams_uni = 4096
max_connection_window = 25165824
max_stream_window = 16777216
disable_active_migration = true
enable_early_data = true
message_queue_capacity = 4096

EOF
    fi
done

cat >> "$INSTALL_DIR/vpn.toml" <<EOF
[forward_protocol]
direct = {}

[metrics]
address = "127.0.0.1:1987"
request_timeout_secs = 3
EOF

# hosts.toml
cat > "$INSTALL_DIR/hosts.toml" <<EOF
[[main_hosts]]
hostname = "${DOMAIN}"
cert_chain_path = "${CERT_PATH}"
private_key_path = "${KEY_PATH}"
EOF

# credentials.toml
cat > "$INSTALL_DIR/credentials.toml" <<EOF
[[client]]
username = "${USERNAME}"
password = "${PASSWORD}"
EOF

# rules.toml
cat > "$INSTALL_DIR/rules.toml" <<EOF
# Блокировка известных сетей сканеров (Shodan, Censys и др.)
[[rule]]
cidr = "208.180.20.0/24"
action = "deny"

[[rule]]
cidr = "198.20.69.0/24"
action = "deny"

[[rule]]
cidr = "198.20.70.0/24"
action = "deny"

[[rule]]
cidr = "71.6.146.0/24"
action = "deny"

[[rule]]
cidr = "71.6.147.0/24"
action = "deny"

[[rule]]
cidr = "162.142.125.0/24"
action = "deny"
EOF

chown trusttunnel:trusttunnel "$INSTALL_DIR"/*.toml
ok "Конфиги созданы."

# ── Добавление в nginx SNI map (только при сосуществовании) ───────────────────
if [ "$COEXIST_MODE" -eq 1 ]; then
    sep
    inf "Настройка nginx SNI proxy для TrustTunnel..."

    if [ "$HAS_XRAY_STREAM" -eq 1 ]; then
        # x-ui-pro уже создал stream.conf со своим map + upstream-ами.
        # Структура его stream.conf:
        #   map $ssl_preread_server_name $sni_name { ... }
        #   upstream xray { server 127.0.0.1:8443; }
        #   upstream www  { server 127.0.0.1:7443; }
        #   server { listen 443; proxy_pass $sni_name; ssl_preread on; }
        #
        # Наш upstream и запись в map добавляем В ТОТ ЖЕ stream.conf,
        # чтобы не создавать конфликтов между несколькими stream-блоками на порту 443.
        # При повторном запуске — удаляем старые наши строки и вставляем свежие.

        STREAM_CONF="/etc/nginx/stream-enabled/stream.conf"

        # Используем Python для надёжного редактирования stream.conf —
        # sed слишком хрупок для многострочного формата nginx.
        python3 - <<PYEOF
import re, sys

conf_path = "/etc/nginx/stream-enabled/stream.conf"
domain    = "${DOMAIN}"
port      = "${TT_PORT}"
marker    = "# trusttunnel-managed"
upstream  = f"upstream trusttunnel_backend {{ server 127.0.0.1:{port}; }} {marker}"
map_entry = f"    {domain}    trusttunnel_backend; {marker}"

with open(conf_path) as f:
    text = f.read()

# 1. Удаляем ВСЕ наши строки — и с маркером, и без (от старых версий скрипта).
#    Чистим: любую строку содержащую trusttunnel_backend или наш домен в map.
lines = [
    l for l in text.splitlines()
    if "trusttunnel_backend" not in l
    and not re.match(r'^\s+' + re.escape(domain) + r'\s', l)
]
# Убираем задвоенные пустые строки которые могут остаться после удаления
cleaned = []
prev_blank = False
for l in lines:
    is_blank = l.strip() == ""
    if is_blank and prev_blank:
        continue
    cleaned.append(l)
    prev_blank = is_blank
text = "\n".join(cleaned)

# 2. Добавляем map-запись сразу после открывающей скобки map-блока
text = re.sub(
    r'(map\s+\$ssl_preread_server_name\s+\$sni_name\s*\{)',
    r'\1\n' + map_entry,
    text, count=1
)

# 3. Вставляем upstream перед ПЕРВЫМ "server {" в файле
text = re.sub(
    r'(?m)^server\s*\{',
    upstream + "\nserver {",
    text, count=1
)

with open(conf_path, "w") as f:
    f.write(text + "\n")

print("  stream.conf обновлён успешно")
PYEOF

        ok "Домен $DOMAIN → 127.0.0.1:$TT_PORT добавлен в nginx SNI map."

        # Убираем отдельный файл upstream если остался от прошлых запусков
        rm -f /etc/nginx/stream-enabled/trusttunnel_upstream.conf 2>/dev/null || true
        rm -f /etc/nginx/stream-enabled/trusttunnel_stream.conf 2>/dev/null || true

    else
        # nginx есть, но stream.conf от x-ui-pro нет (nginx без x-ui-pro).
        # Создаём свой полноценный stream-блок.
        mkdir -p /etc/nginx/stream-enabled
        cat > "/etc/nginx/stream-enabled/trusttunnel_stream.conf" <<EOF
# trusttunnel-managed
upstream trusttunnel_backend {
    server 127.0.0.1:${TT_PORT};
}

map \$ssl_preread_server_name \$tt_backend {
    ${DOMAIN}    trusttunnel_backend;
}

server {
    listen 443;
    proxy_pass \$tt_backend;
    ssl_preread on;
}
EOF
        ok "Создан nginx stream-блок для TrustTunnel на порту 443."

        # Подключаем stream-enabled в nginx.conf если ещё не подключён
        if ! grep -rq "stream-enabled" /etc/nginx/ 2>/dev/null; then
            echo "stream { include /etc/nginx/stream-enabled/*.conf; }" >> /etc/nginx/nginx.conf
        fi
    fi

    # ── Исправляем дублирование ngx_stream_module ───────────────────────────────
    # x-ui-pro добавляет в nginx.conf:
    #   load_module /usr/lib/nginx/modules/ngx_stream_module.so;
    # Ubuntu/Debian грузит его через modules-enabled/50-mod-stream.conf.
    # Двойная загрузка → "[emerg] already loaded".
    # 70-mod-stream-geoip2.conf зависит от stream и должен идти после 50-mod-stream.
    #
    # Правильное решение:
    #   1. Убеждаемся что 50-mod-stream.conf симлинк существует (правильный порядок)
    #   2. Удаляем дублирующий load_module из nginx.conf

    # Восстанавливаем симлинк если он был удалён (предыдущими запусками скрипта)
    # Имя файла в modules-available: mod-stream.conf (без числового префикса)
    STREAM_MOD_SRC=$(find /usr/share/nginx/modules-available/ -name "*mod-stream.conf" \
                     ! -name "*geoip*" 2>/dev/null | head -1)
    if [ -n "$STREAM_MOD_SRC" ] && [ ! -e /etc/nginx/modules-enabled/50-mod-stream.conf ]; then
        ln -sf "$STREAM_MOD_SRC" /etc/nginx/modules-enabled/50-mod-stream.conf
        inf "Восстановлен симлинк 50-mod-stream.conf → $STREAM_MOD_SRC"
    fi

    # Удаляем load_module ngx_stream_module из nginx.conf — он дублирует modules-enabled
    sed -i '/load_module.*ngx_stream_module\.so/d' /etc/nginx/nginx.conf 2>/dev/null || true

    # Подключаем stream-enabled в nginx.conf если ещё не подключён
    if ! grep -rq "stream-enabled" /etc/nginx/ 2>/dev/null; then
        echo "stream { include /etc/nginx/stream-enabled/*.conf; }" >> /etc/nginx/nginx.conf
    fi

    # Проверяем конфиг и перезагружаем
    if ! nginx -t 2>/tmp/nginx_test.log; then
        err "nginx конфиг невалиден после изменений:"
        cat /tmp/nginx_test.log >&2
        exit 1
    fi
    nginx -s reload
    ok "nginx перезагружен с новым SNI routing."
fi

# ── UFW ──────────────────────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
    ufw allow 443/tcp &>/dev/null || true
    ufw allow 443/udp &>/dev/null || true
    if [ "$COEXIST_MODE" -eq 0 ]; then
        ufw allow 80/tcp &>/dev/null || true
    fi
    ufw reload &>/dev/null || true
    ok "UFW: порты открыты."
fi

# ── Systemd сервис ────────────────────────────────────────────────────────────
sep
inf "Создание systemd сервиса..."

# Создаём лог-файл от имени пользователя trusttunnel ДО старта сервиса,
# иначе systemd создаст его как root и endpoint упадёт с Permission denied.
touch /var/log/trusttunnel.log
chown trusttunnel:trusttunnel /var/log/trusttunnel.log
chmod 640 /var/log/trusttunnel.log

cat > /etc/systemd/system/trusttunnel.service <<EOF
[Unit]
Description=TrustTunnel VPN Endpoint
Documentation=https://github.com/TrustTunnel/TrustTunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=trusttunnel
Group=trusttunnel
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/trusttunnel_endpoint \\
    ${INSTALL_DIR}/vpn.toml \\
    ${INSTALL_DIR}/hosts.toml \\
    --logfile /var/log/trusttunnel.log
# Hot-reload TLS при SIGHUP (без остановки сервиса)
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable trusttunnel
systemctl start trusttunnel
sleep 2

if systemctl is-active --quiet trusttunnel; then
    ok "Сервис TrustTunnel запущен и включён в автозапуск."
else
    err "TrustTunnel не запустился. Логи:"
    journalctl -u trusttunnel -n 20 --no-pager || true
    exit 1
fi

# ── Автообновление сертификата ────────────────────────────────────────────────
# Настраиваем ДВА механизма обновления: certbot-таймер systemd + cron (резерв)
sep
inf "Настройка автообновления Let's Encrypt сертификата..."

# Deploy hook: после обновления — hot-reload TrustTunnel (SIGHUP, без даунтайма)
# и reload nginx если он запущен
DEPLOY_HOOK="/etc/letsencrypt/renewal-hooks/deploy/01-trusttunnel-reload.sh"
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > "$DEPLOY_HOOK" <<'HOOKEOF'
#!/bin/bash
# Выполняется certbot автоматически после каждого успешного обновления сертификата.
# Hot-reload TrustTunnel: загружает новый сертификат без разрыва соединений.
systemctl reload trusttunnel 2>/dev/null \
    || kill -HUP "$(systemctl show -p MainPID --value trusttunnel 2>/dev/null)" 2>/dev/null \
    || true
# Перезагружаем nginx если запущен
systemctl is-active --quiet nginx 2>/dev/null && nginx -s reload || true
HOOKEOF
chmod +x "$DEPLOY_HOOK"

# Проверяем, работает ли certbot-таймер systemd
CRON_NEEDED=1
if systemctl list-timers --all 2>/dev/null | grep -qiE 'certbot|letsencrypt'; then
    ok "Certbot systemd-таймер уже активен — автообновление настроено."
    CRON_NEEDED=0
fi

# Резервный cron (на случай отсутствия systemd-таймера)
if [ "$CRON_NEEDED" -eq 1 ]; then
    inf "Systemd-таймер certbot не найден, добавляем cron..."
    # Удаляем старые записи нашего cron и добавляем свежие
    crontab -l 2>/dev/null | grep -v "certbot renew" | crontab - || true
    ( crontab -l 2>/dev/null
      echo "0 3 * * * certbot renew --quiet --deploy-hook '/etc/letsencrypt/renewal-hooks/deploy/01-trusttunnel-reload.sh' >> /var/log/certbot-renew.log 2>&1"
    ) | crontab -
    ok "Cron добавлен: обновление сертификата ежедневно в 03:00."
fi

# Тест обновления (dry-run)
# Certbot возвращает exit code 1 даже если НАШИ домены успешны, но какой-то
# другой домен на сервере (не наш) упал. Проверяем только наш домен явно.
inf "Тест автообновления (dry-run)..."
DRY_RUN_OUT=$(certbot renew --dry-run 2>&1 || true)
if echo "$DRY_RUN_OUT" | grep -q "Simulating renewal of an existing certificate for ${DOMAIN}"; then
    if echo "$DRY_RUN_OUT" | grep -A2 "${DOMAIN}" | grep -q "success\|Successfully"; then
        ok "Тест автообновления для $DOMAIN прошёл успешно."
    else
        # Ищем строку success в общем списке
        if echo "$DRY_RUN_OUT" | grep -q "${CERT_PATH}.*success\|live/${DOMAIN}/fullchain.pem (success)"; then
            ok "Тест автообновления для $DOMAIN прошёл успешно."
        else
            warn "Dry-run для $DOMAIN не прошёл. Проверьте: certbot renew --dry-run -v"
        fi
    fi
else
    warn "Dry-run не нашёл домен $DOMAIN. Проверьте: certbot renew --dry-run"
fi

# ── Экспорт client-config ──────────────────────────────────────────────────────
sep
inf "Генерация конфигурации для клиента..."

CLIENT_CONF_FILE="$INSTALL_DIR/client_${USERNAME}.conf"

# Даём endpoint чуть больше времени на запуск
sleep 2

# ВАЖНО: параметр -a принимает только IP-адрес, не hostname.
# IP сервера уже определён в переменной SERVER_IP в начале скрипта.
if CLIENT_CONFIG=$("$INSTALL_DIR/trusttunnel_endpoint" \
        "$INSTALL_DIR/vpn.toml" \
        "$INSTALL_DIR/hosts.toml" \
        -c "$USERNAME" \
        -a "${SERVER_IP}:${TT_PUBLIC_PORT}" 2>&1); then
    echo "$CLIENT_CONFIG" > "$CLIENT_CONF_FILE"
    chown trusttunnel:trusttunnel "$CLIENT_CONF_FILE"
    chmod 600 "$CLIENT_CONF_FILE"
    ok "Client-config сохранён: $CLIENT_CONF_FILE"
else
    warn "Не удалось экспортировать client-config. Ошибка: $CLIENT_CONFIG"
    CLIENT_CONFIG=""
fi

# ── Загрузка client-config на файлообменник ────────────────────────────────────
# Используем 0x0.st — надёжный, не требует регистрации, отдаёт прямую ссылку
CONFIG_URL=""
if [ -n "$CLIENT_CONFIG" ] && [ -f "$CLIENT_CONF_FILE" ]; then
    inf "Загрузка client-config на временный файлообменник (0x0.st)..."
    CONFIG_URL=$(curl -s --max-time 15 \
        -F "file=@${CLIENT_CONF_FILE}" \
        "https://0x0.st" 2>/dev/null || echo "")

    # Fallback: termbin (текстовый, простая передача через nc)
    if [ -z "$CONFIG_URL" ] || ! echo "$CONFIG_URL" | grep -q "^http"; then
        inf "0x0.st недоступен, пробуем termbin.com..."
        CONFIG_URL=$(timeout 15 bash -c \
            "cat '$CLIENT_CONF_FILE' | nc termbin.com 9999" 2>/dev/null || echo "")
    fi

    if echo "$CONFIG_URL" | grep -q "^http"; then
        ok "Client-config загружен: $CONFIG_URL"
    else
        warn "Не удалось загрузить на файлообменник. Используйте текст ниже."
        CONFIG_URL=""
    fi
fi

# ── Итоговый вывод ────────────────────────────────────────────────────────────
echo
sep
echo -e "${GRN}"
cat << 'DONE'
  ██████╗  ██████╗ ███╗   ██╗███████╗
  ██╔══██╗██╔═══██╗████╗  ██║██╔════╝
  ██║  ██║██║   ██║██╔██╗ ██║█████╗
  ██║  ██║██║   ██║██║╚██╗██║██╔══╝
  ██████╔╝╚██████╔╝██║ ╚████║███████╗
  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚══════╝
DONE
echo -e "${NC}"
sep
echo -e "${GRN}  TrustTunnel VPN успешно установлен!${NC}"
sep
echo
echo -e "  ${YLW}Данные для подключения к VPN:${NC}"
echo -e "  Домен:   ${GRN}${DOMAIN}${NC}"
echo -e "  Порт:    ${GRN}${TT_PUBLIC_PORT}${NC}"
echo -e "  Логин:   ${GRN}${USERNAME}${NC}"
echo -e "  Пароль:  ${GRN}${PASSWORD}${NC}"
echo
sep
echo -e "  ${YLW}Как подключить клиента:${NC}"
echo
echo -e "  ${BLU}Мобильное приложение (iOS / Android):${NC}"
echo -e "    App Store:  https://agrd.io/ios_trusttunnel"
echo -e "    Play Store: https://agrd.io/android_trusttunnel"
echo -e "    Импортируйте client-config файл в приложение."
echo
echo -e "  ${BLU}CLI-клиент (Linux / macOS / Windows):${NC}"
echo -e "    Установка:"
echo -e "      curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnelClient/refs/heads/master/scripts/install.sh | sh -s -"
echo -e "    Настройка (подставьте путь к скачанному client-config):"
echo -e "      ./setup_wizard --mode non-interactive --endpoint_config <путь_к_config> --settings trusttunnel_client.toml"
echo -e "    Запуск:"
echo -e "      sudo ./trusttunnel_client -c trusttunnel_client.toml"
echo
sep
echo -e "  ${YLW}Client-config файл:${NC}"
echo

if [ -n "$CONFIG_URL" ]; then
    echo -e "  ${GRN}Ссылка для скачивания (временная, ~24ч):${NC}"
    echo -e "  ${GRN}→ ${CONFIG_URL}${NC}"
    echo
    echo -e "  ${GRY}Скачайте файл и импортируйте в приложение TrustTunnel.${NC}"
    echo -e "  ${GRY}Или скопируйте текст ниже:${NC}"
else
    echo -e "  ${GRY}Скопируйте содержимое ниже и сохраните в файл client_config.conf:${NC}"
fi
echo

if [ -n "$CLIENT_CONFIG" ]; then
    echo "$CLIENT_CONFIG"
else
    echo -e "  ${YLW}Сгенерируйте вручную после запуска:${NC}"
    echo -e "  cd ${INSTALL_DIR} && ./trusttunnel_endpoint vpn.toml hosts.toml -c ${USERNAME} -a ${SERVER_IP}:${TT_PUBLIC_PORT}"
fi

echo
sep
echo -e "  ${YLW}Управление сервисом:${NC}"
echo -e "  Статус:                 ${GRY}systemctl status trusttunnel${NC}"
echo -e "  Перезапуск:             ${GRY}systemctl restart trusttunnel${NC}"
echo -e "  Reload TLS (без даунт): ${GRY}systemctl reload trusttunnel${NC}"
echo -e "  Логи:                   ${GRY}journalctl -u trusttunnel -f${NC}"
echo
echo -e "  ${YLW}Добавить ещё одного пользователя:${NC}"
echo -e "  ${GRY}nano ${INSTALL_DIR}/credentials.toml${NC}  # добавьте [[client]] блок"
echo -e "  ${GRY}systemctl restart trusttunnel${NC}"
echo
echo -e "  ${YLW}Экспорт config для нового пользователя:${NC}"
echo -e "  ${GRY}cd ${INSTALL_DIR} && ./trusttunnel_endpoint vpn.toml hosts.toml -c ИМЯ -a ${SERVER_IP}:${TT_PUBLIC_PORT}${NC}"
echo
echo -e "  ${YLW}Обновление TrustTunnel:${NC}"
echo -e "  ${GRY}systemctl stop trusttunnel${NC}"
echo -e "  ${GRY}curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh | sh -s - -o ${INSTALL_DIR} -a y${NC}"
echo -e "  ${GRY}systemctl start trusttunnel${NC}"
echo
echo -e "  ${YLW}Автообновление сертификата:${NC}  настроено ✔"
if [ "$CRON_NEEDED" -eq 0 ]; then
    echo -e "  ${GRY}(через certbot systemd-таймер)${NC}"
else
    echo -e "  ${GRY}(через cron, ежедневно в 03:00)${NC}"
fi
sep
echo -e "${GRN}  ⚡ Сохраните данный вывод!${NC}"
sep
