#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="/home/3proxy"
CONFIG_FILE="/home/3proxy/3proxy.cfg"
SERVICE_FILE="/etc/systemd/system/3proxy.service"
PROXY_LIST_FILE="/tmp/proxy_list.txt"
BACKUP_DIR="/home/3proxy/backup"

log() { echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[ОШИБКА]${NC} $1" >&2; }
warning() { echo -e "${YELLOW}[ВНИМАНИЕ]${NC} $1"; }
info() { echo -e "${BLUE:-}[ИНФО]${NC:-} $1"; }

random_string() { tr -dc A-Za-z0-9 </dev/urandom | head -c12; }

show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((current * width / total))
    local remaining=$((width - completed))

    printf "\r[%s%s] %d%% (%d/%d)" \
        "$(printf "%*s" $completed | tr ' ' '=')" \
        "$(printf "%*s" $remaining)" \
        $percentage $current $total
}

gen_ipv6() {
    local hex_chars=$(tr -dc '0-9a-f' < /dev/urandom | head -c 16)
    local block1="${hex_chars:0:4}"
    local block2="${hex_chars:4:4}"
    local block3="${hex_chars:8:4}"
    local block4="${hex_chars:12:4}"
    echo "$1:$block1:$block2:$block3:$block4"
}

check_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        error "Запустите от имени root (используйте sudo)"
        exit 1
    fi
}

check_system() {
    if [[ ! -f /etc/os-release ]]; then
        error "Файл /etc/os-release не найден"
        exit 1
    fi
    if ! grep -qi "ubuntu" /etc/os-release; then
        error "Поддерживается только Ubuntu. Обнаружена ОС: $(grep '^NAME=' /etc/os-release 2>/dev/null || echo 'Неизвестная')"
        exit 1
    fi

    for cmd in lsb_release df awk ping ip ss curl wget tar make; do
        command -v "$cmd" >/dev/null 2>&1 || { error "Команда $cmd не найдена"; exit 1; }
    done

    local version=$(lsb_release -rs | cut -d. -f1 2>/dev/null || echo "0")
    [[ $version -lt 20 ]] && { error "Требуется Ubuntu 20.04+"; exit 1; }

    [[ ! -f /proc/net/if_inet6 ]] && { error "IPv6 не поддерживается"; exit 1; }

    local free_space=$(df / | awk 'NR==2 {print $4}')
    [[ $free_space -lt 1048576 ]] && { error "Недостаточно места на диске (нужно >1GB)"; exit 1; }

    timeout 5 ping -c 1 8.8.8.8 >/dev/null 2>&1 || { error "Нет интернет-соединения"; exit 1; }

    log "Проверка системы пройдена"
}

validate_ipv6_subnet() {
    local subnet="$1"
    [[ ! "$subnet" =~ ^[0-9a-fA-F:]+/[0-9]+$ ]] && return 1
    local prefix_len="${subnet##*/}"
    [[ $prefix_len -lt 48 || $prefix_len -gt 128 ]] && return 1
    return 0
}

validate_ipv4() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        error "Неверный формат IPv4 адреса: $ip"
        return 1
    fi
    local IFS='.'
    local -a octets
    read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if ! [[ "$octet" =~ ^[0-9]+$ ]] || [[ "$octet" -gt 255 ]] || [[ "$octet" -lt 0 ]]; then
            error "Недействительный октет в IPv4 адресе: '$octet' в '$ip'"
            return 1
        fi
    done

    if timeout 3 ping -c 1 "$ip" >/dev/null 2>&1; then
        :
    fi
    return 0
}

validate_port() {
    local port="$1"
    [[ ! "$port" =~ ^[0-9]+$ ]] && return 1
    [[ $port -lt 1024 || $port -gt 65535 ]] && return 1
    ss -tuln | grep -q ":$port " && return 1
    return 0
}

check_port_range() {
    local start_port="$1"
    local count="$2"
    local max_port=$((start_port + count * 2 - 1))
    [[ $max_port -gt 65535 ]] && return 1
    local listening_ports=$(ss -tuln | awk '{print $4}' | grep -o ':[0-9]*$' | cut -d: -f2 | sort -n)
    for ((i=0; i<count; i++)); do
        local socks_port=$((start_port + i))
        local http_port=$((start_port + count + i))
        if echo "$listening_ports" | grep -q "^$socks_port$" || echo "$listening_ports" | grep -q "^$http_port$"; then
            return 1
        fi
    done
    return 0
}

get_user_input() {
    log "Начинаем настройку..."

    while true; do
        echo -n "IPv6 подсеть (например, 2001:db8::/64): "
        read IPV6_SUBNET
        if validate_ipv6_subnet "$IPV6_SUBNET"; then
            break
        else
            error "Неверный формат IPv6 подсети"
        fi
    done

    while true; do
        echo -n "Внешний IPv4 адрес сервера: "
        read EXTERNAL_IPV4
        if validate_ipv4 "$EXTERNAL_IPV4"; then
            break
        else
            error "Неверный IPv4 адрес или адрес недоступен"
        fi
    done

    while true; do
        echo -n "Количество прокси (1-5000): "
        read PROXY_COUNT
        if [[ "$PROXY_COUNT" =~ ^[0-9]+$ ]] && [[ $PROXY_COUNT -ge 1 && $PROXY_COUNT -le 5000 ]]; then
            break
        else
            error "Введите число от 1 до 5000"
        fi
    done

    while true; do
        echo -n "Тип прокси: (1) Классический (SOCKS5 + HTTP) (2) Авто-определение (один порт): "
        read PROXY_TYPE_CHOICE
        if [[ "$PROXY_TYPE_CHOICE" == "1" || "$PROXY_TYPE_CHOICE" == "2" ]]; then
            break
        else
            error "Введите 1 или 2"
        fi
    done

    while true; do
        if [[ "$PROXY_TYPE_CHOICE" == "1" ]]; then
            echo -n "Начальный порт для SOCKS5 (10000-40000): "
        else
            echo -n "Начальный порт для прокси (10000-40000): "
        fi
        read START_PORT
        if validate_port "$START_PORT" && [[ $START_PORT -ge 10000 && $START_PORT -le 40000 ]]; then
            if [[ "$PROXY_TYPE_CHOICE" == "1" ]]; then
                local max_http_port=$((START_PORT + PROXY_COUNT * 2 - 1))
                if [[ $max_http_port -le 65535 ]]; then
                    if check_port_range "$START_PORT" "$PROXY_COUNT"; then
                        HTTP_START_PORT=$((START_PORT + PROXY_COUNT))
                        break
                    else
                        error "Некоторые порты в диапазоне уже заняты"
                    fi
                else
                    error "Недостаточно портов. Максимальный порт будет: $max_http_port"
                fi
            else
                local max_port=$((START_PORT + PROXY_COUNT - 1))
                if [[ $max_port -le 65535 ]]; then
                    break
                else
                    error "Недостаточно портов. Максимальный порт будет: $max_port"
                fi
            fi
        else
            error "Неверный порт или порт занят"
        fi
    done

    while true; do
        echo -n "Аутентификация: (1) Одинаковая для всех (2) Случайная для каждого: "
        read AUTH_CHOICE
        if [[ "$AUTH_CHOICE" == "1" || "$AUTH_CHOICE" == "2" ]]; then
            break
        else
            error "Введите 1 или 2"
        fi
    done

    if [[ "$AUTH_CHOICE" == "1" ]]; then
        while true; do
            echo -n "Имя пользователя: "; read PROXY_USER
            if [[ ${#PROXY_USER} -ge 3 && ! "$PROXY_USER" =~ [[:space:]:] ]]; then
                break
            fi
            error "Имя пользователя должно быть не менее 3 символов и не должно содержать пробелы, табы или двоеточия."
        done
        while true; do
            echo -n "Пароль: "; read -s PROXY_PASS; echo
            if [[ ${#PROXY_PASS} -ge 6 && ! "$PROXY_PASS" =~ [[:space:]:] ]]; then
                break
            fi
            error "Пароль должен быть не менее 6 символов и не должен содержать пробелы, табы или двоеточия."
        done
    fi

    log "Настройка завершена"
}

create_backup() {
    if [[ -f "$CONFIG_FILE" ]]; then
        mkdir -p "$BACKUP_DIR" || return 1
        local backup_filename="3proxy.cfg.$(date +%Y%m%d_%H%M%S)"
        local backup_path="$BACKUP_DIR/$backup_filename"
        cp "$CONFIG_FILE" "$backup_path" || return 1
        log "Создана резервная копия конфигурации: $backup_path"
    fi
    return 0
}

install_dependencies() {
    log "Проверка и установка зависимостей..."
    export DEBIAN_FRONTEND=noninteractive

    if ! apt-get update -qq; then
        error "Не удалось обновить список пакетов"
        exit 1
    fi

    local critical_packages="make build-essential wget curl"
    if ! apt-get install -y $critical_packages; then
        error "Не удалось установить критически важные пакеты: $critical_packages"
        exit 1
    fi

    local packages="git net-tools iproute2 iptables ufw systemd openssl pwgen jq libarchive-tools lsb-release ca-certificates"
    local missing_packages=()
    for pkg in $packages; do
        if ! dpkg -l "$pkg" >/dev/null 2>&1; then
            missing_packages+=("$pkg")
        fi
    done

    if [[ ${#missing_packages[@]} -eq 0 ]]; then
        log "Все дополнительные зависимости уже установлены"
    else
        if ! apt-get install -y "${missing_packages[@]}"; then
            error "Не удалось установить зависимости: ${missing_packages[*]}"
            error "Попробуйте выполнить вручную: apt-get install -y ${missing_packages[*]}"
            exit 1
        fi
    fi

    log "Зависимости установлены"
}

install_3proxy() {
    log "Установка 3proxy..."
    if ! mkdir -p "$SCRIPT_DIR" "$BACKUP_DIR"; then
        error "Не удалось создать директории"
        exit 1
    fi
    cd /tmp || { error "Не удалось перейти в /tmp"; exit 1; }
    rm -rf 3proxy-* 3proxy.*.tar.gz 2>/dev/null || true

    log "Скачиваем 3proxy v0.9.5..."
    local specific_version_url="https://github.com/3proxy/3proxy/archive/refs/tags/0.9.5.tar.gz"
    if ! timeout 60 wget -qO "3proxy-0.9.5.tar.gz" "$specific_version_url"; then
        error "Не удалось скачать 3proxy v0.9.5 с $specific_version_url"
        exit 1
    fi

    log "Распаковка 3proxy v0.9.5..."
    if ! tar -xzf "3proxy-0.9.5.tar.gz"; then
        error "Не удалось распаковать 3proxy-0.9.5.tar.gz"
        exit 1
    fi

    local proxy_dir="3proxy-0.9.5"
    if [[ ! -d "$proxy_dir" ]]; then
        proxy_dir=$(find . -maxdepth 1 -type d -name "3proxy-*" | head -1)
        [[ -z "$proxy_dir" || ! -d "$proxy_dir" ]] && { error "Директория 3proxy не найдена после распаковки"; exit 1; }
    fi
    cd "$proxy_dir" || { error "Не удалось перейти в директорию $proxy_dir"; exit 1; }
    log "Компиляция 3proxy..."
    make -f Makefile.Linux >/dev/null 2>&1 || { error "Не удалось скомпилировать 3proxy"; exit 1; }
    [[ ! -f "bin/3proxy" ]] && { error "Бинарный файл 3proxy не был создан"; exit 1; }
    cp bin/3proxy "$SCRIPT_DIR/" || { error "Не удалось скопировать бинарный файл"; exit 1; }
    chmod 755 "$SCRIPT_DIR/3proxy"
    chown root:root "$SCRIPT_DIR/3proxy"


    log "3proxy установлен"
}

optimize_system() {
    log "Оптимизация системы..."

    if ! grep -q "3proxy limits" /etc/security/limits.conf; then
        cat >> /etc/security/limits.conf << 'EOF'

# 3proxy limits
* soft nofile 1000000
* hard nofile 1000000
root soft nofile 1000000
root hard nofile 1000000
EOF
    fi

    cat > /etc/sysctl.d/99-3proxy.conf << 'EOF'
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 65535
net.ipv4.tcp_rmem = 4096 65536 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_max_syn_backlog = 30000
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.route.flush = 1
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.conf.default.log_martians = 0
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.icmp.echo_ignore_all = 1
net.ipv6.conf.all.proxy_ndp = 1
net.ipv6.conf.default.proxy_ndp = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.ip_nonlocal_bind = 1
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.max_map_count = 262144
fs.file-max = 2000000
kernel.pid_max = 262144
EOF

    if ! sysctl -p /etc/sysctl.d/99-3proxy.conf >/dev/null 2>&1; then
        warning "Некоторые параметры ядра не применились"
    fi

    systemctl disable --now snapd bluetooth cups avahi-daemon 2>/dev/null || true
    log "Система оптимизирована"
}

detect_network_interface() {
    NETWORK_INTERFACE=$(ip route | grep default | head -1 | awk '{print $5}' 2>/dev/null)
    [[ -z "$NETWORK_INTERFACE" ]] && NETWORK_INTERFACE=$(ip link show | grep -E "^[0-9]+: (eth|ens|enp|venet)" | head -1 | cut -d: -f2 | tr -d ' ')
    [[ -z "$NETWORK_INTERFACE" ]] && { error "Не удалось определить сетевой интерфейс"; exit 1; }

    if ! ip link show "$NETWORK_INTERFACE" >/dev/null 2>&1; then
        error "Сетевой интерфейс $NETWORK_INTERFACE не найден"
        exit 1
    fi

    log "Сетевой интерфейс: $NETWORK_INTERFACE"
}

configure_ipv6() {
    log "Настройка IPv6..."
    local ipv6_base="${IPV6_SUBNET%/*}"
    local prefix_len="${IPV6_SUBNET##*/}"
    ipv6_base="${ipv6_base%::}"

    IPV6_ADDRESSES=()
    local success=0
    declare -A used_addresses_map

    local batch_size=50
    local generated_addresses=()

    for ((batch=0; batch*batch_size<PROXY_COUNT; batch++)); do
        generated_addresses=()
        local batch_start=$((batch * batch_size))
        local batch_end=$(( (batch+1) * batch_size ))
        [[ $batch_end -gt $PROXY_COUNT ]] && batch_end=$PROXY_COUNT

        while [[ ${#generated_addresses[@]} -lt $((batch_end - batch_start)) ]]; do
            local ipv6_addr=$(gen_ipv6 "$ipv6_base")
            if [[ -z "${used_addresses_map[$ipv6_addr]:-}" ]]; then
                generated_addresses+=("$ipv6_addr")
                used_addresses_map["$ipv6_addr"]=1
            fi
        done

        for addr in "${generated_addresses[@]}"; do
            if ip -6 addr add "${addr}/${prefix_len}" dev "$NETWORK_INTERFACE" 2>/dev/null; then
                IPV6_ADDRESSES+=("$addr")
                ((success++))
            fi
            [[ $PROXY_COUNT -gt 100 ]] && show_progress $success $PROXY_COUNT
        done
    done

    [[ $PROXY_COUNT -gt 100 ]] && log ""

    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || warning "Не удалось включить IPv6 forwarding"

    log "IPv6 настроен: $success из $PROXY_COUNT адресов"

    if [[ $success -eq 0 ]]; then
        error "Не удалось настроить ни одного IPv6 адреса"
        exit 1
    fi

    local success_rate=$((success * 100 / PROXY_COUNT))
    [[ $success_rate -lt 80 ]] && warning "Низкий процент успешных IPv6 адресов: $success_rate%"
}

generate_auth() {
    log "Генерация аутентификации..."
    PROXY_CREDENTIALS=()

    for ((i=0; i<PROXY_COUNT; i++)); do
        if [[ "$AUTH_CHOICE" == "1" ]]; then
            PROXY_CREDENTIALS+=("$PROXY_USER:$PROXY_PASS")
        else
            local user="user$(printf "%04d" $((i+1)))"
            local pass=$(random_string)
            PROXY_CREDENTIALS+=("$user:$pass")
        fi
    done

    log "Сгенерировано $PROXY_COUNT учетных записей"
}

generate_3proxy_config() {
    log "Генерация конфигурации..."
    create_backup
    mkdir -p "$(dirname "$CONFIG_FILE")" || { error "Не удалось создать директорию для конфигурации"; exit 1; }

    cat > "$CONFIG_FILE" << 'EOF'
daemon
timeouts 1 5 30 60 180 1800 15 60
stacksize 65536
nscache 65536
maxconn 5000
log /dev/null
flush
pidfile /var/run/3proxy.pid

EOF

    local users_line="users "
    for cred in "${PROXY_CREDENTIALS[@]}"; do
        users_line+="${cred%:*}:CL:${cred#*:} "
    done
    echo "$users_line" >> "$CONFIG_FILE"
    echo "" >> "$CONFIG_FILE"

    local success_socks=0
    local success_http=0
    local config_content=""

    for ((i=0; i<PROXY_COUNT; i++)); do
        local ipv6_addr="${IPV6_ADDRESSES[$i]:-}"
        local user_pass_pair="${PROXY_CREDENTIALS[$i]:-}"
        local user=""

        [[ -z "$user_pass_pair" ]] && continue
        user="${user_pass_pair%:*}"
        [[ -z "$ipv6_addr" || -z "$EXTERNAL_IPV4" ]] && continue

        if [[ "$PROXY_TYPE_CHOICE" == "1" ]]; then
            local socks_port=$((START_PORT + i))
            local http_port=$((HTTP_START_PORT + i))
            config_content+="auth strong cache
allow $user
socks -n -a -s0 -64 -g -olSO_REUSEADDR,SO_REUSEPORT -ocTCP_TIMESTAMPS,TCP_NODELAY -osTCP_NODELAY -p$socks_port -i$EXTERNAL_IPV4 -e$ipv6_addr
flush

auth strong cache
allow $user
proxy -n -a -s0 -64 -g -olSO_REUSEADDR,SO_REUSEPORT -ocTCP_TIMESTAMPS,TCP_NODELAY -osTCP_NODELAY -p$http_port -i$EXTERNAL_IPV4 -e$ipv6_addr
flush

"
            ((success_socks++))
            ((success_http++))
        else
            local auto_port=$((START_PORT + i))
            config_content+="auth strong cache
allow $user
auto -n -a -s0 -64 -g -olSO_REUSEADDR,SO_REUSEPORT -ocTCP_TIMESTAMPS,TCP_NODELAY -osTCP_NODELAY -p$auto_port -i$EXTERNAL_IPV4 -e$ipv6_addr
flush

"
            ((success_socks++))
        fi
    done

    echo "$config_content" >> "$CONFIG_FILE"
    if [[ "$PROXY_TYPE_CHOICE" == "1" ]]; then
        log "Конфигурация создана: $success_socks SOCKS5 + $success_http HTTP прокси"
    else
        log "Конфигурация создана: $success_socks AUTO прокси (SOCKS5 + HTTP)"
    fi
}

configure_firewall() {
    log "Настройка firewall..."

    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >/dev/null 2>&1
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        ufw allow ssh >/dev/null 2>&1

        for ((i=0; i<PROXY_COUNT; i++)); do
            ufw allow $((START_PORT + i)) >/dev/null 2>&1
            [[ "$PROXY_TYPE_CHOICE" == "1" ]] && ufw allow $((HTTP_START_PORT + i)) >/dev/null 2>&1
        done

        ufw --force enable >/dev/null 2>&1

    elif command -v iptables >/dev/null 2>&1; then
        iptables -F; iptables -X; iptables -t nat -F; iptables -t nat -X
        iptables -P INPUT DROP; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT

        for ((i=0; i<PROXY_COUNT; i++)); do
            iptables -A INPUT -p tcp --dport $((START_PORT + i)) -j ACCEPT
            [[ "$PROXY_TYPE_CHOICE" == "1" ]] && iptables -A INPUT -p tcp --dport $((HTTP_START_PORT + i)) -j ACCEPT
        done

        mkdir -p /etc/iptables 2>/dev/null || true
        iptables-save > /etc/iptables/rules.v4

        if command -v ip6tables >/dev/null 2>&1; then
            ip6tables -F; ip6tables -X
            ip6tables -P INPUT DROP; ip6tables -P FORWARD ACCEPT; ip6tables -P OUTPUT ACCEPT
            ip6tables -A INPUT -i lo -j ACCEPT
            ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT
            ip6tables-save > /etc/iptables/rules.v6
        fi
    fi

    log "Firewall настроен"
}

create_systemd_service() {
    log "Создание сервиса..."

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=3proxy прокси сервер
After=network.target
Wants=network.target

[Service]
Type=forking
PIDFile=/var/run/3proxy.pid
ExecStart=$SCRIPT_DIR/3proxy $CONFIG_FILE
WorkingDirectory=$SCRIPT_DIR
ExecReload=/bin/kill -USR1 \$MAINPID
ExecStop=/bin/kill -TERM \$MAINPID
Restart=always
RestartSec=5
User=root
Group=root
NoNewPrivileges=true
ProtectSystem=strict
BindReadOnlyPaths=$SCRIPT_DIR
ReadWritePaths=/var/log /var/run /tmp
LimitNOFILE=1000000
LimitNPROC=1000000

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable 3proxy
    log "Сервис создан"
}

generate_proxy_list() {
    log "Генерация списка прокси..."

    local proxy_content=""
    if [[ "$PROXY_TYPE_CHOICE" == "1" ]]; then
        proxy_content+="========== SOCKS5 ==========\n"
        for ((i=0; i<PROXY_COUNT; i++)); do
            local cred="${PROXY_CREDENTIALS[$i]}"
            local user="${cred%:*}"
            local pass="${cred#*:}"
            local ipv6_addr="${IPV6_ADDRESSES[$i]:-}"
            [[ -n "$ipv6_addr" ]] && {
                local socks_port=$((START_PORT + i))
                proxy_content+="$EXTERNAL_IPV4:$socks_port:$user:$pass\n"
            }
        done
        proxy_content+="========== SOCKS5 ==========\n\n"

        proxy_content+="========== HTTP ==========\n"
        for ((i=0; i<PROXY_COUNT; i++)); do
            local cred="${PROXY_CREDENTIALS[$i]}"
            local user="${cred%:*}"
            local pass="${cred#*:}"
            local ipv6_addr="${IPV6_ADDRESSES[$i]:-}"
            [[ -n "$ipv6_addr" ]] && {
                local http_port=$((HTTP_START_PORT + i))
                proxy_content+="$EXTERNAL_IPV4:$http_port:$user:$pass\n"
            }
        done
        proxy_content+="========== HTTP ==========\n"
    else
        for ((i=0; i<PROXY_COUNT; i++)); do
            local cred="${PROXY_CREDENTIALS[$i]}"
            local user="${cred%:*}"
            local pass="${cred#*:}"
            local ipv6_addr="${IPV6_ADDRESSES[$i]:-}"
            [[ -n "$ipv6_addr" ]] && {
                local auto_port=$((START_PORT + i))
                proxy_content+="$EXTERNAL_IPV4:$auto_port:$user:$pass\n"
            }
        done
    fi

    echo -e "$proxy_content" > "$PROXY_LIST_FILE"
    local proxy_count=$(wc -l < "$PROXY_LIST_FILE")
    log "Сгенерировано $proxy_count прокси"

    local upload_success=false
    local download_url=""

    if timeout 5 curl -s --head https://uploader.sh >/dev/null 2>&1; then
        local upload_response
        if upload_response=$(timeout 30 curl -s -F "file=@$PROXY_LIST_FILE" https://uploader.sh/upload 2>/dev/null) && [[ -n "$upload_response" ]]; then
            download_url=$(echo "$upload_response" | grep -o 'https://uploader.sh/[^"]*' | head -1)
            [[ -n "$download_url" ]] && upload_success=true
        fi
    fi

    if [[ "$upload_success" == "false" ]] && timeout 5 curl -s --head https://0x0.st >/dev/null 2>&1; then
        if download_url=$(timeout 30 curl -s -F "file=@$PROXY_LIST_FILE" https://0x0.st 2>/dev/null) && [[ -n "$download_url" ]]; then
            upload_success=true
        fi
    fi

    if [[ "$upload_success" == "true" ]]; then
        log ""
        log "=========================================="
        log "✅ СПИСОК ПРОКСИ ЗАГРУЖЕН!"
        log "📥 Скачать: $download_url"
        log "=========================================="
        log ""
    else
        warning "Сервисы загрузки недоступны"
        info "Список прокси сохранен локально: $PROXY_LIST_FILE"
    fi
}

start_3proxy() {
    log "Запуск сервиса..."
    systemctl stop 3proxy 2>/dev/null || true
    sleep 1
    systemctl start 3proxy
    sleep 3

    if systemctl is-active --quiet 3proxy; then
        log "Сервис запущен успешно"

        local check_count=$((PROXY_COUNT < 5 ? PROXY_COUNT : 5))
        local all_ports=$(ss -tuln | awk '{print $4}' | grep -o ':[0-9]*$' | cut -d: -f2)
        local listening_ports=0

        for ((i=0; i<check_count; i++)); do
            local socks_port=$((START_PORT + i))
            if echo "$all_ports" | grep -q "^$socks_port$"; then
                ((listening_ports++))
            fi
            if [[ "$PROXY_TYPE_CHOICE" == "1" ]]; then
                local http_port=$((HTTP_START_PORT + i))
                if echo "$all_ports" | grep -q "^$http_port$"; then
                    ((listening_ports++))
                fi
            fi
        done

        if [[ $listening_ports -gt 0 ]]; then
            log "Прокси слушают на портах (проверено $listening_ports портов)"
        else
            warning "Сервис запущен, но порты не прослушиваются"
            warning "Проверьте логи: journalctl -u 3proxy -n 20"
        fi
    else
        error "Не удалось запустить сервис"
        systemctl status 3proxy --no-pager
        journalctl -u 3proxy -n 10 --no-pager
        exit 1
    fi
}

test_proxy_functionality() {
    log "Тестирование функциональности прокси..."

    if [[ ${#IPV6_ADDRESSES[@]} -gt 0 && ${#PROXY_CREDENTIALS[@]} -gt 0 ]]; then
        local test_port=$START_PORT
        local test_cred="${PROXY_CREDENTIALS[0]}"
        local test_user="${test_cred%:*}"
        local test_pass="${test_cred#*:}"

        if timeout 10 curl -s --socks5 "$test_user:$test_pass@$EXTERNAL_IPV4:$test_port" \
           --max-time 5 http://httpbin.org/ip >/dev/null 2>&1; then
            log "✅ SOCKS5 прокси работает корректно"
        else
            warning "⚠️  SOCKS5 прокси может работать некорректно"
        fi
    fi
}

show_statistics() {
    log ""
    log "=========================================="
    log "🎉 УСТАНОВКА 3PROXY ЗАВЕРШЕНА!"
    log "=========================================="
    log "📊 Сводка:"
    local real_count=$(wc -l < "$PROXY_LIST_FILE" 2>/dev/null || echo "0")
    log "   • Всего прокси: $real_count"
    if [[ "$PROXY_TYPE_CHOICE" == "1" ]]; then
        log "   • SOCKS5: порты $START_PORT-$((START_PORT + PROXY_COUNT - 1))"
        log "   • HTTP: порты $HTTP_START_PORT-$((HTTP_START_PORT + PROXY_COUNT - 1))"
    else
        log "   • AUTO: порты $START_PORT-$((START_PORT + PROXY_COUNT - 1))"
    fi
    log "   • IPv6 подсеть: $IPV6_SUBNET"
    log "   • Внешний IPv4: $EXTERNAL_IPV4"
    log "   • Интерфейс: $NETWORK_INTERFACE"
    log ""
    log "🔧 Управление:"
    log "   • Статус: systemctl status 3proxy"
    log "   • Перезапуск: systemctl restart 3proxy"
    log "   • Логи: journalctl -u 3proxy -f"
    log ""
    log "📁 Файлы:"
    log "   • Конфигурация: $CONFIG_FILE"
    log "   • Список прокси: $PROXY_LIST_FILE"
    log ""
    log "✅ 3proxy работает!"
    log "=========================================="
}

check_existing_installation() {
    if [[ -f "$SCRIPT_DIR/3proxy" ]] || systemctl is-active --quiet 3proxy 2>/dev/null; then
        warning "3proxy уже установлен - автоматическая переустановка"
        systemctl stop 3proxy 2>/dev/null || true
        systemctl disable 3proxy 2>/dev/null || true
    fi
}

cleanup() {
    local exit_code=$?
    [[ $exit_code -ne 0 && -n "${INSTALLATION_STARTED:-}" ]] && {
        error "Установка не удалась"
        systemctl stop 3proxy 2>/dev/null || true
    }
}

trap cleanup EXIT

main() {
    log "=========================================="
    log "🚀 АВТОУСТАНОВЩИК 3PROXY IPv6"
    log "=========================================="
    log "Автоматическая установка 3proxy с IPv6"
    log ""

    log "Проверка системы..."
    check_root
    check_system
    check_existing_installation

    get_user_input

    log ""
    log "📋 Сводка:"
    log "   • IPv6: $IPV6_SUBNET"
    log "   • IPv4: $EXTERNAL_IPV4"
    log "   • Прокси: $PROXY_COUNT"
    if [[ "$PROXY_TYPE_CHOICE" == "1" ]]; then
        log "   • SOCKS5: $START_PORT-$((START_PORT + PROXY_COUNT - 1))"
        log "   • HTTP: $HTTP_START_PORT-$((HTTP_START_PORT + PROXY_COUNT - 1))"
        log "   • Тип: Классический (SOCKS5 + HTTP)"
    else
        log "   • AUTO: $START_PORT-$((START_PORT + PROXY_COUNT - 1))"
        log "   • Тип: Авто-определение (один порт)"
    fi
    [[ "$AUTH_CHOICE" == "1" ]] && log "   • Аутентификация: Одинаковая для всех" || log "   • Аутентификация: Случайная для каждого"
    log ""

    INSTALLATION_STARTED=1
    log "Установка..."
    install_dependencies
    install_3proxy
    optimize_system
    detect_network_interface
    configure_ipv6
    generate_auth
    generate_3proxy_config
    configure_firewall
    create_systemd_service
    start_3proxy
    test_proxy_functionality
    show_statistics
    generate_proxy_list
    log "Установка завершена успешно!"
}

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"
