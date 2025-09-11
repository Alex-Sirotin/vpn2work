#!/bin/bash

# Настройка SSH SOCKS proxy
setup_socks_proxy() {
    echo "Настройка SOCKS proxy на порту ${SOCKS_PROXY_PORT}..."
    
    # Запуск SOCKS прокси через socat
    socat TCP-LISTEN:${SOCKS_PROXY_PORT},fork,reuseaddr SOCKS4A:127.0.0.1:$SSH_HOST:$SSH_PORT,socksport=9050 &
    
    # Альтернатива: использование ssh для SOCKS proxy
    if [ -n "$SSH_HOST" ] && [ -f "/root/.ssh/id_rsa" ]; then
        ssh -i /root/.ssh/id_rsa \
            -o StrictHostKeyChecking=no \
            -o ServerAliveInterval=60 \
            -N -D 0.0.0.0:${SOCKS_PROXY_PORT} \
            $SSH_USER@$SSH_HOST &
    fi
}

# Настройка TinyProxy для HTTP/HTTPS
setup_http_proxy() {
    echo "Настройка HTTP proxy на порту ${HTTP_PROXY_PORT}..."
    
    # Создаем временный конфиг tinyproxy с динамическими портами
    cat > /tmp/tinyproxy.conf << EOF
User nobody
Group nobody
Port ${HTTP_PROXY_PORT}
Timeout 600
DefaultErrorFile "/usr/share/tinyproxy/default.html"
StatFile "/usr/share/tinyproxy/stats.html"
Logfile "/var/log/tinyproxy/tinyproxy.log"
LogLevel Info
PidFile "/var/run/tinyproxy/tinyproxy.pid"
MaxClients 100
MinSpareServers 5
MaxSpareServers 20
StartServers 10
MaxRequestsPerChild 0
Allow ${PROXY_ALLOW_NETWORK}
ViaProxyName "tinyproxy"
ConnectPort 443
ConnectPort 563
ConnectPort 22
EOF
    
    # Запуск tinyproxy с временным конфигом
    tinyproxy -c /tmp/tinyproxy.conf
}

# Настройка дополнительных портов
setup_additional_ports() {
    # Дополнительный SOCKS порт если указан
    if [ -n "$SOCKS_PROXY_PORT_2" ]; then
        echo "Настройка дополнительного SOCKS proxy на порту ${SOCKS_PROXY_PORT_2}..."
        socat TCP-LISTEN:${SOCKS_PROXY_PORT_2},fork,reuseaddr SOCKS4A:127.0.0.1:$SSH_HOST:$SSH_PORT,socksport=9050 &
    fi
    
    # Дополнительный HTTP порт если указан
    if [ -n "$HTTP_PROXY_PORT_2" ]; then
        echo "Настройка дополнительного HTTP proxy на порту ${HTTP_PROXY_PORT_2}..."
        tinyproxy -c /tmp/tinyproxy.conf -p ${HTTP_PROXY_PORT_2} &
    fi
}

# Основной скрипт
main() {
    # Настройка переменных по умолчанию
    SSH_HOST=${SSH_HOST:-""}
    SSH_PORT=${SSH_PORT:-"22"}
    SSH_USER=${SSH_USER:-"root"}
    HTTP_PROXY_PORT=${HTTP_PROXY_PORT:-"8888"}
    SOCKS_PROXY_PORT=${SOCKS_PROXY_PORT:-"1080"}
    PROXY_ALLOW_NETWORK=${PROXY_ALLOW_NETWORK:-"127.0.0.1 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12"}
    
    echo "Настройка прокси серверов:"
    echo "HTTP Proxy: ${HTTP_PROXY_PORT}"
    echo "SOCKS Proxy: ${SOCKS_PROXY_PORT}"
    echo "Дополнительные порты: HTTP2=${HTTP_PROXY_PORT_2}, SOCKS2=${SOCKS_PROXY_PORT_2}"
    
    # Запуск HTTP proxy
    setup_http_proxy
    
    # Запуск SOCKS proxy (если указан SSH хост)
    if [ -n "$SSH_HOST" ] && [ -f "/root/.ssh/id_rsa" ]; then
        setup_socks_proxy
    else
        echo "SSH хост не указан или SSH ключ не найден, SOCKS proxy не запущен"
    fi
    
    # Запуск дополнительных портов
    setup_additional_ports
    
    # Запуск OpenVPN
    echo "Запуск OpenVPN..."
    exec /usr/local/bin/vpn-login.sh
}

main "$@"
