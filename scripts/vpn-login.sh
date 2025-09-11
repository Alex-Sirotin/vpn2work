#!/bin/bash

# Файл для хранения учетных данных
CREDENTIALS_FILE="/etc/openvpn/auth.txt"

# Основные учетные данные
VPN_USERNAME=${VPN_USERNAME:-"tt_ship"}
PASSWORD_PREFIX=${PASSWORD_PREFIX:-"52"}

# Прокси порты (для информации)
HTTP_PROXY_PORT=${HTTP_PROXY_PORT:-"8888"}
SOCKS_PROXY_PORT=${SOCKS_PROXY_PORT:-"1080"}

# Путь к конфигурационному файлу OpenVPN
OVPN_CONFIG=${OVPN_CONFIG:-"/etc/openvpn/client.ovpn"}
OVPN_CONFIG_FILE=${OVPN_CONFIG_FILE}

# Если указан OVPN_CONFIG_FILE, используем его
if [ -n "$OVPN_CONFIG_FILE" ] && [ -f "$OVPN_CONFIG_FILE" ]; then
    OVPN_CONFIG="$OVPN_CONFIG_FILE"
fi

# Проверяем существование конфигурационного файла
if [ ! -f "$OVPN_CONFIG" ]; then
    echo "Ошибка: Конфигурационный файл OpenVPN не найден: $OVPN_CONFIG"
    exit 1
fi

# Экспортируем переменные для Python скрипта
export PASSWORD_PREFIX

# Функция для генерации пароля с OTP
generate_password() {
    python3 /usr/local/bin/generate-otp.py
}

# Функция для обновления учетных данных
update_credentials() {
    local username=$1
    local password=$2
    
    echo "$username" > "$CREDENTIALS_FILE"
    echo "$password" >> "$CREDENTIALS_FILE"
    
    # Очищаем файл после использования
    sleep 1
    rm -f "$CREDENTIALS_FILE"
}

# Функция для вывода информации о прокси
show_proxy_info() {
    echo "=========================================="
    echo "Прокси серверы доступны на:"
    echo "HTTP Proxy:  http://<docker-host>:${HTTP_PROXY_PORT}"
    echo "SOCKS Proxy: socks5://<docker-host>:${SOCKS_PROXY_PORT}"
    
    if [ -n "$HTTP_PROXY_PORT_2" ]; then
        echo "HTTP Proxy 2: http://<docker-host>:${HTTP_PROXY_PORT_2}"
    fi
    
    if [ -n "$SOCKS_PROXY_PORT_2" ]; then
        echo "SOCKS Proxy 2: socks5://<docker-host>:${SOCKS_PROXY_PORT_2}"
    fi
    
    echo "=========================================="
}

# Основной цикл работы
while true; do
    # Генерируем новый пароль с OTP
    VPN_PASSWORD=$(generate_password)
    
    if [ -z "$VPN_PASSWORD" ]; then
        echo "Ошибка генерации пароля. Повтор через 10 секунд..."
        sleep 10
        continue
    fi
    
    # Обновляем файл с учетными данными
    update_credentials "$VPN_USERNAME" "$VPN_PASSWORD"
    
    # Показываем информацию о прокси
    show_proxy_info
    
    echo "Запуск OpenVPN с конфигурацией: $OVPN_CONFIG"
    
    # Запускаем OpenVPN
    openvpn \
        --config "$OVPN_CONFIG" \
        --auth-user-pass "$CREDENTIALS_FILE" \
        --auth-nocache \
        --auth-retry interact
    
    echo "OpenVPN завершил работу. Переподключение через 5 секунд..."
    sleep 5
done
