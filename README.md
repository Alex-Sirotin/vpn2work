# Итоговый Docker образ с VPN, OTP аутентификацией и прокси

## Структура проекта

```
vpn-otp-proxy/
├── Dockerfile
├── docker-compose.yml
├── scripts/
│   ├── vpn-login.sh
│   ├── generate-otp.py
│   ├── crypto_utils.py
│   └── ssh-proxy.sh
├── configs/
│   └── tinyproxy.conf
├── secrets/
│   ├── encryption_key.txt
│   ├── password_prefix.txt
│   └── vpn_username.txt
└── README.md
```

## 1. Dockerfile

```dockerfile
FROM alpine:3.18

# Установка необходимых пакетов
RUN apk add --no-cache \
    openvpn \
    python3 \
    py3-pip \
    bash \
    openssl \
    openssh-client \
    socat \
    iptables \
    tinyproxy

# Установка библиотеки для генерации OTP
RUN pip3 install pyotp cryptography

# Создание директорий
RUN mkdir -p /etc/openvpn/ /root/.ssh/

# Копирование скриптов
COPY scripts/vpn-login.sh /usr/local/bin/
COPY scripts/generate-otp.py /usr/local/bin/
COPY scripts/crypto_utils.py /usr/local/bin/
COPY scripts/ssh-proxy.sh /usr/local/bin/
COPY configs/tinyproxy.conf /etc/tinyproxy/

# Сделать скрипты исполняемыми
RUN chmod +x /usr/local/bin/vpn-login.sh /usr/local/bin/generate-otp.py /usr/local/bin/ssh-proxy.sh

# Точка монтирования для конфигурации
VOLUME /etc/openvpn

# Запуск OpenVPN и SSH proxy
CMD ["/usr/local/bin/ssh-proxy.sh"]
```

## 2. Скрипты

### scripts/vpn-login.sh
```bash
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
```

### scripts/generate-otp.py
```python
#!/usr/bin/env python3

import pyotp
import sys
import os
from crypto_utils import load_encrypted_secret

def get_otp_secret():
    """Получение OTP секрета из зашифрованного файла"""
    try:
        # Путь к зашифрованному файлу
        encrypted_file = '/etc/openvpn/otp_secret.enc'
        encryption_key = os.getenv('ENCRYPTION_KEY')
        
        if not encryption_key:
            raise ValueError("ENCRYPTION_KEY не установлен")
        
        if not os.path.exists(encrypted_file):
            raise FileNotFoundError("Зашифрованный файл с секретом не найден")
        
        # Дешифруем секрет
        secret = load_encrypted_secret(encrypted_file, encryption_key.encode())
        return secret
        
    except Exception as e:
        print(f"Ошибка получения OTP секрета: {e}")
        return None

def generate_otp():
    """Генерация OTP кода на основе зашифрованного секрета"""
    try:
        # Получаем секрет
        secret = get_otp_secret()
        if not secret:
            return None
        
        # Получаем префикс пароля из переменной окружения
        password_prefix = os.getenv('PASSWORD_PREFIX', '52')
        
        # Создаем TOTP объект с секретом
        totp = pyotp.TOTP(secret)
        
        # Генерируем текущий OTP код
        otp_code = totp.now()
        
        # Формируем пароль: префикс + OTP код
        password = f"{password_prefix}{otp_code}"
        
        return password
        
    except Exception as e:
        print(f"Ошибка генерации OTP: {e}")
        return None

if __name__ == "__main__":
    password = generate_otp()
    if password:
        print(password)
    else:
        sys.exit(1)
```

### scripts/crypto_utils.py
```python
from cryptography.fernet import Fernet
import base64
import os

def generate_key():
    """Генерация ключа шифрования"""
    return Fernet.generate_key()

def encrypt_secret(secret, key):
    """Шифрование секрета"""
    fernet = Fernet(key)
    encrypted = fernet.encrypt(secret.encode())
    return encrypted

def decrypt_secret(encrypted_secret, key):
    """Дешифрование секрета"""
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_secret)
    return decrypted.decode()

def save_encrypted_secret(secret, key, filename):
    """Сохранение зашифрованного секрета в файл"""
    encrypted = encrypt_secret(secret, key)
    with open(filename, 'wb') as f:
        f.write(encrypted)

def load_encrypted_secret(filename, key):
    """Загрузка и дешифрование секрета из файла"""
    with open(filename, 'rb') as f:
        encrypted = f.read()
    return decrypt_secret(encrypted, key)
```

### scripts/ssh-proxy.sh
```bash
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
```

## 3. Docker Compose

### docker-compose.yml
```yaml
version: '3.8'
services:
  vpn-otp-proxy:
    build: .
    container_name: vpn-otp-proxy
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    environment:
      - ENCRYPTION_KEY_FILE=/run/secrets/encryption_key
      - PASSWORD_PREFIX_FILE=/run/secrets/password_prefix
      - VPN_USERNAME_FILE=/run/secrets/vpn_username
      - OVPN_CONFIG=/etc/openvpn/client.ovpn
      - SSH_HOST=${SSH_HOST}
      - SSH_PORT=${SSH_PORT:-22}
      - SSH_USER=${SSH_USER:-root}
      - HTTP_PROXY_PORT=${HTTP_PROXY_PORT:-8888}
      - SOCKS_PROXY_PORT=${SOCKS_PROXY_PORT:-1080}
      - HTTP_PROXY_PORT_2=${HTTP_PROXY_PORT_2}
      - SOCKS_PROXY_PORT_2=${SOCKS_PROXY_PORT_2}
      - PROXY_ALLOW_NETWORK=127.0.0.1 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12
    secrets:
      - encryption_key
      - password_prefix
      - vpn_username
    volumes:
      - ./configs/client.ovpn:/etc/openvpn/client.ovpn
      - ./secrets/otp_secret.enc:/etc/openvpn/otp_secret.enc
      - ./secrets/ssh_key:/root/.ssh/id_rsa
      - ./secrets/known_hosts:/root/.ssh/known_hosts
    ports:
      - "${HTTP_PROXY_PORT:-8888}:${HTTP_PROXY_PORT:-8888}"
      - "${SOCKS_PROXY_PORT:-1080}:${SOCKS_PROXY_PORT:-1080}"
      - "${HTTP_PROXY_PORT_2}:${HTTP_PROXY_PORT_2}"
      - "${SOCKS_PROXY_PORT_2}:${SOCKS_PROXY_PORT_2}"
    restart: unless-stopped

secrets:
  encryption_key:
    file: ./secrets/encryption_key.txt
  password_prefix:
    file: ./secrets/password_prefix.txt
  vpn_username:
    file: ./secrets/vpn_username.txt
```

### .env.example
```env
# Параметры VPN
SSH_HOST=your-ssh-server.com
SSH_PORT=22
SSH_USER=username

# Параметры прокси
HTTP_PROXY_PORT=8888
SOCKS_PROXY_PORT=1080
HTTP_PROXY_PORT_2=8889
SOCKS_PROXY_PORT_2=1081
```

## 4. Конфигурационные файлы

### configs/tinyproxy.conf
```config
User nobody
Group nobody
Port 8888
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
Allow 127.0.0.1
Allow 192.168.0.0/16
Allow 10.0.0.0/8
Allow 172.16.0.0/12
ViaProxyName "tinyproxy"
ConnectPort 443
ConnectPort 563
ConnectPort 22
```

## 5. Инструкция по использованию

### 1. Подготовка секретов

1. Создайте директорию `secrets` и файлы:
   - `secrets/encryption_key.txt` - ключ шифрования
   - `secrets/password_prefix.txt` - префикс пароля (по умолчанию "52")
   - `secrets/vpn_username.txt` - имя пользователя VPN
   - `secrets/otp_secret.enc` - зашифрованный OTP секрет

2. Сгенерируйте зашифрованный OTP секрет:
   ```bash
   python3 -c "
   from crypto_utils import generate_key, encrypt_secret
   key = generate_key()
   encrypted = encrypt_secret('YOUR_OTP_SECRET', key)
   with open('secrets/otp_secret.enc', 'wb') as f:
       f.write(encrypted)
   print(f'Encryption key: {key.decode()}')
   "
   ```

3. Сохраните ключ шифрования в `secrets/encryption_key.txt`

### 2. Подготовка конфигурации VPN

1. Поместите ваш файл конфигурации OpenVPN в `configs/client.ovpn`

2. При необходимости настройте параметры в `.env` файле

### 3. Запуск контейнера

```bash
# Сборка образа
docker-compose build

# Запуск контейнера
docker-compose up -d

# Просмотр логов
docker-compose logs -f
```

### 4. Использование прокси

#### HTTP прокси:
```
Адрес: IP-адрес вашего Docker хоста
Порт: 8888 (или указанный в настройках)
```

#### SOCKS5 прокси:
```
Адрес: IP-адрес вашего Docker хоста
Порт: 1080 (или указанный в настройках)
```

### 5. Настройка браузера

#### Ручная настройка:
- Укажите HTTP прокси в настройках браузера
- Или используйте расширение типа Proxy SwitchyOmega

#### Автоматическая настройка (PAC):
```javascript
function FindProxyForURL(url, host) {
    // Сайты для VPN
    var vpnSites = ["example.com", "vpn-only-site.com"];
    
    // Локальные адреса
    if (isPlainHostName(host) || 
        shExpMatch(host, "*.local") ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0") ||
        isInNet(host, "127.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }
    
    // Проверяем VPN сайты
    for (var i = 0; i < vpnSites.length; i++) {
        if (shExpMatch(host, vpnSites[i]) || dnsDomainIs(host, vpnSites[i])) {
            return "PROXY your-docker-host:8888; SOCKS5 your-docker-host:1080";
        }
    }
    
    // Остальные сайты напрямую
    return "DIRECT";
}
```

### 6. Использование SSH через VPN

```bash
# Прямое подключение через VPN туннель
ssh user@host

# Через SOCKS прокси
ssh -o ProxyCommand="nc -x your-docker-host:1080 %h %p" user@host
```

## 6. Управление контейнером

```bash
# Остановка контейнера
docker-compose down

# Перезапуск контейнера
docker-compose restart

# Обновление OTP секрета
# 1. Отредактируйте secrets/otp_secret.enc
# 2. Перезапустите контейнер

# Просмотр статуса
docker-compose ps

# Просмотр логов
docker-compose logs -f
```

Это решение предоставляет полнофункциональный VPN-прокси сервер с OTP аутентификацией, поддерживающий как HTTP, так и SOCKS5 прокси, с возможностью гибкой настройки портов и маршрутизации трафика.