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
COPY scripts/get-otp.sh /usr/local/bin/
COPY scripts/ssh-proxy.sh /usr/local/bin/
COPY configs/tinyproxy.conf /etc/tinyproxy/

# Сделать скрипты исполняемыми
RUN chmod +x /usr/local/bin/vpn-login.sh /usr/local/bin/generate-otp.py /usr/local/bin/ssh-proxy.sh /usr/local/bin/get-otp.sh

# Точка монтирования для конфигурации
VOLUME /etc/openvpn

# Запуск OpenVPN и SSH proxy
#CMD ["/usr/local/bin/ssh-proxy.sh"]
