#!/bin/bash

# Получаем логин
#USERNAME="asirotin"

# Генерация OTP на лету
OTP=$(python3 generate-otp.py "$VPN_USERNAME")

# OpenVPN ожидает две строки: username и password
echo "$VPN_USERNAME"
echo "$OTP"
