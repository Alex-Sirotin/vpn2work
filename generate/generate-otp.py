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
