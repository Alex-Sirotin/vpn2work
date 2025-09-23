#!/usr/bin/env python3

import pyotp
import sys
import os
from crypto_utils import load_encrypted_secret

def get_secret_value(env_var_name):
    """Получает значение из файла (если задана переменная *_FILE) или из переменной окружения."""
    file_path_var = env_var_name + '_FILE'
    
    # Проверяем, задан ли путь к файлу с секретом
    if file_path_var in os.environ:
        file_path = os.environ[file_path_var]
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r') as f:
                    return f.read().strip()  # Читаем и убираем лишние пробелы и переносы строк
            except Exception as e:
                print(f"Ошибка чтения файла {file_path}: {e}")
                return None
        else:
            print(f"Файл не найден: {file_path}")
            return None
    # Если файл не задан, пробуем получить значение напрямую из переменной окружения
    elif env_var_name in os.environ:
        return os.environ[env_var_name]
    else:
        print(f"Не задана переменная окружения или файл для: {env_var_name}")
        return None

def get_otp_secret():
    """Получение OTP секрета из зашифрованного файла"""
    try:
        # Получаем ключ шифрования через функцию-помощник
        encryption_key = get_secret_value('ENCRYPTION_KEY')
        if not encryption_key:
            raise ValueError("Не удалось получить ENCRYPTION_KEY")

        encrypted_file = '/etc/openvpn/otp_secret.enc'
        if not os.path.exists(encrypted_file):
            raise FileNotFoundError("Зашифрованный файл с секретом не найден")

        secret = load_encrypted_secret(encrypted_file, encryption_key.encode())
        return secret

    except Exception as e:
        print(f"Ошибка получения OTP секрета: {e}")
        return None

def generate_otp():
    """Генерация OTP кода на основе зашифрованного секрета"""
    try:
        secret = get_otp_secret()
        if not secret:
            return None

        # Получаем префикс пароля через функцию-помощник
        password_prefix = get_secret_value('PASSWORD_PREFIX')
        if not password_prefix:
            raise ValueError("Не удалось получить PASSWORD_PREFIX")

        totp = pyotp.TOTP(secret)
        otp_code = totp.now()
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
