#!/usr/bin/env python3

from crypto_utils import generate_key, encrypt_secret, save_encrypted_secret
import sys
import os

def main():
    if len(sys.argv) != 2:
        print("Использование: python prepare_secret.py <OTP_SECRET>")
        sys.exit(1)
    
    secret = sys.argv[1]
    
    # Генерируем ключ шифрования
    key = generate_key()
    
    # Сохраняем зашифрованный секрет
    save_encrypted_secret(secret, key, 'otp_secret.enc')
    
    print("Зашифрованный секрет сохранен в otp_secret.enc")
    print(f"Ключ шифрования (сохраните его безопасно):")
    print(key.decode())
    
    # Создаем .env файл для примера
    with open('.env.example', 'w') as f:
        f.write(f"ENCRYPTION_KEY={key.decode()}\n")

if __name__ == "__main__":
    main()
