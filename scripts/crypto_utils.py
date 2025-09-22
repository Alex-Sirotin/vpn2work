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
