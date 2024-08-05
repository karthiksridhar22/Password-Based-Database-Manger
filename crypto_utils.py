import os
import sqlite3
import hashlib
import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from hashlib import sha256

def generate_salt() -> bytes:
    return os.urandom(16)

def generate_iv() -> bytes:
    return os.urandom(16)

def generate_aes_key() ->bytes:
    return os.urandom(32)

def pbkdf2(salt: bytes, password: str, iterations: int = 1000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm= hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    )
    return kdf.derive(password.encode())

def aes256_encrypt(iv: bytes, key: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def aes256_decrypt(iv: bytes, key: bytes, encrypted_data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def gen_hash(username: str):
    return sha256((username.encode('utf-8')).hexdigest())

def generate_bcrypt(password: str):
    bytes_p = password.encode('utf-8')
    password_salt = generate_salt()
    password_bcrypt = bcrypt.hashpw(bytes_p, password_salt)

    return password_bcrypt