from db_utils import *
from crypto_utils import *

import os
import sqlite3
import hashlib
import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


def get_user_pass():
    username = input(print("\n Enter a username \n"))
    password = input(print("\n Enter a password \n "))
    password2 = input(print("\n Confirm your password \n"))
    if (password == password2):
        return username, password
    else:
        print("Passwords did not match")
        get_user_pass()



def main():

    db_name = "password_manager.db"
    initialize_database(db_name)

    res = input(print("\n 1. Create user \n 2. Log in \n"))

    if (res == 1):
        username, password = get_user_pass()
        username_sha256 = gen_hash(username)
        password_salt = generate_salt()
        password_bcrypt = generate_bcrypt(password)
        pbkdf2_key_salt = generate_salt()
        user_key_iv = generate_iv()

        intermediate_key = generate_aes_key()
        password_based_key = pbkdf2(pbkdf2_key_salt, password)

        user_key_aes256cbc = aes256_encrypt(user_key_iv, password_based_key, intermediate_key)

        add_user(db_name, username, username_sha256, password_salt, password_bcrypt, pbkdf2_key_salt, user_key_iv, user_key_aes256cbc)

        print(f"User {username} added successfully.")

    elif(res == 2):
        username = input(print(" \n Enter your username \n"))
        
