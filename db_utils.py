import os
import sqlite3


'''
password stuff:
    encryption_key_pbkdf_salt = generate_salt()
    encryption_key_aes_iv = generate_iv()
    encryption_key = aes256(
        encryption_key_aes_iv,
        pbkdf2(encryption_key_pbkdf_salt, password),
        generate_encryption_key()
    )`


recovery code stuff:
    recovery_code = generate_recovery_code()
    recovery_code_salt = generate_salt()
    recovery_code_hash = bcrypt(recovery_code_salt, recovery_code)
    encryption_key_pbkdf_salt = generate_salt()
    encryption_key_aes_iv = generate_iv()
    encryption_key = aes256(
        encryption_key_aes_iv,
        pbkdf2(encryption_key_pbkdf_salt, recovery_code),
        encryption_key_clear
    )

'''

def create_users_table(conn):
    cur = conn.cursor()
    cur.execute(''' 
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username_sha256 BLOB NOT NULL UNIQUE,
                password_salt BLOB NOT NULL,
                password_bcrypt BLOB NOT NULL,
                pbkdf2_key_salt BLOB NOT NULL,
                user_key_iv BLOB NOT NULL,
                user_key_aes256cbc BLOB NOT NULL
                )
                ''')
    conn.commit()


def create_data_entity_table(conn):
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS DataEntity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            website TEXT NOT NULL,
            value_iv BLOB NOT NULL,
            value_aes256cbc BLOB NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()

def initialize_database(db_name: str):
    if not os.path.exists(db_name):
        conn = sqlite3.connect(db_name)
        create_users_table(conn)
        create_data_entity_table(conn)
        conn.close()


def add_user(db_name: str, user_id: str, username_sha256: bytes, password_salt: bytes, password_bcrypt: bytes, pbkdf2_key_salt: bytes, user_key_iv: bytes, user_key_aes256cbc: bytes):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        INSERT INTO users (id, username_sha256, password_salt, password_bcrypt, pbkdf2_key_salt, user_key_iv, user_key_aes256cbc) 
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (username_sha256, password_salt, password_bcrypt, pbkdf2_key_salt, user_key_iv, user_key_aes256cbc))
    user_id = c.lastrowid
    conn.commit()
    conn.close()
    return user_id

def add_data_entity(db_name: str, user_id: str, website: str, value_iv: bytes, value_aes256cbc: bytes):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        INSERT INTO DataEntity (user_id, website, value_iv, value_aes256cbc) 
        VALUES (?, ?, ?)
    ''', (user_id, website, value_iv, value_aes256cbc))
    conn.commit()
    conn.close()

def retrieve_data_entity(db_name: str, user_id: str):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        SELECT * FROM DataEntity WHERE user_id=?
    ''', (user_id,))
    data_entities = c.fetchall()
    conn.close()
    return data_entities

def delete_data_entity(db_name: str, entity_id: int):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        DELETE FROM DataEntity 
        WHERE id=?
    ''', (entity_id,))
    conn.commit()
    conn.close()


