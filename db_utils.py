import os
import sqlite3

def create_users_table(conn):
    cur = conn.cursor()
    cur.execute(''' 
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
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
            FOREIGN KEY(user_id) REFERENCES users(user_id)
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
        INSERT INTO users (user_id, username_sha256, password_salt, password_bcrypt, pbkdf2_key_salt, user_key_iv, user_key_aes256cbc) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, username_sha256, password_salt, password_bcrypt, pbkdf2_key_salt, user_key_iv, user_key_aes256cbc))
    conn.commit()
    conn.close()

def add_data_entity(db_name: str, user_id: str, website: str, value_iv: bytes, value_aes256cbc: bytes):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        INSERT INTO DataEntity (user_id, website, value_iv, value_aes256cbc) 
        VALUES (?, ?, ?, ?)
    ''', (user_id, website, value_iv, value_aes256cbc))
    conn.commit()
    conn.close()

def retrieve_data_entities(db_name: str, user_id: str):
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

def retrieve_user(db_name: str, username_sha256: bytes):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username_sha256 = ?', (username_sha256,))
    user = c.fetchone()
    conn.close()
    print(f"Retrieved user: {user}")  # Debug statement
    return user
