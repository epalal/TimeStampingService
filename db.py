import os
import random
import sqlite3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def create_db():
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()

    cur.execute('''
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY,
                    username VARCHAR (50) NOT NULL UNIQUE,
                    salt VARCHAR (32) NOT NULL,
                    passwd_hash VARCHAR (64) NOT NULL,
                    tokens_available INTEGER DEFAULT 10,
                    tokens_consumed INTEGER DEFAULT 0)
                ''')
    create_user("alice", "123")
    create_user("bob", "123", tokens=1, token_consumed = 9)
    conn.commit()
    conn.close()


def hash_new_password(password: str) -> dict:
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
    )
    key = kdf.derive(password.encode('utf-8'))

    return {
        "salt": salt.hex(),
        "pwd_hash": key.hex()
    }


def verify_hash(passwd_hash: str, salt: str, password: str) -> bool:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(salt),
        iterations=200000,
    )
    try:
        kdf.verify(password.encode('utf-8'), bytes.fromhex(passwd_hash))
        return True
    except ValueError:
        return False


def create_user(username: str, passwd: str, tokens: int = 10, token_consumed: int = 0):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()

    hashed_passwd = hash_new_password(passwd)

    try:
        cur.execute('''
                    INSERT INTO users (username, salt, passwd_hash, tokens_available, tokens_consumed)
                    VALUES (?, ?, ?, ?, ?)
                    ''', (
                        username,
                        hashed_passwd["salt"],
                        hashed_passwd["pwd_hash"],
                        tokens,
                        token_consumed
                    ))
        conn.commit()
        print(f"Utente '{username}' creato con successo.")
    except sqlite3.IntegrityError:
        print(f"Errore: L'utente '{username}' esiste già.")
    finally:
        conn.close()


def find_user(username, password):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute('''
                SELECT passwd_hash, salt
                FROM users
                WHERE username = ?
                ''', (username,))
    row = cur.fetchone()
    conn.close()
    if row is None:
        fake_hash = os.urandom(32).hex()
        fake_salt = os.urandom(16).hex()
        verify_hash(fake_hash, fake_salt, password)
        return False
    passwd_hash, salt = row
    if passwd_hash is not None and salt is not None:
        return verify_hash(passwd_hash, salt, password)
    else:
        return False


def ask_balance(username):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute('''
                            SELECT tokens_available, tokens_consumed FROM users WHERE username = ?
                            ''', (
        username,
    ))
    tokens = cur.fetchone()
    conn.commit()
    conn.close()
    return tokens[0], tokens[1]


def use_token(username: str) -> bool:
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()

    cur.execute('''
                UPDATE users
                SET tokens_available = tokens_available - 1,
                tokens_consumed = tokens_consumed + 1
                WHERE username = ? AND tokens_available > 0
                ''', (username,))

    success = cur.rowcount == 1

    conn.commit()
    conn.close()

    return success