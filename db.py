import os
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
                    tokens_available INTEGER DEFAULT 10)
                ''')
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



def create_user(username: str, passwd: str, tokens: int = 10):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()

    hashed_passwd = hash_new_password(passwd)

    try:
        cur.execute('''
                    INSERT INTO users (username, salt, passwd_hash, tokens_available)
                    VALUES (?, ?, ?, ?)
                    ''', (
                        username,
                        hashed_passwd["salt"],
                        hashed_passwd["pwd_hash"],
                        tokens
                    ))
        conn.commit()
        print(f"Utente '{username}' creato con successo.")
    except sqlite3.IntegrityError:
        print(f"Errore: L'utente '{username}' esiste già.")
    finally:
        conn.close()


if __name__ == "__main__":
    create_db()
    # Proviamo a creare Alice e Bob
    create_user("alice", "SuperSegreta123", 5)
    create_user("bob", "PasswordBob456", 10)
    hash1= hash_new_password("SuperSegreta123")
    hash2= hash_new_password("PasswordBob456")
    print(hash1)
    print(hash2)

    print(verify_hash(hash1["pwd_hash"], hash1["salt"], "SuperSegreta123"))
    print(verify_hash(hash2["pwd_hash"], hash2["salt"], "PasswordBob456"))

