import os
import sqlite3
from getpass import getpass
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "mensagens.db")

db = sqlite3.connect(DB_PATH)

db.execute("""
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
)
""")

db.execute("""
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Não lida',
    created_at TEXT NOT NULL
)
""")

db.commit()

print("=== Criar primeiro administrador ===")
username = input("Nome de utilizador: ").strip()
password = getpass("Palavra-passe: ")

if not username or not password:
    raise SystemExit("Utilizador e palavra-passe são obrigatórios.")

try:
    db.execute(
        "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
        (username, generate_password_hash(password))
    )
    db.commit()
    print("Administrador criado com sucesso.")
except sqlite3.IntegrityError:
    print("Esse utilizador já existe.")

db.close()
