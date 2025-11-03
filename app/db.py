import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "poc.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, name TEXT)")
    # seed one record
    cur.execute("INSERT OR IGNORE INTO users (id, email, name) VALUES (1, 'alice@example.com', 'Alice')")
    conn.commit()
    conn.close()

def get_user_by_email(email: str):
    q = "SELECT id, email, name FROM users WHERE email = ?"
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(q, (email,))
    row = cur.fetchone()
    conn.close()
    return row
