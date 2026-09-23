from flask import request
import sqlite3


def find_user():
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    username = request.args.get("username")
    query = f"SELECT id, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
