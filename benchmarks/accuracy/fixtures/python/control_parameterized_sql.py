from flask import request
import sqlite3


def find_user():
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    username = request.args.get("username")
    query = "SELECT id, email FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()
