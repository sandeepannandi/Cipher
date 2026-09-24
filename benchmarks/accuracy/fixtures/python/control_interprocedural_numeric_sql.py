import sqlite3
from flask import Flask, request

app = Flask(__name__)


def find_user(conn, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchall()


@app.route("/user")
def user():
    conn = sqlite3.connect("app.db")
    user_id = int(request.args.get("id", "0"))
    return str(find_user(conn, user_id))
