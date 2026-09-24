import sqlite3
from flask import Flask, request

app = Flask(__name__)


def find_user(conn, name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return conn.execute(query).fetchall()


@app.route("/user")
def user():
    conn = sqlite3.connect("app.db")
    name = request.args.get("name")
    return str(find_user(conn, name))
