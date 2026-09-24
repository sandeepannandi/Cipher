import sqlite3


def find_orders(customer):
    conn = sqlite3.connect("shop.db")
    query = "SELECT id, total FROM orders WHERE customer = '%s'" % customer
    return conn.execute(query).fetchall()
