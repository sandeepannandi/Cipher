import sqlite3


def find_orders(customer_id):
    conn = sqlite3.connect("shop.db")
    query = "SELECT id, total FROM orders WHERE customer_id = %d" % customer_id
    return conn.execute(query).fetchall()
