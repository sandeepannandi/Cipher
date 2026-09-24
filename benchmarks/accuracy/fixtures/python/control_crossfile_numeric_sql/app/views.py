from flask import Flask, request

from .repository import find_orders

app = Flask(__name__)


@app.route("/orders")
def orders():
    customer_id = int(request.args.get("customer_id", "0"))
    return {"orders": find_orders(customer_id)}
