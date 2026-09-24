from flask import Flask, request

from .repository import find_orders

app = Flask(__name__)


@app.route("/orders")
def orders():
    customer = request.args.get("customer")
    return {"orders": find_orders(customer)}
