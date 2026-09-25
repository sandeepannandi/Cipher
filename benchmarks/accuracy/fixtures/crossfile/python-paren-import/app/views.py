from .repository import (
    find_orders,
)


@app.route("/orders")
def orders():
    customer = request.args.get("customer")
    return {"orders": find_orders(customer)}
