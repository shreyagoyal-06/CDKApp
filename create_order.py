def create_order(body):
    if "order_items" in body:
        order_items = body["order_items"]
    else:
        # handle missing order items
        pass
