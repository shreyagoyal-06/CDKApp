def handler(body):
    # Attempt to access 'order_items' key in the dictionary
    order_items = body["order_items"]
    print(order_items)

# Sample body dictionary without 'order_items' key
body = {
    "customer_name": "John Doe",
    "order_id": 123456
}

# Call the function, which will raise KeyError
handler(body)