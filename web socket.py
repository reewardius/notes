import websocket
import json

# Replace the URL with the actual web socket endpoint
URL = "wss://[insert your websocket URL here]"

# Replace the JWT token with your actual JWT token
JWT_TOKEN = '[insert your JWT token here]'
HEADERS = {
    'Authorization': 'Bearer ' + JWT_TOKEN
}

# Replace the payload with the actual data you want to send
PAYLOAD = {
    "data": [insert your data in JSON format here]
}

def on_message(ws, message):
    print(message)

def on_error(ws, error):
    print(error)

def on_close(ws):
    print("Closed")

def on_open(ws):
    ws.send(json.dumps(PAYLOAD))

if __name__ == '__main__':
    websocket.enableTrace(True)
    ws = websocket.WebSocketApp(URL,
                              header=HEADERS,
                              on_message=on_message,
                              on_error=on_error,
                              on_close=on_close)
    ws.on_open = on_open
    ws.run_forever()
