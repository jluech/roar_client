import json
import socket


def send_config():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(("0.0.0.0", 42666))
        config = json.loads('{ "algo": "AES-CBC", "burst_duration": "s0", "burst_pause": "0", "burst_rate": "0" }')
        data = json.dumps(config)
        sock.sendall(bytes(data, encoding="utf-8"))
        print("sent", data)


if __name__ == "__main__":
    send_config()
