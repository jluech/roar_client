import json
import socket


def send_config(config_nr=1):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(("0.0.0.0", 42666))

        match config_nr:
            case 0:
                config = json.loads('{ "algo": "AES-CBC", "burst_duration": "s0", "burst_pause": "0", "burst_rate": "0" }')
            case 1:
                config = json.loads('{ "algo": "AES-CTR", "burst_duration": "s0", "burst_pause": "0", "burst_rate": "0" }')
            case 2:
                config = json.loads('{ "algo": "Salsa20", "burst_duration": "s0", "burst_pause": "0", "burst_rate": "0" }')
            case 3:
                config = json.loads('{ "algo": "ChaCha20", "burst_duration": "s0", "burst_pause": "0", "burst_rate": "0" }')
            case _:
                config = json.loads('{ "algo": "AES-CTR", "burst_duration": "s0", "burst_pause": "0", "burst_rate": "0" }')

        data = json.dumps(config)
        sock.sendall(bytes(data, encoding="utf-8"))
        print("sent", data)


if __name__ == "__main__":
    send_config()
