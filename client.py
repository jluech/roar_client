import json
from multiprocessing import Process
import socket

from globals import update_existing_config
from rwpoc import run


def listen_for_config_changes():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", 42666))
        sock.listen(1)

        while True:
            conn, addr = sock.accept()  # keep listening for new connections
            with conn:
                while True:
                    data = conn.recv(1024)  # listen for incoming data of connection
                    if not data:
                        break
                    new_config = json.loads(data)
                    print("received", new_config)
                    update_existing_config(new_config)


if __name__ == "__main__":
    proc = Process(target=listen_for_config_changes)
    proc.start()

    try:
        run(absolute_paths="None", encrypt=True)
    finally:
        proc.terminate()
        proc.join()
