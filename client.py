from json import loads
from multiprocessing import Process
from socket import AF_INET, SOCK_STREAM, socket
from subprocess import call

from globals import update_existing_config
from rwpoc import run


def listen_for_config_changes():
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", 42666))
        sock.listen(1)

        while True:
            conn, addr = sock.accept()  # keep listening for new connections
            with conn:
                while True:
                    data = conn.recv(1024)  # listen for incoming data of connection
                    if not data:
                        break
                    new_config = loads(data)
                    print("received", new_config)
                    update_existing_config(new_config)


def collect_device_fingerprint():
    call("./fingerprinter.sh")  # without option "-n <limit>", this will continuously collect FP


if __name__ == "__main__":
    proc_config = Process(target=listen_for_config_changes)
    proc_config.start()

    proc_fp = Process(target=collect_device_fingerprint)
    proc_fp.start()

    try:
        run(absolute_paths="None", encrypt=True)
    finally:
        proc_fp.terminate()
        proc_config.terminate()
        proc_fp.join()
        proc_config.join()
