from json import loads
from multiprocessing import Process
from os import path
from socket import AF_INET, SOCK_STREAM, socket
from subprocess import Popen

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
                    new_config = loads(data.decode(encoding="utf-8"))
                    print("received", new_config)
                    update_existing_config(new_config)


def kill_process(proc):
    if isinstance(proc, Process):
        print("kill Process", proc)
        proc.terminate()
        proc.join()
    elif isinstance(proc, Popen):
        print("kill Popen", proc)
        proc.kill()
        proc.wait()


if __name__ == "__main__":
    procs = []
    proc_config = Process(target=listen_for_config_changes)
    procs.append(proc_config)
    proc_config.start()

    try:
        abs_paths = "<start-path-on-target-device>"

        while True:
            # input("\nEnter: start encrypting")

            proc_fp = Popen(path.join(path.abspath(path.curdir), "fingerprinter.sh"))
            procs.append(proc_fp)

            # input("\nwait shortly for child to start")
            print("\nENCRYPT")

            run(encrypt=True, absolute_paths=abs_paths)  # encrypt
            kill_process(proc_fp)
            procs.remove(proc_fp)

            # input("\nEnter: start decrypting")
            print("\nDECRYPT")

            run(encrypt=False, absolute_paths=abs_paths)  # decrypt
    finally:
        print("finally")
        for proc in procs:
            kill_process(proc)
