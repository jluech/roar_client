# ROAR - Client
Master Thesis on Ransomware Optimized with AI for Resource-constrained devices

## Client Files
The repository contains two different files for entry point: `client.py` and `client-collect-fp.py`.
Both files will launch the ransomware but the difference lies in the number of runs.
While `client.py` launches the ransomware for an attack scenario, where it is started and will terminate once all files are encrypted,
`client-collect-fp.py` launches a data collection scenario in which - after encryption - it will automatically kill the child process for fingerprint collection, decrypt all affected files, and start over.

## Configuration
Adjust constants in the following files:

| File                   | Constants                                                                                                                                    |
|------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| `client.py`            | - Absolute target directory if not default from `rwpoc.py`                                                                                   |
| `client-collect-fp.py` | - Absolute target directory if not default from `rwpoc.py`                                                                                   |
| `fingerprinter.sh`     | - C2 IP address and port<br>- C2 FP API route<br>- Fingerprint settings (monitoring resources, temperature, time window)                     |
| `rwpoc.py`             | - C2 IP address, port, and RW API route<br>- RW default start directory<br>- RW extension and directory<br>- Safe directories (system files) |
