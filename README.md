# ROAR - Client
Master Thesis on Ransomware Optimized with AI for Resource-constrained devices

## Configuration
Adjust constants in the following files:

| File               | Constants                                                                                                                                    |
|--------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| `client.py`        | - Absolute target directory if not default from `rwpoc.py`                                                                                   |
| `fingerprinter.sh` | - C2 IP address and port<br>- C2 FP API route<br>- Fingerprint settings (monitoring resources, temperature, time window)                     |
| `rwpoc.py`         | - C2 IP address, port, and RW API route<br>- RW default start directory<br>- RW extension and directory<br>- Safe directories (system files) |
