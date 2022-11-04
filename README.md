# ROAR - Client
Master Thesis on Ransomware Optimized with AI for Resource-constrained devices

## Configuration
Adjust constants in the following files:

| File               | Constants                                                                                                                     |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------|
| `client.py`        | - Absolute start directory if not default from `rwpoc.py`                                                                     |
| `fingerprinter.sh` | - Client IP address and port<br>- Server API route<br>- Fingerprint settings (monitoring resources, temperature, time window) |
| `rwpoc.py`         | - RW start directory<br>- RW extension and directory<br>- Safe directories (system files)                                     |
