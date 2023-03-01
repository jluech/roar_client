# ROAR - Client
Master Thesis on Ransomware Optimized with AI for Resource-constrained devices.\
_The official title of this thesis is "AI-powered Ransomware to Optimize its Impact on IoT Spectrum Sensors"._

It is generally advised to first consult the corresponding report of this master thesis.
The report motivates the thesis and introduces the required background.
It further explains the development, and reasoning of the ransomware extension in great detail.





## Setup ROAR
First, make sure you have a compatible Python version installed on your system.
All development regarding the server was run and tested with Python 3.10.
Compatibility with other Python versions is not guaranteed.

Second, you need to install the dependencies required by this repository.
To install them, execute the `setup.sh` script.
That should already do the trick.
Sometimes, the system environment did not update in between the commands, so you may need to just execute the script multiple times to install all dependencies.





## Client Files
The repository contains three different files for entry points: `client.py`, `client-collect-fp.py`, and `client-eval.py`.
All files will launch the ransomware but the difference lies in the number of runs or interactions with the command and control (C2) server.

While `client.py` launches the ransomware for an attack scenario, where it is started and will terminate once all files are encrypted,
`client-collect-fp.py` launches a data collection scenario in which - after encryption - it will automatically kill the child processes (fingerprint collection, configuration changes), decrypt all affected files, and start over.

Furthermore, the `client-eval.py` was used for online training of the related reinforcement learning (RL) agent contained in the ROAR server.
As such, this script launches the ransomware for a mixture of training and attack scenario.
The files of a predefined corpus are encrypted according to the ransomware configuration, and the corpus is reset (replacing the encrypted files with the unencrypted version) after each run.
However, in contrast to the other scripts, it starts more child processes to coordinate with the training with the C2 server, allowing remotely triggering a termination or reset of the current encryption run and resetting the corpus.

On a side note: there is also a folder `dev/`.
It should generally not concern you, as it contains old versions of the ransomware and ways of simulating the C2 server during development.





## Configuration
Adjust constants in the following files:

| File                   | Constants                                                                                                                                    |
|------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| `client.py`            | - Absolute path to target directory if not default from `rwpoc.py`                                                                           |
| `client-collect-fp.py` | - Absolute path to target directory if not default from `rwpoc.py`                                                                           |
| `client-eval.py`       | - Absolute path to target directory if not default from `rwpoc.py`                                                                           |
| `fingerprinter.sh`     | - C2 IP address and port<br>- C2 FP API route<br>- Fingerprint settings (monitoring resources, temperature, time window)                     |
| `globals.sh`           | - Various file paths (DANGER ZONE!)                                                                                                          |
| `reset_corpus.sh`      | - Absolute path to dataset (fingerprints)<br>- Absolute path to corpus folder                                                                |
| `rwpoc.py`             | - C2 IP address, port, and RW API route<br>- RW default start directory<br>- RW extension and directory<br>- Safe directories (system files) |
