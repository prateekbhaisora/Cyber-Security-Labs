## Cryptography Lab

### Introduction

This part of repository contains code to perform `timing analysis` of various symmetric as well as asymmetric `Encryption`, `Hashing`, and `Authenticated Encryption` algorithms. It measures execution time, plaintext size, and ciphertext size for the following algorithms:

* AES-128-CBC
* AES-128-CTR
* RSA-2048
* AES-128-CMAC
* SHA3-256-HMAC
* RSA-2048-SHA3-256-SIG
* ECDSA-256-SHA3-SIG
* AES-128-GCM

### Setup Instructions

1. Create a Python virtual environment and activate it:

```sh
sudo apt install python3.10-venv
python3 -m venv py_3.10.12
source py_3.10.12/bin/activate
```

2. Make the bash setup script executable and install the required Python dependencies:

```sh
sudo chmod +x setup_env.sh
./setup_env.sh
```

3. Run the tests to evaluate all algorithms and print their performance metrics:

```sh
python3 example_test.py
```