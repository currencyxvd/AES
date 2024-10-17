# AES Encryption in C++ with OpenSSL

## Overview

This project demonstrates the use of **AES-256** encryption and decryption in **CBC mode** (Cipher Block Chaining) using the OpenSSL library in C++. The project provides functions to encrypt and decrypt data using a 256-bit key and a 128-bit initialization vector (IV).

## Features

- **AES-256 Encryption (CBC)**: Encrypts data using a 256-bit key and 128-bit IV.
- **AES-256 Decryption (CBC)**: Decrypts data back to its original plaintext form.
- **OpenSSL Integration**: Uses the OpenSSL library to handle cryptographic operations.
- **Hex Output**: The encrypted data (ciphertext) is displayed in hex format.

## Requirements

- **OpenSSL Library**: This project depends on the OpenSSL library for encryption and decryption.
- **C++11 or higher**

### Installing OpenSSL

For Ubuntu/Debian:
```bash
sudo apt-get install libssl-dev
