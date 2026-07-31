# Cryptography & Cryptanalysis Toolset

## Project Overview

1. **Part A/B (Cryptanalysis):** A custom-built pipeline to break a vulnerable 128-bit Linear Feedback Shift Register (LFSR) stream cipher. It utilizes a known-plaintext attack to extract the keystream and maps the linear relationships to a $128 \times 128$ matrix over Galois Field 2 (GF(2)). The initial state is recovered using a pure-Python implementation of Gaussian Elimination.
    
2. **Part C (Modern Replacement):** A secure file encryption tool utilizing AES-256-GCM. It implements modern cryptographic best practices, including PBKDF2-HMAC-SHA256 for key stretching, randomized nonces, and cryptographic authentication tags to prevent tampering.
    

## Project Architecture

- `cryptanalysis_tool.py` - CLI application to crack or verify the legacy LFSR cipher.
    
- `secure_crypto.py` - CLI application for modern AES-256-GCM file encryption.
    
- `gf2_solver.py` - Pure Python implementation of Gaussian Elimination over GF(2).
    
- `legacy_cipher.py` - The vulnerable target LFSR implementation.
    
- `config.py` - Centralized parameters for both legacy and modern systems.
    
- `test_pipeline.py` - Automated integration test suite.
    

## Prerequisites & Installation

This project requires **Python 3.10 or newer**.

To adhere to the assignment constraints, the GF(2) solver and legacy cryptanalysis tools are built entirely from scratch using only the Python Standard Library. No external math libraries were used for Part B.

To support the AES-256-GCM requirements for Part C, the standard `cryptography` package is required.

Bash

```
pip install cryptography
```

## Usage Instructions

### 1. The Cryptanalysis Tool (Legacy System)

**Mode 1: Crack**

Extracts the seed from a ciphertext using a known plaintext header and decrypts the payload.

Bash

```
python cryptanalysis_tool.py crack --ciphertext ciphertext.hex --known-plaintext "SYSTEM_OVERFLOW!"
```

**Mode 2: Verify**

Re-encrypts a given plaintext using a specific hex-encoded seed to verify LFSR behavior.

Bash

```
python cryptanalysis_tool.py verify --seed "0123456789abcdef0123456789abcdef" --plaintext "Test message"
```

### 2. The Secure Vault (Modern Replacement)

**Encrypt a File**

Encrypts a plaintext file using AES-256-GCM.

Bash

```
python secure_crypto.py encrypt --input plaintext.txt --output encrypted.bin --password "YourStrongPassword!"
```

**Decrypt a File**

Verifies the authentication tag and decrypts the file.

Bash

```
python secure_crypto.py decrypt --input encrypted.bin --output decrypted.txt --password "YourStrongPassword!"
```

### 3. Running the Test Suite

An automated test pipeline is included to verify the end-to-end functionality of both the LFSR cracking mechanism and the AES-GCM tamper-detection.

Bash

```
python -m unittest test_pipeline.py
```

## Note

- **GF(2) Matrix Solver:** Implemented entirely from scratch in `gf2_solver.py`. As per the requirements, libraries such as `numpy`, `scipy`, and `sympy` were strictly avoided to demonstrate a fundamental understanding of linear algebra over binary fields.
    
- **AES-256-GCM Implementation:** Because the Python Standard Library does not natively include an AES implementation, the `cryptography` package was utilized for `secure_crypto.py` to meet the requirement of following "modern cryptographic best practices" for production environments.