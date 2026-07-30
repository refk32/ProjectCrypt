import argparse
import os
import secrets
import sys
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
ITERATIONS = 100_000
KEY_SIZE = 32

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit cryptographic key from a password and salt using PBKDF2-HMAC-SHA256.

    Args:
        password: The user-supplied password string.
        salt: A 16-byte cryptographically secure random salt.

    Returns:
        A 32-byte (256-bit) derived key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    """
    Encrypt a file using AES-256-GCM and save it with the required binary structure.

    Args:
        input_path: Path to the plaintext input file.
        output_path: Path where the encrypted binary file will be saved.
        password: The password used to derive the encryption key.
    
    Raises:
        FileNotFoundError: If the input file does not exist.
        IOError: If there are permission issues reading or writing the files.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    with open(input_path, "rb") as f:
        plaintext = f.read()

    # secure random number generator
    # using random noise ensuring hackers cannot predict the salt and nonce
    salt = secrets.token_bytes(SALT_SIZE) 
    nonce = secrets.token_bytes(NONCE_SIZE)
    
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    
    encrypted_data = aesgcm.encrypt(nonce, plaintext, None)
    
    actual_ciphertext = encrypted_data[:-TAG_SIZE] # grab everything from the beginning up to the last 16 bytes
    auth_tag = encrypted_data[-TAG_SIZE:] # exact opposite, grab only the last 16 bytes
    
    with open(output_path, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(auth_tag)
        f.write(actual_ciphertext)

def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    """
    Decrypt an AES-256-GCM encrypted file, verifying its authentication tag.

    Args:
        input_path: Path to the encrypted binary input file.
        output_path: Path where the decrypted plaintext file will be saved.
        password: The password used to derive the decryption key.
        
    Raises:
        FileNotFoundError: If the encrypted input file does not exist.
        ValueError: If the file is too small to contain the required cryptographic headers,
                    or if the authentication tag verification fails (corrupted data/wrong password).
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Encrypted input file not found: {input_path}")

    with open(input_path, "rb") as f: 
        file_data = f.read()

    # if a file is smaller than SALT_SIZE + NONCE_SIZE + TAG_SIZE (44 bytes), 
    # impossible for it to contain the required cryptographic headers
    # reject it immediately to prevent the script from crashing
    minimum_required_length = SALT_SIZE + NONCE_SIZE + TAG_SIZE 
    if len(file_data) < minimum_required_length:
        raise ValueError("Invalid file structure: File is too small to contain valid cryptographic headers.")

    salt = file_data[:SALT_SIZE]
    nonce = file_data[SALT_SIZE:SALT_SIZE + NONCE_SIZE] # start reading right after 16-byte salt, and stops 12 bytes later
    auth_tag = file_data[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + TAG_SIZE] # start reading right after 28-byte and then reads the data from byte 28 up to byte 44
    actual_ciphertext = file_data[minimum_required_length:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key) # init the encryption engine

    data_to_decrypt = actual_ciphertext + auth_tag

    try:
        plaintext = aesgcm.decrypt(nonce, data_to_decrypt, None)
    except InvalidTag:
        raise ValueError("Authentication Failed: The password is incorrect, or the ciphertext has been modified.")

    with open(output_path, "wb") as f:
        f.write(plaintext)

def main() -> None:
    """
    Command-line interface for the secure encryption tool.
    """
    parser = argparse.ArgumentParser(description="Secure File Encryption Tool utilizing AES-256-GCM")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Operation mode: 'encrypt' or 'decrypt'")
    parser.add_argument("-i", "--input", required=True, help="Path to the input file")
    parser.add_argument("-o", "--output", required=True, help="Path to the output file")
    parser.add_argument("-p", "--password", required=True, help="Password for key derivation")
    
    args = parser.parse_args()

    try:
        if args.mode == "encrypt":
            encrypt_file(args.input, args.output, args.password)
            print(f"Success: File successfully encrypted to '{args.output}'.")
        elif args.mode == "decrypt":
            decrypt_file(args.input, args.output, args.password)
            print(f"Success: File successfully decrypted to '{args.output}'.")
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()