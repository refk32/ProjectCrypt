"""Cryptanalysis Tool for Legacy LFSR Ciphers.

This command-line application performs cryptanalytic attacks on vulnerable
linear feedback shift register (LFSR) stream ciphers using a known-plaintext
attack vector. It maps extracted keystream bits into a system of linear equations
over Galois Field 2 (GF(2)), resolves the initial seed via Gaussian elimination,
and decrypts the remaining payload. All matrix resolution logic is handled via custom pure-Python GF(2) routines.


Modes:
    crack: Reads an encrypted file, performs a known-plaintext attack against
           the specified header, solves for the 128-bit secret seed, and outputs
           the fully decrypted plaintext/flag.
    verify: Re-encrypts a provided plaintext string using a given hex-encoded
            LFSR seed to generate testing ciphertexts.


Usage Examples:
    python cryptanalysis_tool.py crack --ciphertext ciphertext.bin --known-plaintext "SYSTEM_OVERFLOW!"
    python cryptanalysis_tool.py verify --seed "0123456789abcdef0123456789abcdef" --plaintext "SYSTEM_OVERFLOW! Hello"
"""

import argparse
import sys
from typing import List
from gf2_solver import solve_gf2
from lsfr_utils import hex_string_to_bits
from config import STATE_SIZE, TAP_POSITIONS

def run_lfsr_generator(seed: List[int], num_bytes: int) -> bytes:
    """Generates a keystream of a specified length using the legacy 128-bit LFSR.

    Args:
        seed (List[int]): The 128-bit initial state represented as a list of integers.
        num_bytes (int): The number of keystream bytes to generate.

    Returns:
        bytes: The generated keystream.
    """
    state = 0
    for i in range(128):
        state |= (seed[i] << i)

    keystream_bytes = bytearray()
    for _ in range(num_bytes):
        byte_val = 0
        for i in range(8):
            fb = ((state >> 127) & 1) ^ ((state >> 30) & 1) ^ ((state >> 12) & 1) ^ ((state >> 2) & 1) ^ 1
            state = ((state << 1) | fb) & ((1 << 128) - 1)
            byte_val |= (state & 1) << i
        keystream_bytes.append(byte_val)
    return bytes(keystream_bytes)

def extract_keystream(ciphertext_bytes: bytes, header_bytes: bytes) -> List[int]:
    """Extracts 128 bits of keystream by XORing the ciphertext with a known header.

    Args:
        ciphertext_bytes (bytes): The full encrypted payload.
        header_bytes (bytes): The known plaintext header (must be at least 16 bytes).

    Returns:
        List[int]: A list of 128 extracted keystream bits.
    """
    if len(ciphertext_bytes) < 16:
        raise ValueError()

    keystream_bits: List[int] = []
    for i in range(16):
        byte_val = ciphertext_bytes[i] ^ header_bytes[i]
        for bit_idx in range(8):
            bit = (byte_val >> bit_idx) & 1
            keystream_bits.append(bit)
    return keystream_bits

def build_lfsr_matrix(keystream_bits: List[int]) -> List[List[int]]:
    """Constructs a 128x129 augmented matrix mapping the LFSR's linear relationships.

    Args:
        keystream_bits (List[int]): The 128 extracted keystream bits.

    Returns:
        List[List[int]]: The augmented matrix for GF(2) resolution.
    """
    if len(keystream_bits) != STATE_SIZE:
        raise ValueError()

    matrix = [[0] * (STATE_SIZE + 1) for _ in range(STATE_SIZE)]
    state_row = [[0] * STATE_SIZE for _ in range(STATE_SIZE)]
    state_const = [0] * STATE_SIZE

    for i in range(STATE_SIZE):
        state_row[i][i] = 1

    for row in range(STATE_SIZE):
        feedback_row = [0] * STATE_SIZE
        feedback_const = 1
        
        for tap in TAP_POSITIONS:
            for col in range(STATE_SIZE):
                feedback_row[col] ^= state_row[tap][col]
            feedback_const ^= state_const[tap]

        for col in range(STATE_SIZE):
            matrix[row][col] = feedback_row[col]

        matrix[row][STATE_SIZE] = keystream_bits[row] ^ feedback_const

        next_state_row = [[0] * STATE_SIZE for _ in range(STATE_SIZE)]
        next_state_const = [0] * STATE_SIZE
        
        next_state_row[0] = feedback_row
        next_state_const[0] = feedback_const
        
        for i in range(1, STATE_SIZE):
            next_state_row[i] = state_row[i - 1]
            next_state_const[i] = state_const[i - 1]
        
        state_row = next_state_row
        state_const = next_state_const

    return matrix

def decrypt_ciphertext(ciphertext_bytes: bytes, seed: List[int]) -> bytes:
    """Decrypts the full payload using the recovered initial seed.

    Args:
        ciphertext_bytes (bytes): The full encrypted data.
        seed (List[int]): The recovered 128-bit LFSR state.

    Returns:
        bytes: The decrypted plaintext data.
    """
    keystream = run_lfsr_generator(seed, len(ciphertext_bytes))
    return bytes(c ^ k for c, k in zip(ciphertext_bytes, keystream))

def mode_crack(ciphertext_path: str, known_plaintext: str) -> None:
    """Executes the known-plaintext attack to recover the seed and decrypt the file.

    Args:
        ciphertext_path (str): Path to the target encrypted file (.bin or .hex).
        known_plaintext (str): The expected starting header string.
    """
    header_bytes = known_plaintext.encode("utf-8")

    try:
        with open(ciphertext_path, "rb") as f:
            raw_data = f.read()
            
        try:
            text_data = raw_data.decode('ascii').strip()
            ciphertext_bytes = bytes.fromhex(text_data)
        except (UnicodeDecodeError, ValueError):
            ciphertext_bytes = raw_data
            
    except IOError as e:
        print(f"Error: Could not read file '{ciphertext_path}': {e}")
        sys.exit(1)

    print("[*] Extracting keystream from known plaintext header...")
    keystream_bits = extract_keystream(ciphertext_bytes, header_bytes)

    print("[*] Constructing 128 x 128 linear equations over GF(2)...")
    matrix = build_lfsr_matrix(keystream_bits)

    print("[*] Solving system via external GF(2) solver...")
    try:
        seed_bits = solve_gf2(matrix)
    except Exception as e:
        print(f"Error during matrix resolution: {e}")
        sys.exit(1)

    seed_int = 0
    for i in range(128):
        seed_int |= (seed_bits[i] << i)
    recovered_hex = hex(seed_int)[2:].zfill(32)
    print(f"\n[+] Recovered initial state (Hex): {recovered_hex}")

    print("[*] Decrypting entire ciphertext...")
    decrypted_bytes = decrypt_ciphertext(ciphertext_bytes, seed_bits)

    output_file = "decrypted_output.txt"
    try:
        with open(output_file, "wb") as f:
            f.write(decrypted_bytes)
        print(f"[+] Saved decrypted plaintext to: {output_file}")
    except IOError:
        pass

    print("\n--- Fully Decrypted Plaintext / FLAG ---")
    try:
        print(decrypted_bytes.decode("utf-8"))
    except UnicodeDecodeError:
        print(decrypted_bytes)

def mode_verify(seed_hex: str, plaintext_str: str) -> None:
    """Re-encrypts a plaintext string using a specific LFSR seed for validation.

    Args:
        seed_hex (str): A 32-character hexadecimal string representing the state.
        plaintext_str (str): The plaintext string to encrypt.
    """
    try:
        seed_bits = hex_string_to_bits(seed_hex)
    except Exception:
        sys.exit(1)

    plaintext_bytes = plaintext_str.encode("utf-8")
    keystream = run_lfsr_generator(seed_bits, len(plaintext_bytes))
    ciphertext_bytes = bytes(p ^ k for p, k in zip(plaintext_bytes, keystream))

    print(f"\n[+] Resulting Ciphertext (Hex): {ciphertext_bytes.hex()}")

def main() -> None:
    """Parses command-line arguments and routes execution to the specified mode."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)

    parser_crack = subparsers.add_parser("crack")
    parser_crack.add_argument("--ciphertext", required=True)
    parser_crack.add_argument("--known-plaintext", default="SYSTEM_OVERFLOW!")

    parser_verify = subparsers.add_parser("verify")
    parser_verify.add_argument("--seed", required=True)
    parser_verify.add_argument("--plaintext", required=True)

    args = parser.parse_args()

    if args.mode == "crack":
        mode_crack(args.ciphertext, args.known_plaintext)
    elif args.mode == "verify":
        mode_verify(args.seed, args.plaintext)

if __name__ == "__main__":
    main()