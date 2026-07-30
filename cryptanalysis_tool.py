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
from lsfr_utils import bits_to_hex_string, hex_string_to_bits
from config import STATE_SIZE, TAP_POSITIONS


# TAP_POSITIONS = [127, 30, 12, 2]
# STATE_SIZE = 128
# SYSTEM_HEADER = b"SYSTEM_OVERFLOW!"


def run_lfsr_generator(seed: List[int], num_bytes: int) -> bytes:
    """Simulates the legacy 128-bit linear feedback shift register (LFSR) forward

    to generate a pseudo-random keystream of a specified byte length.

    Args:
        seed (List[int]): A list of 128 integers (0s and 1s) representing the
          initial state.
        num_bytes (int): The number of output bytes to generate from the keystream.

    Returns:
        bytes: The generated raw keystream bytes.
    """
    current_state = list(seed)
    keystream_bytes = bytearray()

    for _ in range(num_bytes):
        keystream_byte = 0
        for bit_idx in range(8):
            lsb = current_state[0]
            keystream_byte |= lsb << bit_idx

            feedback = (
                current_state[127]
                ^ current_state[30]
                ^ current_state[12]
                ^ current_state[2]
                ^ 1
            )
            current_state = current_state[1:] + [feedback]

        keystream_bytes.append(keystream_byte)
    return bytes(keystream_bytes)



def extract_keystream(ciphertext_bytes: bytes, header_bytes : bytes) -> List[int]:
    """Extracts 128 bits of raw keystream by performing a bitwise XOR operation

    between the first 16 bytes of ciphertext and the known plaintext header.

    Args:
        ciphertext_bytes (bytes): The full binary contents of the encrypted file.

    Returns:
        List[int]: A list of 128 extracted keystream bits.

    Raises:
        ValueError: If the provided ciphertext is shorter than 16 bytes.
    """
    if len(ciphertext_bytes) < 16:
        raise ValueError(
            "Ciphertext is too short. Must be at least 16 bytes to extract the header."
        )

    keystream_bits: List[int] = []
    for i in range(16):
        byte_val = ciphertext_bytes[i] ^ header_bytes[i]
        for bit_idx in range(8):
            bit = (byte_val >> bit_idx) & 1
            keystream_bits.append(bit)
    return keystream_bits


def build_lfsr_matrix(keystream_bits: List[int]) -> List[List[int]]:
    """Constructs a 128x129 augmented matrix mapping the linear relationships

    of the LFSR feedback configuration over Galois Field 2 (GF(2)).

    Args:
        keystream_bits (List[int]): Exactly 128 extracted keystream bits to act
          as the constants column.

    Returns:
        List[List[int]]: A 128x129 grid representing the linear system of equations.

    Raises:
        ValueError: If the keystream length deviates from 128 bits.
    """
    if len(keystream_bits) != STATE_SIZE:
        raise ValueError(f"Expected exactly {STATE_SIZE} keystream bits.")

    matrix = [[0] * (STATE_SIZE + 1) for _ in range(STATE_SIZE)]
    state_row = [[0] * STATE_SIZE for _ in range(STATE_SIZE)]
    for i in range(STATE_SIZE):
        state_row[i][i] = 1

    for row in range(STATE_SIZE):
        for col in range(STATE_SIZE):
            matrix[row][col] = state_row[0][col]

        matrix[row][STATE_SIZE] = keystream_bits[row]

        next_row = [0] * STATE_SIZE
        for i in range(STATE_SIZE - 1):
            next_row[i] = state_row[i + 1]

        feedback_row = [0] * STATE_SIZE
        for tap in TAP_POSITIONS:
            for col in range(STATE_SIZE):
                feedback_row[col] ^= state_row[tap][col]

        next_row[STATE_SIZE - 1] = feedback_row
        state_row = next_row

    return matrix


def decrypt_ciphertext(ciphertext_bytes: bytes, seed: List[int]) -> bytes:
    """Decrypts a full ciphertext payload by generating a matching keystream

    from the recovered initial seed and applying a bitwise XOR reversal.

    Args:
        ciphertext_bytes (bytes): The full encrypted payload.
        seed (List[int]): The recovered 128-bit initial seed state.

    Returns:
        bytes: The fully decrypted plaintext data.
    """
    keystream = run_lfsr_generator(seed, len(ciphertext_bytes))
    return bytes(c ^ k for c, k in zip(ciphertext_bytes, keystream))


def mode_crack(ciphertext_path: str, known_plaintext: str) -> None:
    """Executes Mode 1 (Crack): Manages the end-to-end known-plaintext attack pipeline,

    including file ingestion, keystream extraction, matrix building, GF(2) resolution,
    payload decryption, and artifact output.

    Args:
        ciphertext_path (str): The local file path to the target ciphertext.
        known_plaintext (str): The expected starting header string used for the attack.
    """
    header_bytes = known_plaintext.encode("utf-8")

    try:
        with open(ciphertext_path, "rb") as f:
            ciphertext_bytes = f.read()
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

    recovered_hex = bits_to_hex_string(seed_bits)
    print(f"\n[+] Recovered initial state (Hex): {recovered_hex}")

    print("[*] Decrypting entire ciphertext...")
    decrypted_bytes = decrypt_ciphertext(ciphertext_bytes, seed_bits)

    output_file = "decrypted_output.txt"
    try:
        with open(output_file, "wb") as f:
            f.write(decrypted_bytes)
        print(f"[+] Saved decrypted plaintext to: {output_file}")
    except IOError as e:
        print(f"Error saving output file: {e}")

    print("\n--- Fully Decrypted Plaintext / FLAG ---")
    try:
        print(decrypted_bytes.decode("utf-8"))
    except UnicodeDecodeError:
        print(decrypted_bytes)


def mode_verify(seed_hex: str, plaintext_str: str) -> None:
    """Executes Mode 2 (Verify): Re-encrypts a provided plaintext string using a

    given hex-encoded seed state to test and validate system consistency.

    Args:
        seed_hex (str): The 32-character hex string representing the test seed.
        plaintext_str (str): The plaintext message string to encrypt.
    """
    try:
        seed_bits = hex_string_to_bits(seed_hex)
    except Exception as e:
        print(f"Error parsing hex seed: {e}")
        sys.exit(1)

    plaintext_bytes = plaintext_str.encode("utf-8")
    keystream = run_lfsr_generator(seed_bits, len(plaintext_bytes))
    ciphertext_bytes = bytes(p ^ k for p, k in zip(plaintext_bytes, keystream))

    print(f"\n[+] Resulting Ciphertext (Hex): {ciphertext_bytes.hex()}")


def main() -> None:
    """Parses command-line arguments and routes execution into either

    the cryptanalytic crack mode or the verification re-encryption mode.
    """
    parser = argparse.ArgumentParser(description="Cryptanalysis Tool for Legacy LFSR Ciphers")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    parser_crack = subparsers.add_parser("crack", help="Crack ciphertext using known plaintext")
    parser_crack.add_argument("--ciphertext", required=True, help="Path to ciphertext file")
    parser_crack.add_argument("--known-plaintext", default="SYSTEM_OVERFLOW!", help="Known plaintext header")

    parser_verify = subparsers.add_parser("verify", help="Re-encrypt plaintext using legacy LFSR")
    parser_verify.add_argument("--seed", required=True, help="Initial LFSR seed in hex format")
    parser_verify.add_argument("--plaintext", required=True, help="Plaintext string to encrypt")

    args = parser.parse_args()

    if args.mode == "crack":
        mode_crack(args.ciphertext, args.known_plaintext)
    elif args.mode == "verify":
        mode_verify(args.seed, args.plaintext)


if __name__ == "__main__":
    main()