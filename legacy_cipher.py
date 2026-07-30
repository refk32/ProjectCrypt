import sys
from typing import List

TAP_POSITIONS = [127, 30, 12, 2]
STATE_SIZE = 128


def run_lfsr_generator(seed: List[int], num_bytes: int) -> bytes:
    """Simulates the legacy LFSR forward to generate a keystream of given length."""
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


def encrypt_file(input_path: str, output_path: str, seed: List[int]) -> None:
    """Encrypts a plaintext file using the legacy LFSR keystream."""
    with open(input_path, "rb") as f:
        plaintext = f.read()

    keystream = run_lfsr_generator(seed, len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))

    with open(output_path, "wb") as f:
        f.write(ciphertext)


def main() -> None:
    if len(sys.argv) < 4:
        print(
            "Usage: python legacy_cipher.py encrypt <input_file> <output_ciphertext_file>"
        )
        return

    command = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3]

    # Hardcoded test seed (128 bits of alternating 1s and 0s for testing)
    test_seed = [i % 2 for i in range(STATE_SIZE)]

    if command == "encrypt":
        encrypt_file(input_file, output_file, test_seed)
        print(f"Successfully encrypted '{input_file}' to '{output_file}'.")


if __name__ == "__main__":
    main()