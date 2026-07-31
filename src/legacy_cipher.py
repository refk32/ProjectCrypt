"""Legacy LFSR stream cipher (128-bit state).

This module implements the proprietary Linear Feedback Shift Register (LFSR)
stream cipher used by the legacy system under analysis.
"""

from __future__ import annotations

MASK_128 = (1 << 128) - 1


def _feedback_bit(state: int) -> int:
    """Compute the feedback bit for the current 128-bit LFSR state.

    Feedback taps (per technical specification):
      bit 127 XOR bit 30 XOR bit 12 XOR bit 2 XOR 1
    which corresponds to the polynomial
      x^128 + x^31 + x^13 + x^3 + 1
    together with the constant-1 affine term.
    """
    return (
        ((state >> 127) & 1)
        ^ ((state >> 30) & 1)
        ^ ((state >> 12) & 1)
        ^ ((state >> 2) & 1)
        ^ 1
    )


def shift(state: int) -> int:
    """Shift the register left by one and insert the feedback bit into the LSB."""
    fb = _feedback_bit(state)
    return ((state << 1) | fb) & MASK_128


def next_keystream_byte(state: int) -> tuple[int, int]:
    """Generate one keystream byte and return (new_state, keystream_byte).

    One byte is produced by performing eight shift operations. After each
    shift, the LSB is collected into the output byte from bit 0 through bit 7.
    """
    byte = 0
    for i in range(8):
        state = shift(state)
        byte |= (state & 1) << i
    return state, byte


def keystream(seed: int, length: int) -> bytes:
    """Generate ``length`` keystream bytes from the initial 128-bit state."""
    state = seed & MASK_128
    out = bytearray()
    for _ in range(length):
        state, ks = next_keystream_byte(state)
        out.append(ks)
    return bytes(out)


def encrypt(plaintext: bytes, seed: int) -> bytes:
    """Encrypt plaintext: ciphertext = plaintext XOR keystream."""
    ks = keystream(seed, len(plaintext))
    return bytes(p ^ k for p, k in zip(plaintext, ks))


def decrypt(ciphertext: bytes, seed: int) -> bytes:
    """Decrypt ciphertext (identical to encrypt for a stream cipher)."""
    return encrypt(ciphertext, seed)


if __name__ == "__main__":
    # Minimal self-check (does not expose challenge secrets).
    demo_seed = 0x0123456789ABCDEF0123456789ABCDEF
    demo_pt = b"SYSTEM_OVERFLOW!"
    ct = encrypt(demo_pt, demo_seed)
    assert decrypt(ct, demo_seed) == demo_pt
    print("legacy_cipher self-check OK")
    print(f"demo ciphertext: {ct.hex()}")
