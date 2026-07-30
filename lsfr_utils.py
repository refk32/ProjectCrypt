from config import STATE_SIZE
from typing import List

def bits_to_hex_string(bits: List[int]) -> str:
    """Converts a binary sequence list into a standardized 32-character

    hexadecimal representation.

    Args:
        bits (List[int]): A list of 128 integer bits (0s and 1s).

    Returns:
        str: A lowercase 32-character hexadecimal string.
    """    
    val = 0
    for bit in bits:
        val = (val << 1) | bit
    byte_array = val.to_bytes((STATE_SIZE + 7) // 8, byteorder="big")
    return byte_array.hex()


def hex_string_to_bits(hex_str: str) -> List[int]:
    """Parses a hexadecimal string representation of a secret seed into

    an explicit list of 128 individual binary bit values.

    Args:
        hex_str (str): A hex string representing the initial LFSR state.

    Returns:
        List[int]: A list containing exactly 128 binary integers (0s and 1s).
    """
    hex_str = hex_str.strip()
    if hex_str.startswith("0x") or hex_str.startswith("0X"):
        hex_str = hex_str[2:]

    val = int(hex_str, 16)
    bit_string = bin(val)[2:].zfill(STATE_SIZE)
    return [int(b) for b in bit_string]