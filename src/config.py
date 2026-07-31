# --- Legacy LFSR Configuration --- (used in cryptanalysis_tool.py and lsfr_utils.py)
TAP_POSITIONS = [127, 30, 12, 2]
STATE_SIZE = 128
# SYSTEM_HEADER = b"SYSTEM_OVERFLOW!"

# --- Modern AES-256-GCM Configuration --- (used in secure_crypto.py)
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
ITERATIONS = 100_000
KEY_SIZE = 32