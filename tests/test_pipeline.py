import subprocess
import os
import unittest
from src.legacy_cipher import encrypt

class TestMasterCryptoPipeline(unittest.TestCase):
    def setUp(self):
        """Create temporary test artifacts for both modern and legacy pipelines."""
        self.plain_msg_path = "test_plain.txt"
        self.legacy_msg_path = "legacy_message.txt"
        self.encrypted_aes_path = "test_encrypted_aes.bin"
        self.decrypted_aes_path = "test_decrypted_aes.bin"
        self.tampered_aes_path = "test_tampered_aes.bin"
        self.legacy_ciphertext_path = "legacy_ciphertext.bin"
        self.decrypted_legacy_path = "decrypted_output.txt"
        
        self.test_password = "SuperSecureMasterPassword123!"
        self.test_seed_int = 0x0123456789abcdef0123456789abcdef

        with open(self.plain_msg_path, "wb") as f:
            f.write(b"Confidential modern payload protected by AES-256-GCM and PBKDF2.")

        with open(self.legacy_msg_path, "wb") as f:
            f.write(b"SYSTEM_OVERFLOW! Secret legacy flag data recovered.")

    def tearDown(self):
        """Clean up all temporary test files."""
        for path in [
            self.plain_msg_path,
            self.legacy_msg_path,
            self.encrypted_aes_path,
            self.decrypted_aes_path,
            self.tampered_aes_path,
            self.legacy_ciphertext_path,
            self.decrypted_legacy_path,
        ]:
            if os.path.exists(path):
                os.remove(path)

    def test_1_aes_encryption_decryption(self):
        """Tests secure_crypto.py encryption and decryption workflows."""
        encrypt_cmd = [
            "python", "src/secure_crypto.py", "encrypt",
            "--input", self.plain_msg_path,
            "--output", self.encrypted_aes_path,
            "--password", self.test_password,
        ]
        res = subprocess.run(encrypt_cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"AES Encryption failed: {res.stderr}")

        decrypt_cmd = [
            "python", "src/secure_crypto.py", "decrypt",
            "--input", self.encrypted_aes_path,
            "--output", self.decrypted_aes_path,
            "--password", self.test_password,
        ]
        res_dec = subprocess.run(decrypt_cmd, capture_output=True, text=True)
        self.assertEqual(res_dec.returncode, 0, f"AES Decryption failed: {res_dec.stderr}")

        with open(self.plain_msg_path, "rb") as original, open(self.decrypted_aes_path, "rb") as decrypted:
            self.assertEqual(original.read(), decrypted.read())

    def test_2_aes_tamper_detection(self):
        """Tests that secure_crypto.py rejects modified ciphertexts via authentication tags."""
        encrypt_cmd = [
            "python", "src/secure_crypto.py", "encrypt",
            "--input", self.plain_msg_path,
            "--output", self.encrypted_aes_path,
            "--password", self.test_password,
        ]
        subprocess.run(encrypt_cmd, capture_output=True, text=True)

        with open(self.encrypted_aes_path, "rb") as f:
            data = bytearray(f.read())
        
        data[-1] ^= 0xFF

        with open(self.tampered_aes_path, "wb") as f:
            f.write(data)

        decrypt_cmd = [
            "python", "src/secure_crypto.py", "decrypt",
            "--input", self.tampered_aes_path,
            "--output", self.decrypted_aes_path,
            "--password", self.test_password,
        ]
        res = subprocess.run(decrypt_cmd, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0, "Tampered file was incorrectly decrypted successfully!")

    def test_3_legacy_lfsr_verify_and_crack(self):
        with open(self.legacy_msg_path, "rb") as f:
            plaintext = f.read()
        
        ciphertext = encrypt(plaintext, self.test_seed_int)
        
        with open(self.legacy_ciphertext_path, "wb") as f:
            f.write(ciphertext)

        crack_cmd = [
            "python", "src/cryptanalysis_tool.py", "crack",
            "--ciphertext", self.legacy_ciphertext_path,
            "--known-plaintext", "SYSTEM_OVERFLOW!"
        ]
        res_crack = subprocess.run(crack_cmd, capture_output=True, text=True)
        self.assertEqual(res_crack.returncode, 0, f"Cryptanalysis tool failed: {res_crack.stderr}")

        self.assertTrue(os.path.exists(self.decrypted_legacy_path))
        with open(self.decrypted_legacy_path, "rb") as f:
            decrypted_data = f.read()

        self.assertEqual(decrypted_data, plaintext)
    
    def test_4_custom_header_legacy_crack(self):
        """Tests that cryptanalysis_tool.py successfully handles a non-default custom header."""
        custom_header = b"CUSTOM_FLAG_XYZ!"
        custom_msg_path = "custom_message.txt"
        custom_ciphertext_path = "custom_ciphertext.bin"

        with open(custom_msg_path, "wb") as f:
            f.write(custom_header + b" Additional secret payload data.")

        with open(custom_msg_path, "rb") as f:
            plaintext = f.read()
        
        ciphertext = encrypt(plaintext, self.test_seed_int)
        
        with open(custom_ciphertext_path, "wb") as f:
            f.write(ciphertext)

        crack_cmd = [
            "python", "src/cryptanalysis_tool.py", "crack",
            "--ciphertext", custom_ciphertext_path,
            "--known-plaintext", "CUSTOM_FLAG_XYZ!"
        ]
        res = subprocess.run(crack_cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Custom header crack failed: {res.stderr}")

        for p in [custom_msg_path, custom_ciphertext_path]:
            if os.path.exists(p):
                os.remove(p)


if __name__ == "__main__":
    unittest.main()