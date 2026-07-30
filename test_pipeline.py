import subprocess
import os
import unittest


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
        self.test_seed = "0123456789abcdef0123456789abcdef"

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
            "python", "secure_crypto.py", "encrypt",
            "--input", self.plain_msg_path,
            "--output", self.encrypted_aes_path,
            "--password", self.test_password,
        ]
        res = subprocess.run(encrypt_cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"AES Encryption failed: {res.stderr}")

        decrypt_cmd = [
            "python", "secure_crypto.py", "decrypt",
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
            "python", "secure_crypto.py", "encrypt",
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
            "python", "secure_crypto.py", "decrypt",
            "--input", self.tampered_aes_path,
            "--output", self.decrypted_aes_path,
            "--password", self.test_password,
        ]
        res = subprocess.run(decrypt_cmd, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0, "Tampered file was incorrectly decrypted successfully!")

    def test_3_legacy_lfsr_verify_and_crack(self):
        """Tests legacy_cipher.py re-encryption and cryptanalysis_tool.py cracking mechanism."""
        # 1. Encrypt legacy message via legacy_cipher.py
        encrypt_cmd = [
            "python", "legacy_cipher.py", "encrypt",
            self.legacy_msg_path, self.legacy_ciphertext_path
        ]
        res = subprocess.run(encrypt_cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Legacy encryption failed: {res.stderr}")

        # 2. Run cryptanalysis_tool.py crack mode
        crack_cmd = [
            "python", "cryptanalysis_tool.py", "crack",
            "--ciphertext", self.legacy_ciphertext_path,
            "--known-plaintext", "SYSTEM_OVERFLOW!"
        ]
        res_crack = subprocess.run(crack_cmd, capture_output=True, text=True)
        self.assertEqual(res_crack.returncode, 0, f"Cryptanalysis tool failed: {res_crack.stderr}")

        # 3. Verify output decryption file matches original content
        self.assertTrue(os.path.exists(self.decrypted_legacy_path))
        with open(self.decrypted_legacy_path, "rb") as f:
            decrypted_data = f.read()

        with open(self.legacy_msg_path, "rb") as f:
            original_data = f.read()

        self.assertEqual(decrypted_data, original_data)
    
    def test_4_custom_header_legacy_crack(self):
        """Tests that cryptanalysis_tool.py successfully handles a non-default custom header."""
        custom_header = b"CUSTOM_FLAG_XYZ!"
        custom_msg_path = "custom_message.txt"
        custom_ciphertext_path = "custom_ciphertext.bin"

        with open(custom_msg_path, "wb") as f:
            f.write(custom_header + b" Additional secret payload data.")

        # Re-encrypt using the custom header logic via a temporary script or custom bytes
        # Simulating encryption manually with the LFSR generator for the test:
        from legacy_cipher import run_lfsr_generator
        test_seed = [i % 2 for i in range(128)]
        with open(custom_msg_path, "rb") as f:
            plaintext = f.read()
        
        keystream = run_lfsr_generator(test_seed, len(plaintext))
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
        
        with open(custom_ciphertext_path, "wb") as f:
            f.write(ciphertext)

        # Run crack mode passing the explicit custom header argument
        crack_cmd = [
            "python", "cryptanalysis_tool.py", "crack",
            "--ciphertext", custom_ciphertext_path,
            "--known-plaintext", "CUSTOM_FLAG_XYZ!"
        ]
        res = subprocess.run(crack_cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Custom header crack failed: {res.stderr}")

        # Clean up custom test files
        for p in [custom_msg_path, custom_ciphertext_path]:
            if os.path.exists(p):
                os.remove(p)


if __name__ == "__main__":
    unittest.main()