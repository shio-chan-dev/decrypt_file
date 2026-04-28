import tempfile
import unittest
from pathlib import Path

from decrypt_file import decrypt_bytes, decrypt_file, encrypt_bytes, encrypt_file, sha256_file


KEY = b"0123456789abcdef"
IV = b"abcdef9876543210"


class SM4ValidationTests(unittest.TestCase):
    def test_cbc_bytes_round_trip_with_pkcs7_padding(self):
        plaintext = b"hello sm4 cbc"

        ciphertext = encrypt_bytes(plaintext, KEY, IV, mode="CBC")
        decrypted = decrypt_bytes(ciphertext, KEY, IV, mode="CBC")

        self.assertEqual(decrypted, plaintext)
        self.assertNotEqual(ciphertext, plaintext)

    def test_ctr_bytes_round_trip_without_padding(self):
        plaintext = b"ctr mode does not need block aligned plaintext"

        ciphertext = encrypt_bytes(plaintext, KEY, IV, mode="CTR")
        decrypted = decrypt_bytes(ciphertext, KEY, IV, mode="CTR")

        self.assertEqual(decrypted, plaintext)

    def test_cbc_file_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "plain.bin"
            cipher = tmp_path / "cipher.bin"
            decrypted = tmp_path / "decrypted.bin"
            source.write_bytes((b"file validation sample\n" * 4096) + b"tail")

            encrypt_file(source, cipher, KEY, IV, mode="CBC")
            decrypt_file(cipher, decrypted, KEY, IV, mode="CBC")

            self.assertEqual(sha256_file(decrypted), sha256_file(source))

    def test_invalid_key_and_iv_are_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_bytes(b"data", b"short", IV)
        with self.assertRaises(ValueError):
            encrypt_bytes(b"data", KEY, b"short")


if __name__ == "__main__":
    unittest.main()
