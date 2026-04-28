"""SM4 CPU 基线工具自动测试。

该测试文件使用标准库 unittest 验证核心 SM4 工具函数，确保字符串、文件、
模式选择和参数校验在后续改动中保持稳定。
"""

import tempfile
import unittest
from pathlib import Path

from decrypt_file import decrypt_bytes, decrypt_file, encrypt_bytes, encrypt_file, sha256_file


KEY = b"0123456789abcdef"
IV = b"abcdef9876543210"


class SM4ValidationTests(unittest.TestCase):
    """SM4 CPU 基线功能测试集合。"""

    def test_cbc_bytes_round_trip_with_pkcs7_padding(self):
        """
        验证 CBC 模式字节加解密可以正确往返。

        Args:
            None: unittest 自动调用测试方法。

        Returns:
            None: 通过断言表达测试结果。

        Raises:
            AssertionError: 解密结果不等于明文或密文未发生变化时抛出。
        """
        plaintext = b"hello sm4 cbc"

        ciphertext = encrypt_bytes(plaintext, KEY, IV, mode="CBC")
        decrypted = decrypt_bytes(ciphertext, KEY, IV, mode="CBC")

        self.assertEqual(decrypted, plaintext)
        self.assertNotEqual(ciphertext, plaintext)

    def test_ctr_bytes_round_trip_without_padding(self):
        """
        验证 CTR 模式字节加解密不依赖块对齐。

        Args:
            None: unittest 自动调用测试方法。

        Returns:
            None: 通过断言表达测试结果。

        Raises:
            AssertionError: 解密结果不等于明文时抛出。
        """
        plaintext = b"ctr mode does not need block aligned plaintext"

        ciphertext = encrypt_bytes(plaintext, KEY, IV, mode="CTR")
        decrypted = decrypt_bytes(ciphertext, KEY, IV, mode="CTR")

        self.assertEqual(decrypted, plaintext)

    def test_cbc_file_round_trip(self):
        """
        验证 CBC 模式文件加解密后 sha256 保持一致。

        Args:
            None: unittest 自动调用测试方法。

        Returns:
            None: 通过断言表达测试结果。

        Raises:
            AssertionError: 解密文件 sha256 与原文件不一致时抛出。
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "plain.bin"
            cipher = tmp_path / "cipher.bin"
            decrypted = tmp_path / "decrypted.bin"
            # 构造非 16 字节对齐的文件内容，用于覆盖 PKCS7 padding。
            source.write_bytes((b"file validation sample\n" * 4096) + b"tail")

            encrypt_file(source, cipher, KEY, IV, mode="CBC")
            decrypt_file(cipher, decrypted, KEY, IV, mode="CBC")

            self.assertEqual(sha256_file(decrypted), sha256_file(source))

    def test_invalid_key_and_iv_are_rejected(self):
        """
        验证非法 key 和 IV 长度会被拒绝。

        Args:
            None: unittest 自动调用测试方法。

        Returns:
            None: 通过断言表达测试结果。

        Raises:
            AssertionError: 非法参数没有抛出 ValueError 时抛出。
        """
        # SM4 key 和 IV 都必须是 16 字节。
        with self.assertRaises(ValueError):
            encrypt_bytes(b"data", b"short", IV)
        with self.assertRaises(ValueError):
            encrypt_bytes(b"data", KEY, b"short")


if __name__ == "__main__":
    unittest.main()
