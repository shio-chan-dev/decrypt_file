"""SM4 验证工具包入口。

该模块集中导出 CPU 基线验证中常用的 SM4 加解密和文件校验函数，方便
脚本和测试文件使用统一导入路径。
"""

from .sm4 import (
    DEFAULT_CHUNK_SIZE,
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
    sha256_file,
)

__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "decrypt_bytes",
    "decrypt_file",
    "encrypt_bytes",
    "encrypt_file",
    "sha256_file",
]
