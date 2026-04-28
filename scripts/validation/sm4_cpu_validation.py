"""SM4 CPU 基线验证脚本。

该脚本会生成本地测试明文和测试文件，使用同一组 key/IV 完成 SM4 加密、
解密和 sha256 校验，并输出中文字段，便于后续整理验证报告。
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from decrypt_file import decrypt_bytes, decrypt_file, encrypt_bytes, encrypt_file, sha256_file

DEFAULT_KEY = b"0123456789abcdef"
DEFAULT_IV = b"abcdef9876543210"
DEFAULT_TEXT = b"SM4 validation plaintext for CPU baseline."
SM4_MODE = "CBC"
SM4_PADDING = "pkcs7"


def main() -> int:
    """
    解析命令行参数并执行 CPU 基线验证。

    Args:
        None: 参数通过命令行传入。

    Returns:
        int: 进程退出码，0 表示验证通过。

    Raises:
        RuntimeError: 字符串或文件往返校验失败时抛出。
        ValueError: SM4 参数不合法时由底层函数抛出。
    """
    parser = argparse.ArgumentParser(description="Run local SM4 CPU validation.")
    parser.add_argument("--size-mb", type=int, default=1)
    parser.add_argument("--output-dir", default="validation_output/sm4_cpu")
    args = parser.parse_args()

    # 验证输出目录默认被 .gitignore 忽略，避免提交本地样例文件。
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    run_string_validation()
    run_file_validation(args.size_mb, output_dir)
    return 0


def run_string_validation() -> None:
    """
    使用 SM4-CBC/PKCS7 执行字符串加密、解密和结果核对。

    Args:
        None: 使用脚本内置的 SM4-CBC/PKCS7 参数。

    Returns:
        None: 验证结果直接打印到标准输出。

    Raises:
        RuntimeError: 解密后的字符串与原始明文不一致时抛出。
        ValueError: SM4 参数不合法时由底层函数抛出。
    """
    ciphertext = encrypt_bytes(DEFAULT_TEXT, DEFAULT_KEY, DEFAULT_IV, mode=SM4_MODE, padding=SM4_PADDING)
    plaintext = decrypt_bytes(ciphertext, DEFAULT_KEY, DEFAULT_IV, mode=SM4_MODE, padding=SM4_PADDING)
    if plaintext != DEFAULT_TEXT:
        raise RuntimeError("string round-trip validation failed")

    print("字符串验证：通过")
    print(f"加密模式：SM4-{SM4_MODE}")
    print("CBC填充：PKCS7")
    print(f"字符串密文(hex)：{ciphertext.hex()}")


def run_file_validation(size_mb: int, output_dir: Path) -> None:
    """
    使用 SM4-CBC/PKCS7 执行文件加密、解密、sha256 校验和性能统计。

    Args:
        size_mb (int): 自动生成测试文件的大小，单位 MB。
        output_dir (Path): 测试文件输出目录。

    Returns:
        None: 验证结果直接打印到标准输出。

    Raises:
        RuntimeError: 解密文件 sha256 与原始文件不一致时抛出。
        OSError: 文件读写失败时由底层文件操作抛出。
    """
    plaintext_path = output_dir / "sample_plain.bin"
    ciphertext_path = output_dir / "sample_cipher.bin"
    decrypted_path = output_dir / "sample_decrypted.bin"

    # 先生成明文样例，再用同一组 key/IV 加密成密文样例。
    write_sample_file(plaintext_path, size_mb)
    encrypt_file(plaintext_path, ciphertext_path, DEFAULT_KEY, DEFAULT_IV, mode=SM4_MODE, padding=SM4_PADDING)

    # 只统计解密阶段耗时，便于后续和 GPU 解密耗时对比。
    start = time.perf_counter()
    decrypt_file(ciphertext_path, decrypted_path, DEFAULT_KEY, DEFAULT_IV, mode=SM4_MODE, padding=SM4_PADDING)
    elapsed = time.perf_counter() - start

    # 使用 sha256 确认解密文件和原始文件完全一致。
    plain_hash = sha256_file(plaintext_path)
    decrypted_hash = sha256_file(decrypted_path)
    if plain_hash != decrypted_hash:
        raise RuntimeError("file round-trip validation failed")

    bytes_decrypted = ciphertext_path.stat().st_size
    throughput = bytes_decrypted / elapsed / 1024 / 1024 if elapsed else 0.0

    print("文件验证：通过")
    print(f"原始文件：{plaintext_path}")
    print(f"密文文件：{ciphertext_path}")
    print(f"解密文件：{decrypted_path}")
    print(f"原始文件sha256：{plain_hash}")
    print(f"解密耗时(秒)：{elapsed:.6f}")
    print(f"解密吞吐量(MB/s)：{throughput:.2f}")


def write_sample_file(path: Path, size_mb: int) -> None:
    """
    生成指定大小的本地测试文件。

    Args:
        path (Path): 测试文件输出路径。
        size_mb (int): 文件大小，单位 MB。

    Returns:
        None: 函数直接写入 path。

    Raises:
        OSError: 文件写入失败时由底层文件操作抛出。
    """
    pattern = b"SM4 validation file block.\n"
    # 构造 1MB 模板块，避免大文件测试时逐小片重复写入。
    block = (pattern * ((1024 * 1024 // len(pattern)) + 1))[: 1024 * 1024]
    target_size = size_mb * 1024 * 1024
    written = 0

    with path.open("wb") as target:
        while written < target_size:
            # 最后一轮只写入剩余字节，保证文件大小严格等于 size_mb。
            chunk = block[: min(len(block), target_size - written)]
            target.write(chunk)
            written += len(chunk)


if __name__ == "__main__":
    raise SystemExit(main())
