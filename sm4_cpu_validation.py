from __future__ import annotations

import argparse
import time
from pathlib import Path

from decrypt_file import decrypt_bytes, decrypt_file, encrypt_bytes, encrypt_file, sha256_file

DEFAULT_KEY = b"0123456789abcdef"
DEFAULT_IV = b"abcdef9876543210"
DEFAULT_TEXT = b"SM4 validation plaintext for CPU baseline."


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local SM4 CPU validation.")
    parser.add_argument("--mode", choices=["CBC", "CTR"], default="CBC")
    parser.add_argument("--size-mb", type=int, default=1)
    parser.add_argument("--output-dir", default="validation_output/sm4_cpu")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    run_string_validation(args.mode)
    run_file_validation(args.mode, args.size_mb, output_dir)
    return 0


def run_string_validation(mode: str) -> None:
    ciphertext = encrypt_bytes(DEFAULT_TEXT, DEFAULT_KEY, DEFAULT_IV, mode=mode)
    plaintext = decrypt_bytes(ciphertext, DEFAULT_KEY, DEFAULT_IV, mode=mode)
    if plaintext != DEFAULT_TEXT:
        raise RuntimeError("string round-trip validation failed")

    print("字符串验证：通过")
    print(f"加密模式：SM4-{mode}")
    print(f"字符串密文(hex)：{ciphertext.hex()}")


def run_file_validation(mode: str, size_mb: int, output_dir: Path) -> None:
    plaintext_path = output_dir / "sample_plain.bin"
    ciphertext_path = output_dir / "sample_cipher.bin"
    decrypted_path = output_dir / "sample_decrypted.bin"

    write_sample_file(plaintext_path, size_mb)

    encrypt_file(plaintext_path, ciphertext_path, DEFAULT_KEY, DEFAULT_IV, mode=mode)

    start = time.perf_counter()
    decrypt_file(ciphertext_path, decrypted_path, DEFAULT_KEY, DEFAULT_IV, mode=mode)
    elapsed = time.perf_counter() - start

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
    pattern = b"SM4 validation file block.\n"
    block = (pattern * ((1024 * 1024 // len(pattern)) + 1))[: 1024 * 1024]
    target_size = size_mb * 1024 * 1024
    written = 0

    with path.open("wb") as target:
        while written < target_size:
            chunk = block[: min(len(block), target_size - written)]
            target.write(chunk)
            written += len(chunk)


if __name__ == "__main__":
    raise SystemExit(main())
