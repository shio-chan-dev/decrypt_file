from __future__ import annotations

import argparse
import time
from pathlib import Path

from decrypt_file import decrypt_file, encrypt_file, sha256_file
from decrypt_file.sm4_torch import cuda_device_name, decrypt_file_torch, synchronize_device

DEFAULT_KEY = b"0123456789abcdef"
DEFAULT_IV = b"abcdef9876543210"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SM4 CPU/GPU validation on a CUDA machine.")
    parser.add_argument("--mode", choices=["CBC", "CTR"], default="CBC")
    parser.add_argument("--size-mb", type=int, default=64)
    parser.add_argument("--chunk-mb", type=int, default=16)
    parser.add_argument("--output-dir", default="validation_output/sm4_gpu")
    parser.add_argument("--device", default="cuda")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    chunk_size = args.chunk_mb * 1024 * 1024
    if chunk_size % 16:
        raise ValueError("chunk size must be a multiple of 16 bytes")

    try:
        gpu_name = cuda_device_name(args.device)
    except RuntimeError as exc:
        print("GPU环境检查：失败")
        print(f"失败原因：{exc}")
        print("处理建议：请在已安装 PyTorch 且 CUDA 可用的 GPU 服务器上运行该脚本。")
        return 2
    paths = build_paths(output_dir)
    write_sample_file(paths["plain"], args.size_mb)
    encrypt_file(paths["plain"], paths["cipher"], DEFAULT_KEY, DEFAULT_IV, mode=args.mode)

    cpu_elapsed = measure_cpu_decrypt(paths, args.mode, chunk_size)
    gpu_elapsed = measure_gpu_decrypt(paths, args.mode, chunk_size, args.device)

    plain_hash = sha256_file(paths["plain"])
    cpu_hash = sha256_file(paths["cpu_decrypted"])
    gpu_hash = sha256_file(paths["gpu_decrypted"])
    if plain_hash != cpu_hash or plain_hash != gpu_hash:
        raise RuntimeError("CPU/GPU decrypt output hash mismatch")

    bytes_decrypted = paths["cipher"].stat().st_size
    cpu_throughput = bytes_decrypted / cpu_elapsed / 1024 / 1024 if cpu_elapsed else 0.0
    gpu_throughput = bytes_decrypted / gpu_elapsed / 1024 / 1024 if gpu_elapsed else 0.0
    speedup = cpu_elapsed / gpu_elapsed if gpu_elapsed else 0.0

    print("GPU验证：通过")
    print(f"GPU设备：{gpu_name}")
    print(f"加密模式：SM4-{args.mode}")
    print(f"测试文件大小(MB)：{args.size_mb}")
    print(f"分块大小(MB)：{args.chunk_mb}")
    print(f"原始文件：{paths['plain']}")
    print(f"密文文件：{paths['cipher']}")
    print(f"CPU解密文件：{paths['cpu_decrypted']}")
    print(f"GPU解密文件：{paths['gpu_decrypted']}")
    print(f"原始文件sha256：{plain_hash}")
    print(f"CPU解密sha256：{cpu_hash}")
    print(f"GPU解密sha256：{gpu_hash}")
    print(f"CPU解密耗时(秒)：{cpu_elapsed:.6f}")
    print(f"GPU解密耗时(秒)：{gpu_elapsed:.6f}")
    print(f"CPU解密吞吐量(MB/s)：{cpu_throughput:.2f}")
    print(f"GPU解密吞吐量(MB/s)：{gpu_throughput:.2f}")
    print(f"GPU相对CPU加速比：{speedup:.2f}")
    return 0


def build_paths(output_dir: Path) -> dict[str, Path]:
    return {
        "plain": output_dir / "sample_plain.bin",
        "cipher": output_dir / "sample_cipher.bin",
        "cpu_decrypted": output_dir / "sample_cpu_decrypted.bin",
        "gpu_decrypted": output_dir / "sample_gpu_decrypted.bin",
    }


def measure_cpu_decrypt(paths: dict[str, Path], mode: str, chunk_size: int) -> float:
    start = time.perf_counter()
    decrypt_file(paths["cipher"], paths["cpu_decrypted"], DEFAULT_KEY, DEFAULT_IV, mode=mode, chunk_size=chunk_size)
    return time.perf_counter() - start


def measure_gpu_decrypt(paths: dict[str, Path], mode: str, chunk_size: int, device: str) -> float:
    synchronize_device(device)
    start = time.perf_counter()
    decrypt_file_torch(paths["cipher"], paths["gpu_decrypted"], DEFAULT_KEY, DEFAULT_IV, mode=mode, chunk_size=chunk_size, device=device)
    synchronize_device(device)
    return time.perf_counter() - start


def write_sample_file(path: Path, size_mb: int) -> None:
    pattern = b"SM4 GPU validation file block.\n"
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
