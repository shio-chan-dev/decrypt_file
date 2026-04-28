"""SM4 CPU/GPU 对比验证脚本。

该脚本面向已安装 PyTorch 且 CUDA 可用的 GPU 服务器。脚本会生成同一份
测试密文，分别使用 CPU 和 Torch/CUDA 路径解密，并输出中文对比指标。
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from decrypt_file import decrypt_file, encrypt_file, sha256_file
from decrypt_file.sm4_torch import cuda_device_name, decrypt_file_torch, synchronize_device

DEFAULT_KEY = b"0123456789abcdef"
DEFAULT_IV = b"abcdef9876543210"


def main() -> int:
    """
    解析命令行参数并执行 CPU/GPU 解密对比验证。

    Args:
        None: 参数通过命令行传入。

    Returns:
        int: 进程退出码，0 表示验证通过，2 表示 GPU 环境检查失败。

    Raises:
        RuntimeError: CPU/GPU 解密结果 hash 不一致时抛出。
        ValueError: 分块大小、加密模式或 SM4 参数不合法时抛出。
        OSError: 文件读写失败时由底层文件操作抛出。
    """
    parser = argparse.ArgumentParser(description="Run SM4 CPU/GPU validation on a CUDA machine.")
    parser.add_argument("--mode", choices=["CBC", "CTR"], default="CBC")
    parser.add_argument("--size-mb", type=int, default=64)
    parser.add_argument("--chunk-mb", type=int, default=16)
    parser.add_argument("--output-dir", default="validation_output/sm4_gpu")
    parser.add_argument("--device", default="cuda")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # chunk-mb 控制单次送入 CPU/GPU 解密的文件块大小。
    chunk_size = args.chunk_mb * 1024 * 1024
    if chunk_size % 16:
        raise ValueError("chunk size must be a multiple of 16 bytes")

    # 先检查 GPU 环境，避免在无 CUDA 机器上生成无意义性能数据。
    try:
        gpu_name = cuda_device_name(args.device)
    except RuntimeError as exc:
        print("GPU环境检查：失败")
        print(f"失败原因：{exc}")
        print("处理建议：请确认运行脚本的 python3 和验证 PyTorch 的 python3 是同一个解释器。")
        print("处理建议：如果日志提示 NVIDIA driver 过旧，请安装与当前驱动兼容的 PyTorch CUDA 版本。")
        print('排查命令：python3 -c "import sys, torch; print(sys.executable); print(torch.__version__); print(torch.version.cuda); print(torch.cuda.is_available())"')
        return 2

    paths = build_paths(output_dir)
    write_sample_file(paths["plain"], args.size_mb)
    encrypt_file(paths["plain"], paths["cipher"], DEFAULT_KEY, DEFAULT_IV, mode=args.mode)

    # CPU/GPU 使用同一份密文，保证耗时和吞吐量可对比。
    cpu_elapsed = measure_cpu_decrypt(paths, args.mode, chunk_size)
    gpu_elapsed = measure_gpu_decrypt(paths, args.mode, chunk_size, args.device)

    # hash 同时校验 CPU 解密和 GPU 解密，避免只比较速度不验证正确性。
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
    """
    生成 CPU/GPU 对比验证需要的文件路径。

    Args:
        output_dir (Path): 验证输出目录。

    Returns:
        dict[str, Path]: 包含原始文件、密文文件、CPU 解密文件和 GPU 解密文件路径。

    Raises:
        None: 仅组装路径，不进行文件读写。
    """
    return {
        "plain": output_dir / "sample_plain.bin",
        "cipher": output_dir / "sample_cipher.bin",
        "cpu_decrypted": output_dir / "sample_cpu_decrypted.bin",
        "gpu_decrypted": output_dir / "sample_gpu_decrypted.bin",
    }


def measure_cpu_decrypt(paths: dict[str, Path], mode: str, chunk_size: int) -> float:
    """
    统计 CPU 解密耗时。

    Args:
        paths (dict[str, Path]): 验证文件路径集合。
        mode (str): SM4 模式，支持 CBC 或 CTR。
        chunk_size (int): 文件解密分块大小，单位字节。

    Returns:
        float: CPU 解密耗时，单位秒。

    Raises:
        OSError: 文件读写失败时由底层文件操作抛出。
        ValueError: mode 或密文数据不合法时由底层函数抛出。
    """
    start = time.perf_counter()
    decrypt_file(paths["cipher"], paths["cpu_decrypted"], DEFAULT_KEY, DEFAULT_IV, mode=mode, chunk_size=chunk_size)
    return time.perf_counter() - start


def measure_gpu_decrypt(paths: dict[str, Path], mode: str, chunk_size: int, device: str) -> float:
    """
    统计 GPU 解密耗时。

    Args:
        paths (dict[str, Path]): 验证文件路径集合。
        mode (str): SM4 模式，支持 CBC 或 CTR。
        chunk_size (int): 文件解密分块大小，单位字节。
        device (str): Torch 设备名称，通常为 cuda。

    Returns:
        float: GPU 解密耗时，单位秒。

    Raises:
        RuntimeError: PyTorch 或 CUDA 不可用时抛出。
        OSError: 文件读写失败时由底层文件操作抛出。
        ValueError: mode 或密文数据不合法时由底层函数抛出。
    """
    # CUDA 调用是异步的，计时前后都需要同步设备。
    synchronize_device(device)
    start = time.perf_counter()
    decrypt_file_torch(paths["cipher"], paths["gpu_decrypted"], DEFAULT_KEY, DEFAULT_IV, mode=mode, chunk_size=chunk_size, device=device)
    synchronize_device(device)
    return time.perf_counter() - start


def write_sample_file(path: Path, size_mb: int) -> None:
    """
    生成指定大小的 GPU 对比测试文件。

    Args:
        path (Path): 测试文件输出路径。
        size_mb (int): 文件大小，单位 MB。

    Returns:
        None: 函数直接写入 path。

    Raises:
        OSError: 文件写入失败时由底层文件操作抛出。
    """
    pattern = b"SM4 GPU validation file block.\n"
    # 构造 1MB 模板块，减少生成大文件时的循环次数。
    block = (pattern * ((1024 * 1024 // len(pattern)) + 1))[: 1024 * 1024]
    target_size = size_mb * 1024 * 1024
    written = 0

    with path.open("wb") as target:
        while written < target_size:
            # 最后一轮只写入剩余字节，保证输出文件大小准确。
            chunk = block[: min(len(block), target_size - written)]
            target.write(chunk)
            written += len(chunk)


if __name__ == "__main__":
    raise SystemExit(main())
