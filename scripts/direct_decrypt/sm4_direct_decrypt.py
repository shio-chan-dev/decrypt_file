"""SM4 直接解密测试脚本。

该脚本用于验证外部提供的真实加密文件或小段密文、密钥和 IV 是否能按
SM4-CBC/PKCS7 解密。它不会生成样例数据，只会基于命令行传入的真实样例
做尝试，并输出中文结果。
"""

from __future__ import annotations

import argparse
import base64
import sys
import time
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from decrypt_file import decrypt_bytes, decrypt_file, sha256_file

SM4_MODE = "CBC"
SM4_PADDING = "pkcs7"


@dataclass(frozen=True)
class CipherCandidate:
    """待尝试解密的密文字节候选。"""

    name: str
    data: bytes


def main() -> int:
    """
    解析命令行参数并尝试直接解密外部密文样例。

    Args:
        None: 参数通过命令行传入。

    Returns:
        int: 进程退出码，0 表示脚本执行完成。

    Raises:
        ValueError: 密钥或 IV 不是合法十六进制，或者长度不符合 SM4 要求时抛出。
    """
    parser = argparse.ArgumentParser(description="Directly test SM4-CBC/PKCS7 decryption with provided key/IV.")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--ciphertext", help="密文字符串，按整体输入，不自动按业务字段拆分")
    input_group.add_argument("--input-file", help="真正的加密文件路径，对应业务解包后的 encFilePath")
    parser.add_argument("--key-hex", required=True, help="16 字节 SM4 密钥，hex 格式")
    parser.add_argument("--iv-hex", required=True, help="16 字节 SM4 IV/初始向量，hex 格式")
    parser.add_argument("--output-file", help="文件解密输出路径；字符串模式下如果有可读结果，也会写入该文件")
    args = parser.parse_args()

    key = bytes.fromhex(args.key_hex)
    iv = bytes.fromhex(args.iv_hex)
    if len(key) != 16:
        raise ValueError("SM4 密钥必须是 16 字节，也就是 32 位 hex 字符")
    if len(iv) != 16:
        raise ValueError("SM4 IV 必须是 16 字节，也就是 32 位 hex 字符")

    if args.input_file:
        if not args.output_file:
            raise ValueError("使用 --input-file 解密文件时必须提供 --output-file")
        run_file_decrypt(args.input_file, args.output_file, key, iv)
        return 0

    candidates = build_cipher_candidates(args.ciphertext)
    last_success: bytes | None = None

    print("SM4直接解密测试：开始")
    print(f"输入密文字符数：{len(args.ciphertext)}")
    print(f"密钥长度(bytes)：{len(key)}")
    print(f"向量长度(bytes)：{len(iv)}")
    print(f"测试模式：SM4-{SM4_MODE}")
    print("CBC填充：PKCS7")

    for candidate in candidates:
        print("")
        print(f"密文解释方式：{candidate.name}")
        print(f"密文字节长度：{len(candidate.data)}")
        print(f"是否16字节对齐：{'是' if len(candidate.data) % 16 == 0 else '否'}")

        result = try_decrypt(candidate.data, key, iv)
        print_result(result)
        if result is not None:
            last_success = result

    if args.output_file and last_success is not None:
        with open(args.output_file, "wb") as target:
            target.write(last_success)
        print("")
        print(f"解密输出文件：{args.output_file}")

    print("")
    print("SM4直接解密测试：结束")
    return 0


def run_file_decrypt(input_file: str, output_file: str, key: bytes, iv: bytes) -> None:
    """
    使用 SM4-CBC/PKCS7 解密真实加密文件。

    Args:
        input_file (str): 业务解包后得到的加密文件路径。
        output_file (str): 解密后的明文文件输出路径。
        key (bytes): 16 字节 SM4 密钥。
        iv (bytes): 16 字节 SM4 IV。

    Returns:
        None: 解密结果直接写入 output_file。

    Raises:
        OSError: 文件读写失败时由底层文件操作抛出。
        ValueError: 密文、key、IV 或 padding 不合法时由底层函数抛出。
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print("SM4文件解密：开始")
    print(f"输入文件：{input_path}")
    print(f"输出文件：{output_path}")
    print(f"解密模式：SM4-{SM4_MODE}")
    print("CBC填充：PKCS7")

    bytes_decrypted = input_path.stat().st_size
    start = time.perf_counter()
    decrypt_file(input_path, output_path, key, iv, mode=SM4_MODE, padding=SM4_PADDING)
    elapsed = time.perf_counter() - start
    throughput = bytes_decrypted / elapsed / 1024 / 1024 if elapsed else 0.0

    print("解密状态：成功")
    print(f"输入文件大小(MB)：{bytes_decrypted / 1024 / 1024:.2f}")
    print(f"解密耗时(秒)：{elapsed:.6f}")
    print(f"解密吞吐量(MB/s)：{throughput:.2f}")
    print(f"输出文件sha256：{sha256_file(output_path)}")
    print("SM4文件解密：结束")


def build_cipher_candidates(ciphertext: str) -> list[CipherCandidate]:
    """
    将整体密文字符串转换为多个可能的密文字节候选。

    Args:
        ciphertext (str): 命令行传入的完整密文字符串。

    Returns:
        list[CipherCandidate]: 可尝试解密的密文字节候选。

    Raises:
        None: base64 或 hex 解析失败时只跳过对应候选。
    """
    candidates = []

    try:
        # validate=True 可以明确发现 `|` 这类非 base64 字符。
        decoded = base64.b64decode(ciphertext, validate=True)
        candidates.append(CipherCandidate("整体base64解码", decoded))
    except Exception as exc:
        print(f"整体base64解码：失败，原因：{exc}")

    try:
        decoded = bytes.fromhex(ciphertext)
        candidates.append(CipherCandidate("整体hex解码", decoded))
    except ValueError as exc:
        print(f"整体hex解码：失败，原因：{exc}")

    # 有些系统会把密文字符串本身作为 bytes 传输，这里也做一次直接尝试。
    candidates.append(CipherCandidate("整体字符串UTF-8字节", ciphertext.encode("utf-8")))
    return candidates


def try_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes | None:
    """
    使用 SM4-CBC/PKCS7 尝试解密。

    Args:
        ciphertext (bytes): 待解密密文字节。
        key (bytes): 16 字节 SM4 密钥。
        iv (bytes): 16 字节 SM4 IV/初始向量。

    Returns:
        bytes | None: 解密成功返回明文字节，失败返回 None。

    Raises:
        None: 解密异常会被捕获并转换为中文输出。
    """
    try:
        return decrypt_bytes(ciphertext, key, iv, mode=SM4_MODE, padding=SM4_PADDING)
    except Exception as exc:
        print(f"解密模式：SM4-{SM4_MODE}")
        print("解密状态：失败")
        print(f"失败原因：{type(exc).__name__}: {exc}")
        return None


def print_result(plaintext: bytes | None) -> None:
    """
    打印一次解密尝试结果。

    Args:
        plaintext (bytes | None): 解密得到的明文字节，失败时为 None。

    Returns:
        None: 结果直接打印到标准输出。

    Raises:
        None: 仅执行格式化输出。
    """
    if plaintext is None:
        return

    print(f"解密模式：SM4-{SM4_MODE}")
    print("解密状态：算法执行成功")
    print(f"明文长度(bytes)：{len(plaintext)}")
    print(f"明文hex预览：{plaintext[:128].hex()}")

    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        print("明文UTF-8：无法解码，可能不是文本或解密参数不匹配")
        return

    print("明文UTF-8：可解码")
    print(f"明文内容预览：{text[:500]}")


if __name__ == "__main__":
    raise SystemExit(main())
