"""SM4 单文件解密验证脚本。

用途：
1. 直接把本文件发给他人运行，不依赖本项目的 `decrypt_file/` 包。
2. 支持 `--backend cpu`、`--backend gpu`、`--backend both`、`--backend auto`。
3. 自动尝试整体密文、`|` 分段、base64、hex、ASN.1/DER 内部候选密文字段。
4. 固定使用 SM4-CBC + PKCS7 padding 解密。
5. 支持传入真实加密文件路径，按文件流输出解密文件。

依赖：
1. CPU 后端只使用 Python 标准库。
2. GPU 后端需要安装 PyTorch，并且 `torch.cuda.is_available()` 为 True。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path

SM4_BLOCK_BYTES = 16
MASK32 = 0xFFFFFFFF

SBOX = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
]

FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
CK = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249, 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229, 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209, 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
]


@dataclass(frozen=True)
class CipherCandidate:
    """待尝试解密的密文字节候选。"""

    name: str
    data: bytes


@dataclass(frozen=True)
class IvCandidate:
    """待尝试使用的 IV 候选。"""

    name: str
    data: bytes


def main() -> int:
    """
    解析命令行参数并执行 SM4 直接解密验证。

    Args:
        None: 参数通过命令行传入。

    Returns:
        int: 进程退出码，0 表示执行完成，2 表示 GPU 环境不可用。

    Raises:
        ValueError: key、IV 或 backend 参数不合法时抛出。
        OSError: 写入输出文件失败时由底层文件操作抛出。
    """
    parser = argparse.ArgumentParser(description="Standalone SM4-CBC/PKCS7 decrypt checker with CPU/GPU options.")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--ciphertext", help="外部提供的完整密文字符串")
    input_group.add_argument("--ciphertext-file", help="从文件读取密文字符串，适合密文很长时使用")
    input_group.add_argument("--input-file", help="真正的加密文件路径，对应业务解包后的 encFilePath")
    parser.add_argument("--key-hex", required=True, help="16 字节 SM4 密钥，hex 格式")
    parser.add_argument("--iv-hex", required=True, help="16 字节 SM4 IV/初始向量，hex 格式")
    parser.add_argument("--backend", choices=["auto", "cpu", "gpu", "both"], default="auto", help="解密后端，默认 auto")
    parser.add_argument("--device", default="cuda", help="GPU 后端使用的 Torch CUDA 设备，例如 cuda、cuda:0、cuda:2")
    parser.add_argument("--output-file", help="文件解密输出路径；字符串模式下如果出现可读 UTF-8 明文，也会写入该文件")
    parser.add_argument("--chunk-mb", type=int, default=16, help="文件解密分块大小，单位 MB")
    parser.add_argument("--show-failures", action="store_true", help="显示每个失败候选的具体失败原因")
    parser.add_argument("--show-unreadable", action="store_true", help="显示算法成功但 UTF-8 不可读的明文 hex 预览")
    args = parser.parse_args()

    key = bytes.fromhex(args.key_hex)
    iv = bytes.fromhex(args.iv_hex)
    validate_key_iv(key, iv)

    try:
        backends = resolve_backends(args.backend, args.device)
    except RuntimeError as exc:
        print("GPU环境检查：失败")
        print(f"失败原因：{exc}")
        print("处理建议：可以改用 --backend cpu，或在 CUDA 可用环境中运行 --backend gpu。")
        return 2

    if args.input_file:
        if not args.output_file:
            raise ValueError("使用 --input-file 解密文件时必须提供 --output-file")
        run_file_mode(args.input_file, args.output_file, key, iv, backends, args.device, args.chunk_mb)
        return 0

    ciphertext = read_ciphertext_arg(args.ciphertext, args.ciphertext_file)
    candidates, asn1_ivs = build_cipher_candidates(ciphertext)
    ivs = dedupe_ivs([IvCandidate("命令行传入IV", iv), *asn1_ivs])

    print("SM4单文件解密：开始")
    print(f"后端选择：{','.join(backends)}")
    print(f"密文字符数：{len(ciphertext)}")
    print(f"密文候选数量：{len(candidates)}")
    print(f"向量候选数量：{len(ivs)}")
    print("测试模式：SM4-CBC")
    print("CBC填充：PKCS7")

    readable_results: list[bytes] = []
    algorithm_success_count = 0
    failure_count = 0

    for backend in backends:
        print("")
        print(f"当前后端：{backend.upper()}")
        for candidate in candidates:
            for iv_candidate in ivs:
                plaintext, error = decrypt_once(backend, candidate.data, key, iv_candidate.data, args.device)
                if error:
                    failure_count += 1
                    if args.show_failures:
                        print_failure(backend, candidate.name, iv_candidate, error)
                    continue

                algorithm_success_count += 1
                if is_readable_utf8(plaintext):
                    readable_results.append(plaintext)
                    print_readable_success(backend, candidate.name, iv_candidate, plaintext)
                elif args.show_unreadable:
                    print_unreadable_success(backend, candidate.name, iv_candidate, plaintext)

    if args.output_file and readable_results:
        output_path = Path(args.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(readable_results[-1])
        print("")
        print(f"可读明文输出文件：{output_path}")

    print("")
    print("SM4单文件解密：结束")
    print(f"算法执行成功次数：{algorithm_success_count}")
    print(f"失败次数：{failure_count}")
    print(f"可读明文次数：{len(readable_results)}")
    if not readable_results:
        print("结论：未找到可读 UTF-8 明文，请继续确认密文字段、IV、PKCS7 padding 和密钥是否匹配。")
    return 0


def read_ciphertext_arg(ciphertext: str | None, ciphertext_file: str | None) -> str:
    """
    从命令行参数或文件读取密文字符串。

    Args:
        ciphertext (str | None): 命令行直接传入的密文。
        ciphertext_file (str | None): 密文文件路径。

    Returns:
        str: 去除首尾空白后的密文字符串。

    Raises:
        ValueError: 同时缺少或同时提供两个来源时抛出。
        OSError: 文件读取失败时由底层文件操作抛出。
    """
    if bool(ciphertext) == bool(ciphertext_file):
        raise ValueError("请二选一提供 --ciphertext 或 --ciphertext-file")
    if ciphertext_file:
        return Path(ciphertext_file).read_text(encoding="utf-8").strip()
    return ciphertext.strip()


def validate_key_iv(key: bytes, iv: bytes) -> None:
    """
    校验 SM4 key 和 IV 长度。

    Args:
        key (bytes): SM4 密钥。
        iv (bytes): SM4 IV/初始向量。

    Returns:
        None: 校验通过后返回。

    Raises:
        ValueError: key 或 IV 不是 16 字节时抛出。
    """
    if len(key) != SM4_BLOCK_BYTES:
        raise ValueError("SM4 密钥必须是 16 字节，也就是 32 位 hex 字符")
    if len(iv) != SM4_BLOCK_BYTES:
        raise ValueError("SM4 IV 必须是 16 字节，也就是 32 位 hex 字符")


def resolve_backends(backend: str, device: str) -> list[str]:
    """
    根据命令行参数确定实际执行的后端列表。

    Args:
        backend (str): 后端选项，支持 auto、cpu、gpu、both。
        device (str): GPU 后端使用的 Torch 设备。

    Returns:
        list[str]: 实际执行的后端列表。

    Raises:
        RuntimeError: 指定 gpu 或 both 但 CUDA 不可用时抛出。
    """
    if backend == "cpu":
        return ["cpu"]
    if backend == "gpu":
        print_gpu_info(device)
        return ["gpu"]
    if backend == "both":
        print_gpu_info(device)
        return ["cpu", "gpu"]

    try:
        print_gpu_info(device)
        return ["gpu"]
    except RuntimeError as exc:
        print("GPU自动选择：不可用")
        print(f"失败原因：{exc}")
        print("自动切换：CPU")
        return ["cpu"]


def run_file_mode(input_file: str, output_file: str, key: bytes, iv: bytes, backends: list[str], device: str, chunk_mb: int) -> None:
    """
    使用指定后端解密真实加密文件。

    Args:
        input_file (str): 业务解包后得到的加密文件路径。
        output_file (str): 明文文件输出路径。
        key (bytes): 16 字节 SM4 密钥。
        iv (bytes): 16 字节 SM4 IV。
        backends (list[str]): 实际执行的后端列表。
        device (str): GPU 后端使用的 Torch 设备。
        chunk_mb (int): 文件解密分块大小，单位 MB。

    Returns:
        None: 解密结果直接写入输出文件。

    Raises:
        OSError: 文件读写失败时由底层文件操作抛出。
        ValueError: chunk_mb、密文、key、IV 或 padding 不合法时抛出。
    """
    chunk_size = chunk_mb * 1024 * 1024
    if chunk_size % SM4_BLOCK_BYTES:
        raise ValueError("chunk size must be a multiple of 16 bytes")

    input_path = Path(input_file)
    output_path = Path(output_file)

    print("SM4单文件文件解密：开始")
    print(f"输入文件：{input_path}")
    print(f"解密模式：SM4-CBC")
    print("CBC填充：PKCS7")
    print(f"分块大小(MB)：{chunk_mb}")

    for backend in backends:
        target_path = output_path_for_backend(output_path, backend, len(backends))
        target_path.parent.mkdir(parents=True, exist_ok=True)

        if backend == "cpu":
            decrypt_file_cpu(input_path, target_path, key, iv, chunk_size)
        else:
            decrypt_file_gpu(input_path, target_path, key, iv, chunk_size, device)

        print("")
        print(f"后端：{backend.upper()}")
        print(f"输出文件：{target_path}")
        print(f"输出文件sha256：{sha256_file(target_path)}")

    print("")
    print("SM4单文件文件解密：结束")


def output_path_for_backend(output_path: Path, backend: str, backend_count: int) -> Path:
    """
    根据后端数量生成输出路径。

    Args:
        output_path (Path): 用户传入的输出路径。
        backend (str): 当前后端名称。
        backend_count (int): 本次执行后端数量。

    Returns:
        Path: 单后端时返回原路径，多后端时追加后端后缀。

    Raises:
        None: 仅做路径拼接。
    """
    if backend_count == 1:
        return output_path
    return output_path.with_name(f"{output_path.stem}_{backend}{output_path.suffix}")


def sha256_file(path: Path) -> str:
    """
    计算文件 sha256。

    Args:
        path (Path): 待计算 hash 的文件路径。

    Returns:
        str: 文件内容的 sha256 hex 字符串。

    Raises:
        OSError: 文件读取失败时由底层文件操作抛出。
    """
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_cipher_candidates(ciphertext: str) -> tuple[list[CipherCandidate], list[IvCandidate]]:
    """
    从外部密文字符串构造密文候选和 IV 候选。

    Args:
        ciphertext (str): 外部提供的完整密文字符串。

    Returns:
        tuple[list[CipherCandidate], list[IvCandidate]]: 密文候选和 ASN.1 内部 IV 候选。

    Raises:
        None: 无法解析的格式会被跳过。
    """
    candidates: list[CipherCandidate] = []
    ivs: list[IvCandidate] = []

    for name, text in split_ciphertext_parts(ciphertext):
        decoded = decode_base64(text)
        if decoded is not None:
            candidates.append(CipherCandidate(f"{name}base64解码", decoded))
            der_candidates, der_ivs = extract_asn1_candidates(decoded, name)
            candidates.extend(der_candidates)
            ivs.extend(der_ivs)

        decoded_hex = decode_hex(text)
        if decoded_hex is not None:
            candidates.append(CipherCandidate(f"{name}hex解码", decoded_hex))

    candidates.append(CipherCandidate("整体字符串UTF-8字节", ciphertext.encode("utf-8")))
    return dedupe_candidates(candidates), dedupe_ivs(ivs)


def split_ciphertext_parts(ciphertext: str) -> list[tuple[str, str]]:
    """
    返回整体密文和按竖线拆分后的密文段。

    Args:
        ciphertext (str): 外部提供的密文字符串。

    Returns:
        list[tuple[str, str]]: 来源名称和对应文本。

    Raises:
        None: 仅执行字符串拆分。
    """
    parts = [("整体", ciphertext)]
    if "|" in ciphertext:
        for index, part in enumerate(ciphertext.split("|"), start=1):
            parts.append((f"第{index}段", part))
    return parts


def decode_base64(text: str) -> bytes | None:
    """
    尝试按 base64 解码。

    Args:
        text (str): 待解码文本。

    Returns:
        bytes | None: 成功返回字节，失败返回 None。

    Raises:
        None: 解码异常会被捕获。
    """
    try:
        return base64.b64decode(text, validate=True)
    except Exception:
        return None


def decode_hex(text: str) -> bytes | None:
    """
    尝试按 hex 解码。

    Args:
        text (str): 待解码文本。

    Returns:
        bytes | None: 成功返回字节，失败返回 None。

    Raises:
        None: 解码异常会被捕获。
    """
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


def extract_asn1_candidates(data: bytes, source_name: str) -> tuple[list[CipherCandidate], list[IvCandidate]]:
    """
    从 DER/ASN.1 字节中提取可能的密文和 IV。

    Args:
        data (bytes): DER/ASN.1 编码字节。
        source_name (str): 当前数据来源名称。

    Returns:
        tuple[list[CipherCandidate], list[IvCandidate]]: 提取出的密文候选和 IV 候选。

    Raises:
        None: ASN.1 解析失败时返回空列表。
    """
    candidates: list[CipherCandidate] = []
    ivs: list[IvCandidate] = []
    try:
        nodes = parse_der_nodes(data)
    except ValueError:
        return candidates, ivs

    for index, (tag, value) in enumerate(nodes, start=1):
        if tag == 0x04 and len(value) == SM4_BLOCK_BYTES:
            ivs.append(IvCandidate(f"{source_name}ASN.1 OCTET STRING#{index}", value))
        if tag == 0x80 and len(value) >= SM4_BLOCK_BYTES:
            candidates.append(CipherCandidate(f"{source_name}ASN.1 context[0]#{index}", value))
        if tag == 0x04 and len(value) > SM4_BLOCK_BYTES:
            candidates.append(CipherCandidate(f"{source_name}ASN.1 OCTET STRING#{index}", value))

    return candidates, ivs


def parse_der_nodes(data: bytes) -> list[tuple[int, bytes]]:
    """
    递归解析 DER TLV 节点，返回 primitive 节点。

    Args:
        data (bytes): DER/ASN.1 编码字节。

    Returns:
        list[tuple[int, bytes]]: primitive 节点的 tag 和 value。

    Raises:
        ValueError: DER 长度字段不完整或越界时抛出。
    """
    nodes: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        tag = data[offset]
        offset += 1
        length, offset = read_der_length(data, offset)
        end = offset + length
        if end > len(data):
            raise ValueError("DER length exceeds available bytes")

        value = data[offset:end]
        if tag & 0x20:
            nodes.extend(parse_der_nodes(value))
        else:
            nodes.append((tag, value))
        offset = end
    return nodes


def read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    """
    读取 DER length 字段。

    Args:
        data (bytes): DER/ASN.1 编码字节。
        offset (int): length 字段起始位置。

    Returns:
        tuple[int, int]: length 数值和新的 offset。

    Raises:
        ValueError: length 字段缺失、过长或越界时抛出。
    """
    if offset >= len(data):
        raise ValueError("missing DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    size = first & 0x7F
    if size == 0 or size > 4 or offset + size > len(data):
        raise ValueError("invalid DER length")
    return int.from_bytes(data[offset : offset + size], "big"), offset + size


def dedupe_candidates(candidates: list[CipherCandidate]) -> list[CipherCandidate]:
    """
    按字节内容去重密文候选。

    Args:
        candidates (list[CipherCandidate]): 原始候选列表。

    Returns:
        list[CipherCandidate]: 去重后的候选列表。

    Raises:
        None: 仅执行内存去重。
    """
    seen: set[bytes] = set()
    result = []
    for candidate in candidates:
        if candidate.data in seen:
            continue
        seen.add(candidate.data)
        result.append(candidate)
    return result


def dedupe_ivs(ivs: list[IvCandidate]) -> list[IvCandidate]:
    """
    按字节内容去重 IV 候选。

    Args:
        ivs (list[IvCandidate]): 原始 IV 候选列表。

    Returns:
        list[IvCandidate]: 去重后的 IV 候选列表。

    Raises:
        None: 仅执行内存去重。
    """
    seen: set[bytes] = set()
    result = []
    for iv in ivs:
        if iv.data in seen:
            continue
        seen.add(iv.data)
        result.append(iv)
    return result


def decrypt_once(backend: str, ciphertext: bytes, key: bytes, iv: bytes, device: str) -> tuple[bytes, Exception | None]:
    """
    使用指定后端和 IV 尝试执行一次 SM4-CBC/PKCS7 解密。

    Args:
        backend (str): 解密后端，cpu 或 gpu。
        ciphertext (bytes): 待解密密文字节。
        key (bytes): 16 字节 SM4 密钥。
        iv (bytes): 16 字节 SM4 IV。
        device (str): GPU 后端使用的 Torch 设备。

    Returns:
        tuple[bytes, Exception | None]: 成功时返回明文和 None，失败时返回空 bytes 和异常。

    Raises:
        None: 单次解密异常会作为返回值返回。
    """
    try:
        if backend == "cpu":
            return decrypt_bytes_cpu(ciphertext, key, iv), None
        return decrypt_bytes_gpu(ciphertext, key, iv, device), None
    except Exception as exc:
        return b"", exc


def decrypt_bytes_cpu(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    使用纯 Python SM4 实现解密 CBC/PKCS7 字节数据。

    Args:
        ciphertext (bytes): 待解密密文字节。
        key (bytes): 16 字节 SM4 密钥。
        iv (bytes): 16 字节 IV。

    Returns:
        bytes: 解密后的明文字节。

    Raises:
        ValueError: 参数或密文格式不合法时抛出。
    """
    validate_key_iv(key, iv)
    return decrypt_cbc_cpu(ciphertext, key, iv)


def decrypt_file_cpu(input_path: Path, output_path: Path, key: bytes, iv: bytes, chunk_size: int) -> None:
    """
    使用纯 Python SM4 实现流式文件解密。

    Args:
        input_path (Path): 加密文件路径。
        output_path (Path): 明文文件输出路径。
        key (bytes): 16 字节 SM4 密钥。
        iv (bytes): 16 字节 IV。
        chunk_size (int): 文件读取分块大小，必须是 16 的倍数。

    Returns:
        None: 解密结果直接写入 output_path。

    Raises:
        ValueError: chunk_size、密文长度或 padding 不合法时抛出。
        OSError: 文件读写失败时由底层文件操作抛出。
    """
    validate_key_iv(key, iv)
    if chunk_size % SM4_BLOCK_BYTES:
        raise ValueError("chunk_size must be a multiple of 16 bytes")

    round_keys = _round_keys(key)[::-1]
    previous = iv
    pending_plain = b""

    with Path(input_path).open("rb") as source, Path(output_path).open("wb") as target:
        while chunk := source.read(chunk_size):
            plain_chunk, previous = decrypt_cbc_blocks_cpu(chunk, round_keys, previous)
            if pending_plain:
                target.write(pending_plain)
            target.write(plain_chunk[:-SM4_BLOCK_BYTES])
            pending_plain = plain_chunk[-SM4_BLOCK_BYTES:]

        if not pending_plain:
            raise ValueError("missing CBC ciphertext")
        target.write(pkcs7_unpad(pending_plain))


def decrypt_cbc_cpu(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    使用 SM4-CBC 解密并执行 PKCS7 去填充。

    Args:
        ciphertext (bytes): CBC 密文字节，长度必须是 16 的倍数。
        key (bytes): 16 字节 SM4 密钥。
        iv (bytes): 16 字节 IV。

    Returns:
        bytes: 解密后的明文字节。

    Raises:
        ValueError: 密文长度或 padding 不合法时抛出。
    """
    plaintext, _ = decrypt_cbc_blocks_cpu(ciphertext, _round_keys(key)[::-1], iv)
    return pkcs7_unpad(plaintext)


def decrypt_cbc_blocks_cpu(ciphertext: bytes, round_keys: list[int], previous: bytes) -> tuple[bytes, bytes]:
    """
    解密一段 16 字节对齐的 CBC 密文块，不执行 PKCS7 去填充。

    Args:
        ciphertext (bytes): 16 字节对齐的 CBC 密文字节。
        round_keys (list[int]): 解密用的 32 个轮密钥。
        previous (bytes): 当前分块前一个 CBC 密文块，首块使用 IV。

    Returns:
        tuple[bytes, bytes]: 当前明文块拼接结果和当前分块最后一个密文块。

    Raises:
        ValueError: 密文或 previous 长度不合法时抛出。
    """
    if len(previous) != SM4_BLOCK_BYTES:
        raise ValueError("previous CBC block must be 16 bytes")
    if not ciphertext or len(ciphertext) % SM4_BLOCK_BYTES:
        raise ValueError("CBC ciphertext length must be a positive multiple of 16 bytes")

    plaintext_blocks = []
    for offset in range(0, len(ciphertext), SM4_BLOCK_BYTES):
        block = ciphertext[offset : offset + SM4_BLOCK_BYTES]
        decrypted = sm4_crypt_block_cpu(block, round_keys)
        plaintext_blocks.append(xor_bytes(decrypted, previous))
        previous = block
    return b"".join(plaintext_blocks), previous


def sm4_crypt_block_cpu(block: bytes, round_keys: list[int]) -> bytes:
    """
    使用 CPU 整数运算处理一个 SM4 分组。

    Args:
        block (bytes): 16 字节输入分组。
        round_keys (list[int]): 32 个轮密钥。

    Returns:
        bytes: 16 字节输出分组。

    Raises:
        ValueError: block 长度不是 16 字节时抛出。
    """
    if len(block) != SM4_BLOCK_BYTES:
        raise ValueError("SM4 block must be 16 bytes")

    words = [int.from_bytes(block[index : index + 4], "big") for index in range(0, SM4_BLOCK_BYTES, 4)]
    x0, x1, x2, x3 = words
    for rk in round_keys:
        mixed = x1 ^ x2 ^ x3 ^ rk
        x0, x1, x2, x3 = x1, x2, x3, (x0 ^ round_transform_int(mixed)) & MASK32
    return b"".join(word.to_bytes(4, "big") for word in (x3, x2, x1, x0))


def decrypt_bytes_gpu(ciphertext: bytes, key: bytes, iv: bytes, device: str) -> bytes:
    """
    使用 Torch/CUDA SM4 实现解密 CBC/PKCS7 字节数据。

    Args:
        ciphertext (bytes): 待解密密文字节。
        key (bytes): 16 字节 SM4 密钥。
        iv (bytes): 16 字节 IV。
        device (str): Torch CUDA 设备。

    Returns:
        bytes: 解密后的明文字节。

    Raises:
        RuntimeError: PyTorch 或 CUDA 不可用时抛出。
        ValueError: 参数或密文格式不合法时抛出。
    """
    validate_key_iv(key, iv)
    torch = require_torch()
    torch_device = torch.device(device)
    if torch_device.type != "cuda":
        raise RuntimeError("GPU backend requires cuda device")
    if not torch.cuda.is_available():
        torch_version = getattr(torch, "__version__", "unknown")
        torch_cuda = getattr(torch.version, "cuda", "unknown")
        raise RuntimeError(f"CUDA is not available (torch={torch_version}, torch_cuda={torch_cuda})")

    torch.cuda.synchronize(torch_device)
    plaintext = decrypt_cbc_gpu(ciphertext, key, iv, torch_device, torch)
    torch.cuda.synchronize(torch_device)
    return plaintext


def decrypt_file_gpu(input_path: Path, output_path: Path, key: bytes, iv: bytes, chunk_size: int, device: str) -> None:
    """
    使用 Torch/CUDA SM4 实现流式文件解密。

    Args:
        input_path (Path): 加密文件路径。
        output_path (Path): 明文文件输出路径。
        key (bytes): 16 字节 SM4 密钥。
        iv (bytes): 16 字节 IV。
        chunk_size (int): 文件读取分块大小，必须是 16 的倍数。
        device (str): Torch CUDA 设备。

    Returns:
        None: 解密结果直接写入 output_path。

    Raises:
        RuntimeError: PyTorch 或 CUDA 不可用时抛出。
        ValueError: chunk_size、密文长度或 padding 不合法时抛出。
        OSError: 文件读写失败时由底层文件操作抛出。
    """
    validate_key_iv(key, iv)
    if chunk_size % SM4_BLOCK_BYTES:
        raise ValueError("chunk_size must be a multiple of 16 bytes")

    torch = require_torch()
    torch_device = torch.device(device)
    if torch_device.type != "cuda":
        raise RuntimeError("GPU backend requires cuda device")
    if not torch.cuda.is_available():
        torch_version = getattr(torch, "__version__", "unknown")
        torch_cuda = getattr(torch.version, "cuda", "unknown")
        raise RuntimeError(f"CUDA is not available (torch={torch_version}, torch_cuda={torch_cuda})")

    round_keys = _round_keys(key)[::-1]
    previous = iv
    pending_plain = b""

    torch.cuda.synchronize(torch_device)
    with Path(input_path).open("rb") as source, Path(output_path).open("wb") as target:
        while chunk := source.read(chunk_size):
            plain_chunk, previous = decrypt_cbc_blocks_gpu(chunk, round_keys, previous, torch_device, torch)
            if pending_plain:
                target.write(pending_plain)
            target.write(plain_chunk[:-SM4_BLOCK_BYTES])
            pending_plain = plain_chunk[-SM4_BLOCK_BYTES:]

        if not pending_plain:
            raise ValueError("missing CBC ciphertext")
        target.write(pkcs7_unpad(pending_plain))
    torch.cuda.synchronize(torch_device)


def decrypt_cbc_gpu(ciphertext: bytes, key: bytes, iv: bytes, device, torch) -> bytes:
    """
    使用 Torch/CUDA 解密 CBC 密文并去除 PKCS7 padding。

    Args:
        ciphertext (bytes): CBC 密文字节，长度必须是 16 的倍数。
        key (bytes): 16 字节 SM4 密钥。
        iv (bytes): 16 字节 IV。
        device: Torch 设备对象。
        torch: PyTorch 模块对象。

    Returns:
        bytes: 解密后的明文字节。

    Raises:
        ValueError: 密文长度或 padding 不合法时抛出。
    """
    plaintext, _ = decrypt_cbc_blocks_gpu(ciphertext, _round_keys(key)[::-1], iv, device, torch)
    return pkcs7_unpad(plaintext)


def decrypt_cbc_blocks_gpu(ciphertext: bytes, round_keys: list[int], previous_block: bytes, device, torch) -> tuple[bytes, bytes]:
    """
    使用 Torch/CUDA 解密一段 CBC 密文块，不执行 PKCS7 去填充。

    Args:
        ciphertext (bytes): 16 字节对齐的 CBC 密文字节。
        round_keys (list[int]): 解密用的 32 个轮密钥。
        previous_block (bytes): 当前分块前一个 CBC 密文块，首块使用 IV。
        device: Torch 设备对象。
        torch: PyTorch 模块对象。

    Returns:
        tuple[bytes, bytes]: 当前明文块拼接结果和当前分块最后一个密文块。

    Raises:
        ValueError: 密文或 previous_block 长度不合法时抛出。
    """
    if len(previous_block) != SM4_BLOCK_BYTES:
        raise ValueError("previous CBC block must be 16 bytes")
    if not ciphertext or len(ciphertext) % SM4_BLOCK_BYTES:
        raise ValueError("data length must be a positive multiple of 16 bytes")

    cipher_blocks = bytes_to_block_tensor(ciphertext, device, torch)
    decrypted_blocks = crypt_blocks_gpu(cipher_blocks, round_keys, device, torch)
    previous = torch.empty_like(cipher_blocks)
    previous[0] = bytes_to_block_tensor(previous_block, device, torch)[0]
    if cipher_blocks.shape[0] > 1:
        previous[1:] = cipher_blocks[:-1]
    plain_blocks = torch.bitwise_xor(decrypted_blocks, previous)
    return block_tensor_to_bytes(plain_blocks), ciphertext[-SM4_BLOCK_BYTES:]


def crypt_blocks_gpu(blocks, round_keys: list[int], device, torch):
    """
    在 Torch 设备上批量执行 SM4 分组加解密。

    Args:
        blocks: 形状为 (n, 16) 的 uint8 Torch 张量。
        round_keys (list[int]): 32 个 SM4 轮密钥。
        device: Torch 设备对象。
        torch: PyTorch 模块对象。

    Returns:
        torch.Tensor: 加解密后的 uint8 分组张量。

    Raises:
        RuntimeError: Torch 张量运算失败时由 PyTorch 抛出。
    """
    sbox = torch.tensor(SBOX, dtype=torch.int64, device=device)
    words = blocks_to_words(blocks, torch)
    x0, x1, x2, x3 = words[:, 0], words[:, 1], words[:, 2], words[:, 3]
    keys = torch.tensor(round_keys, dtype=torch.int64, device=device)

    for rk in keys:
        mixed = torch.bitwise_xor(torch.bitwise_xor(torch.bitwise_xor(x1, x2), x3), rk)
        x0, x1, x2, x3 = x1, x2, x3, torch.bitwise_xor(x0, round_transform_tensor(mixed, sbox, torch))
    return words_to_blocks(torch.stack((x3, x2, x1, x0), dim=1), torch)


def blocks_to_words(blocks, torch):
    """
    将 16 字节分组张量转换为 32 位字张量。

    Args:
        blocks: 形状为 (n, 16) 的 uint8 Torch 张量。
        torch: PyTorch 模块对象。

    Returns:
        torch.Tensor: 形状为 (n, 4) 的 int64 Torch 张量。

    Raises:
        RuntimeError: Torch 张量运算失败时由 PyTorch 抛出。
    """
    values = blocks.to(torch.int64)
    return (
        (values[:, 0::4] << 24)
        | (values[:, 1::4] << 16)
        | (values[:, 2::4] << 8)
        | values[:, 3::4]
    )


def words_to_blocks(words, torch):
    """
    将 32 位字张量转换回 16 字节分组张量。

    Args:
        words: 形状为 (n, 4) 的 int64 Torch 张量。
        torch: PyTorch 模块对象。

    Returns:
        torch.Tensor: 形状为 (n, 16) 的 uint8 Torch 张量。

    Raises:
        RuntimeError: Torch 张量运算失败时由 PyTorch 抛出。
    """
    return torch.stack(
        (
            (words[:, 0] >> 24) & 0xFF,
            (words[:, 0] >> 16) & 0xFF,
            (words[:, 0] >> 8) & 0xFF,
            words[:, 0] & 0xFF,
            (words[:, 1] >> 24) & 0xFF,
            (words[:, 1] >> 16) & 0xFF,
            (words[:, 1] >> 8) & 0xFF,
            words[:, 1] & 0xFF,
            (words[:, 2] >> 24) & 0xFF,
            (words[:, 2] >> 16) & 0xFF,
            (words[:, 2] >> 8) & 0xFF,
            words[:, 2] & 0xFF,
            (words[:, 3] >> 24) & 0xFF,
            (words[:, 3] >> 16) & 0xFF,
            (words[:, 3] >> 8) & 0xFF,
            words[:, 3] & 0xFF,
        ),
        dim=1,
    ).to(torch.uint8)


def round_transform_tensor(value, sbox, torch):
    """
    执行 SM4 轮函数中的 T 变换。

    Args:
        value: 输入 32 位字张量。
        sbox: SM4 SBOX 张量。
        torch: PyTorch 模块对象。

    Returns:
        torch.Tensor: 变换后的 32 位字张量。

    Raises:
        RuntimeError: Torch 张量运算失败时由 PyTorch 抛出。
    """
    substituted = substitute_tensor(value, sbox)
    return substituted ^ rotl_tensor(substituted, 2) ^ rotl_tensor(substituted, 10) ^ rotl_tensor(substituted, 18) ^ rotl_tensor(substituted, 24)


def substitute_tensor(value, sbox):
    """
    对 32 位字张量执行 SM4 SBOX 替换。

    Args:
        value: 输入 32 位字张量。
        sbox: SM4 SBOX 张量。

    Returns:
        torch.Tensor: SBOX 替换后的 32 位字张量。

    Raises:
        RuntimeError: Torch 张量运算失败时由 PyTorch 抛出。
    """
    return (
        (sbox[(value >> 24) & 0xFF] << 24)
        | (sbox[(value >> 16) & 0xFF] << 16)
        | (sbox[(value >> 8) & 0xFF] << 8)
        | sbox[value & 0xFF]
    )


def rotl_tensor(value, bits: int):
    """
    对 32 位字张量执行循环左移。

    Args:
        value: 输入 32 位字张量。
        bits (int): 左移位数。

    Returns:
        torch.Tensor: 循环左移后的 32 位字张量。

    Raises:
        RuntimeError: Torch 张量运算失败时由 PyTorch 抛出。
    """
    return ((value << bits) & MASK32) | (value >> (32 - bits))


def bytes_to_block_tensor(data: bytes, device, torch):
    """
    将 16 字节对齐的数据转换为 Torch 分组张量。

    Args:
        data (bytes): 输入字节，长度必须是 16 的倍数。
        device: Torch 设备对象。
        torch: PyTorch 模块对象。

    Returns:
        torch.Tensor: 形状为 (n, 16) 的 uint8 Torch 张量。

    Raises:
        ValueError: data 长度不是 16 的倍数时抛出。
    """
    if len(data) % SM4_BLOCK_BYTES:
        raise ValueError("data length must be a multiple of 16 bytes")
    return bytes_to_tensor(data, device, torch).reshape(-1, SM4_BLOCK_BYTES)


def bytes_to_tensor(data: bytes, device, torch):
    """
    将 bytes 复制到指定 Torch 设备。

    Args:
        data (bytes): 输入字节。
        device: Torch 设备对象。
        torch: PyTorch 模块对象。

    Returns:
        torch.Tensor: uint8 Torch 张量。

    Raises:
        RuntimeError: Torch 张量创建或设备传输失败时由 PyTorch 抛出。
    """
    tensor = torch.frombuffer(bytearray(data), dtype=torch.uint8)
    tensor = tensor.to(device)
    return tensor.clone() if device.type == "cpu" else tensor


def block_tensor_to_bytes(blocks) -> bytes:
    """
    将 Torch 分组张量转换为 bytes。

    Args:
        blocks: 形状为 (n, 16) 的 uint8 Torch 张量。

    Returns:
        bytes: 拼接后的字节。

    Raises:
        RuntimeError: Torch 张量拷贝回 CPU 失败时由 PyTorch 抛出。
    """
    return bytes(blocks.reshape(-1).cpu().tolist())


def _round_keys(key: bytes) -> list[int]:
    """
    生成 SM4 轮密钥。

    Args:
        key (bytes): 16 字节 SM4 密钥。

    Returns:
        list[int]: 32 个轮密钥。

    Raises:
        ValueError: key 长度不是 16 字节时抛出。
    """
    if len(key) != SM4_BLOCK_BYTES:
        raise ValueError("SM4 key must be 16 bytes")

    key_words = [int.from_bytes(key[index : index + 4], "big") for index in range(0, SM4_BLOCK_BYTES, 4)]
    k = [word ^ FK[index] for index, word in enumerate(key_words)]
    keys = []
    for index in range(32):
        mixed = k[index + 1] ^ k[index + 2] ^ k[index + 3] ^ CK[index]
        round_key = (k[index] ^ key_transform_int(mixed)) & MASK32
        k.append(round_key)
        keys.append(round_key)
    return keys


def key_transform_int(value: int) -> int:
    """
    执行 SM4 密钥扩展 T' 变换。

    Args:
        value (int): 输入 32 位字。

    Returns:
        int: 变换后的 32 位字。

    Raises:
        None: 仅进行整数运算。
    """
    substituted = substitute_int(value)
    return substituted ^ rotl_int(substituted, 13) ^ rotl_int(substituted, 23)


def round_transform_int(value: int) -> int:
    """
    执行 SM4 数据轮函数 T 变换。

    Args:
        value (int): 输入 32 位字。

    Returns:
        int: 变换后的 32 位字。

    Raises:
        None: 仅进行整数运算。
    """
    substituted = substitute_int(value)
    return substituted ^ rotl_int(substituted, 2) ^ rotl_int(substituted, 10) ^ rotl_int(substituted, 18) ^ rotl_int(substituted, 24)


def substitute_int(value: int) -> int:
    """
    对整数形式的 32 位字执行 SBOX 替换。

    Args:
        value (int): 输入 32 位字。

    Returns:
        int: SBOX 替换后的 32 位字。

    Raises:
        None: 仅进行整数运算。
    """
    return (
        (SBOX[(value >> 24) & 0xFF] << 24)
        | (SBOX[(value >> 16) & 0xFF] << 16)
        | (SBOX[(value >> 8) & 0xFF] << 8)
        | SBOX[value & 0xFF]
    )


def rotl_int(value: int, bits: int) -> int:
    """
    对 32 位整数执行循环左移。

    Args:
        value (int): 输入 32 位字。
        bits (int): 左移位数。

    Returns:
        int: 循环左移后的 32 位字。

    Raises:
        None: 仅进行整数运算。
    """
    return ((value << bits) & MASK32) | (value >> (32 - bits))


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """
    对两个等长或右侧更长的字节串执行异或。

    Args:
        left (bytes): 左侧字节串。
        right (bytes): 右侧字节串。

    Returns:
        bytes: 异或结果。

    Raises:
        None: 只处理 zip 可配对长度。
    """
    return bytes(a ^ b for a, b in zip(left, right))


def pkcs7_unpad(data: bytes) -> bytes:
    """
    校验并移除 PKCS7 padding。

    Args:
        data (bytes): 带 padding 的明文字节。

    Returns:
        bytes: 去除 padding 后的明文字节。

    Raises:
        ValueError: padding 不合法时抛出。
    """
    if not data:
        raise ValueError("missing PKCS7 padding")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > SM4_BLOCK_BYTES:
        raise ValueError("invalid PKCS7 padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS7 padding bytes")
    return data[:-pad_len]


def print_gpu_info(device: str) -> None:
    """
    打印 GPU 设备信息。

    Args:
        device (str): Torch CUDA 设备。

    Returns:
        None: 信息直接打印到标准输出。

    Raises:
        RuntimeError: PyTorch 未安装或 CUDA 不可用时抛出。
    """
    torch = require_torch()
    torch_device = torch.device(device)
    if torch_device.type != "cuda":
        raise RuntimeError("GPU backend requires cuda device")
    if not torch.cuda.is_available():
        torch_version = getattr(torch, "__version__", "unknown")
        torch_cuda = getattr(torch.version, "cuda", "unknown")
        raise RuntimeError(f"CUDA is not available (torch={torch_version}, torch_cuda={torch_cuda})")
    print(f"GPU设备：{torch.cuda.get_device_name(torch_device)}")


def require_torch():
    """
    延迟导入 PyTorch。

    Args:
        None: 无入参。

    Returns:
        module: PyTorch 模块对象。

    Raises:
        RuntimeError: PyTorch 未安装时抛出。
    """
    try:
        import torch
    except ImportError as exc:
        raise RuntimeError("PyTorch is required for GPU backend") from exc
    return torch


def is_readable_utf8(data: bytes) -> bool:
    """
    判断明文是否像可读 UTF-8 文本。

    Args:
        data (bytes): 待判断的明文字节。

    Returns:
        bool: 能解码且可打印字符占比较高时返回 True。

    Raises:
        None: UTF-8 解码异常会被捕获。
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text:
        return False
    printable_count = sum(1 for char in text if char.isprintable() or char in "\r\n\t")
    return printable_count / len(text) >= 0.85


def print_failure(backend: str, candidate_name: str, iv: IvCandidate, error: Exception) -> None:
    """
    打印一次失败的解密尝试。

    Args:
        backend (str): 解密后端。
        candidate_name (str): 密文候选名称。
        iv (IvCandidate): 当前 IV 候选。
        error (Exception): 捕获到的异常。

    Returns:
        None: 失败信息直接打印到标准输出。

    Raises:
        None: 仅执行格式化输出。
    """
    print(f"失败：后端={backend}，模式=SM4-CBC，密文={candidate_name}，IV={iv.name}，原因={type(error).__name__}: {error}")


def print_readable_success(backend: str, candidate_name: str, iv: IvCandidate, plaintext: bytes) -> None:
    """
    打印一次可读明文结果。

    Args:
        backend (str): 解密后端。
        candidate_name (str): 成功解密的密文候选名称。
        iv (IvCandidate): 成功使用的 IV 候选。
        plaintext (bytes): 解密得到的明文字节。

    Returns:
        None: 结果直接打印到标准输出。

    Raises:
        None: 调用前已经通过 is_readable_utf8 判断。
    """
    print("")
    print("可读明文：发现")
    print(f"后端：{backend.upper()}")
    print("解密模式：SM4-CBC")
    print(f"密文候选：{candidate_name}")
    print(f"IV来源：{iv.name}")
    print(f"IV(hex)：{iv.data.hex()}")
    print(f"明文长度(bytes)：{len(plaintext)}")
    print(f"明文内容预览：{plaintext.decode('utf-8')[:1000]}")


def print_unreadable_success(backend: str, candidate_name: str, iv: IvCandidate, plaintext: bytes) -> None:
    """
    打印一次算法成功但不可读的结果。

    Args:
        backend (str): 解密后端。
        candidate_name (str): 成功执行算法的密文候选名称。
        iv (IvCandidate): 当前 IV 候选。
        plaintext (bytes): 解密得到的明文字节。

    Returns:
        None: 结果直接打印到标准输出。

    Raises:
        None: 仅执行格式化输出。
    """
    print(f"不可读结果：后端={backend}，模式=SM4-CBC，密文={candidate_name}，IV={iv.name}，hex预览={plaintext[:64].hex()}")


if __name__ == "__main__":
    raise SystemExit(main())
