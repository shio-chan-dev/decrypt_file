"""SM4 GPU 直接解密外部密文样例脚本。

该脚本用于把领导或业务系统提供的真实密文、SM4 密钥和 IV 放到 CUDA
路径上尝试解密。脚本只调用 Torch/CUDA 版 SM4 解密实现，不使用 CPU
版 `cryptography` 解密函数。
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from pathlib import Path

from decrypt_file.sm4_torch import cuda_device_name, decrypt_bytes_torch, synchronize_device


@dataclass(frozen=True)
class CipherCandidate:
    """一次可尝试的密文字节候选。"""

    name: str
    data: bytes


@dataclass(frozen=True)
class IvCandidate:
    """一次可尝试的 IV/计数器初始值候选。"""

    name: str
    data: bytes


def main() -> int:
    """
    解析命令行参数并在 GPU 上尝试解密外部密文。

    Args:
        None: 参数通过命令行传入。

    Returns:
        int: 进程退出码，0 表示至少完成尝试，2 表示 GPU 环境不可用。

    Raises:
        ValueError: key、IV、模式或设备参数不合法时抛出。
        OSError: 写入输出文件失败时由底层文件操作抛出。
    """
    parser = argparse.ArgumentParser(description="Decrypt provided SM4 ciphertext with Torch/CUDA only.")
    parser.add_argument("--ciphertext", required=True, help="外部提供的完整密文字符串")
    parser.add_argument("--key-hex", required=True, help="16 字节 SM4 密钥，hex 格式")
    parser.add_argument("--iv-hex", required=True, help="16 字节 SM4 IV/初始向量，hex 格式")
    parser.add_argument("--mode", choices=["AUTO", "CBC", "CTR"], default="AUTO", help="SM4 模式，默认尝试 CBC 和 CTR")
    parser.add_argument("--device", default="cuda", help="Torch CUDA 设备，例如 cuda、cuda:0、cuda:2")
    parser.add_argument("--output-file", help="如果出现 UTF-8 可读结果，将最后一个可读结果写入文件")
    args = parser.parse_args()

    if not args.device.startswith("cuda"):
        raise ValueError("该脚本只用于 GPU 验证，请使用 cuda 或 cuda:N 设备")

    key = bytes.fromhex(args.key_hex)
    iv = bytes.fromhex(args.iv_hex)
    if len(key) != 16:
        raise ValueError("SM4 密钥必须是 16 字节，也就是 32 位 hex 字符")
    if len(iv) != 16:
        raise ValueError("SM4 IV 必须是 16 字节，也就是 32 位 hex 字符")

    # 先检查 CUDA，避免误用 CPU 路径完成解密。
    try:
        gpu_name = cuda_device_name(args.device)
    except RuntimeError as exc:
        print("GPU环境检查：失败")
        print(f"失败原因：{exc}")
        print("处理建议：请在 torch.cuda.is_available() 为 True 的环境运行。")
        return 2

    candidates, asn1_ivs = build_cipher_candidates(args.ciphertext)
    ivs = dedupe_ivs([IvCandidate("命令行传入IV", iv), *asn1_ivs])
    modes = ["CBC", "CTR"] if args.mode == "AUTO" else [args.mode]

    print("SM4 GPU直接解密：开始")
    print(f"GPU设备：{gpu_name}")
    print(f"密文候选数量：{len(candidates)}")
    print(f"向量候选数量：{len(ivs)}")
    print(f"测试模式：{','.join(modes)}")

    last_readable: bytes | None = None
    success_count = 0
    for candidate in candidates:
        print("")
        print(f"密文解释方式：{candidate.name}")
        print(f"密文字节长度：{len(candidate.data)}")
        print(f"是否16字节对齐：{'是' if len(candidate.data) % 16 == 0 else '否'}")

        for iv_candidate in ivs:
            for mode in modes:
                plaintext = try_gpu_decrypt(candidate, key, iv_candidate, mode, args.device)
                if plaintext is None:
                    continue

                success_count += 1
                print_success(candidate, iv_candidate, mode, plaintext)
                if is_readable_utf8(plaintext):
                    last_readable = plaintext

    if args.output_file and last_readable is not None:
        output_path = Path(args.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(last_readable)
        print("")
        print(f"可读明文输出文件：{output_path}")

    print("")
    print(f"GPU算法成功次数：{success_count}")
    print("SM4 GPU直接解密：结束")
    return 0


def build_cipher_candidates(ciphertext: str) -> tuple[list[CipherCandidate], list[IvCandidate]]:
    """
    从外部密文字符串构造多个可能的密文字节候选。

    Args:
        ciphertext (str): 外部提供的完整密文字符串。

    Returns:
        tuple[list[CipherCandidate], list[IvCandidate]]: 密文候选和 ASN.1 中发现的 IV 候选。

    Raises:
        None: 无法解析的格式会被跳过。
    """
    raw_candidates: list[CipherCandidate] = []
    iv_candidates: list[IvCandidate] = []

    for name, text in split_ciphertext_parts(ciphertext):
        decoded = decode_base64(text)
        if decoded is not None:
            raw_candidates.append(CipherCandidate(f"{name}base64解码", decoded))
            der_candidates, der_ivs = extract_asn1_candidates(decoded, name)
            raw_candidates.extend(der_candidates)
            iv_candidates.extend(der_ivs)

        decoded_hex = decode_hex(text)
        if decoded_hex is not None:
            raw_candidates.append(CipherCandidate(f"{name}hex解码", decoded_hex))

    # 兜底把原字符串作为 bytes 尝试，便于发现业务系统直接传原始字符的情况。
    raw_candidates.append(CipherCandidate("整体字符串UTF-8字节", ciphertext.encode("utf-8")))
    return dedupe_candidates(raw_candidates), dedupe_ivs(iv_candidates)


def split_ciphertext_parts(ciphertext: str) -> list[tuple[str, str]]:
    """
    按整体和竖线分段返回待解析文本。

    Args:
        ciphertext (str): 外部提供的密文字符串。

    Returns:
        list[tuple[str, str]]: 每段文本及其来源名称。

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
    尝试按 base64 解码字符串。

    Args:
        text (str): 待解码文本。

    Returns:
        bytes | None: 解码成功返回字节，失败返回 None。

    Raises:
        None: base64 异常会被捕获。
    """
    try:
        return base64.b64decode(text, validate=True)
    except Exception:
        return None


def decode_hex(text: str) -> bytes | None:
    """
    尝试按 hex 解码字符串。

    Args:
        text (str): 待解码文本。

    Returns:
        bytes | None: 解码成功返回字节，失败返回 None。

    Raises:
        None: hex 异常会被捕获。
    """
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


def extract_asn1_candidates(data: bytes, source_name: str) -> tuple[list[CipherCandidate], list[IvCandidate]]:
    """
    从 DER/ASN.1 字节中提取可能的密文和 IV。

    Args:
        data (bytes): 已解码出的 DER/ASN.1 字节。
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
        # DER OCTET STRING 且长度为 16 时常见于 IV 参数。
        if tag == 0x04 and len(value) == 16:
            ivs.append(IvCandidate(f"{source_name}ASN.1 OCTET STRING#{index}", value))

        # 原始密文通常位于 primitive context-specific [0]，且 SM4-CBC 需要 16 字节对齐。
        if tag == 0x80 and len(value) >= 16:
            candidates.append(CipherCandidate(f"{source_name}ASN.1 context[0]#{index}", value))

        # 某些封装会把密文放在 OCTET STRING；这里也作为候选，但排除明显的 16 字节 IV。
        if tag == 0x04 and len(value) > 16:
            candidates.append(CipherCandidate(f"{source_name}ASN.1 OCTET STRING#{index}", value))

    return candidates, ivs


def parse_der_nodes(data: bytes) -> list[tuple[int, bytes]]:
    """
    递归解析 DER TLV 节点，返回所有 primitive 节点。

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
        # tag 的 0x20 位表示 constructed，constructed 节点继续向内递归。
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


def try_gpu_decrypt(candidate: CipherCandidate, key: bytes, iv: IvCandidate, mode: str, device: str) -> bytes | None:
    """
    使用指定模式和 IV 在 GPU 上尝试解密。

    Args:
        candidate (CipherCandidate): 密文字节候选。
        key (bytes): 16 字节 SM4 密钥。
        iv (IvCandidate): IV/计数器初始值候选。
        mode (str): SM4 模式，CBC 或 CTR。
        device (str): Torch CUDA 设备。

    Returns:
        bytes | None: 解密成功返回明文字节，失败返回 None。

    Raises:
        None: 单个候选失败会转换为中文输出并继续尝试其他候选。
    """
    try:
        # CUDA 调用是异步的，前后同步能让异常更靠近当前候选。
        synchronize_device(device)
        padding = "pkcs7" if mode == "CBC" else "none"
        plaintext = decrypt_bytes_torch(candidate.data, key, iv.data, mode=mode, padding=padding, device=device)
        synchronize_device(device)
        return plaintext
    except Exception as exc:
        print(f"解密模式：SM4-{mode}，IV来源：{iv.name}，状态：失败，原因：{type(exc).__name__}: {exc}")
        return None


def print_success(candidate: CipherCandidate, iv: IvCandidate, mode: str, plaintext: bytes) -> None:
    """
    打印一次 GPU 解密成功结果。

    Args:
        candidate (CipherCandidate): 成功解密的密文候选。
        iv (IvCandidate): 成功使用的 IV 候选。
        mode (str): 成功使用的 SM4 模式。
        plaintext (bytes): 解密得到的明文字节。

    Returns:
        None: 结果直接打印到标准输出。

    Raises:
        None: UTF-8 解码异常会被捕获。
    """
    print(f"解密模式：SM4-{mode}")
    print("解密状态：GPU算法执行成功")
    print(f"成功密文候选：{candidate.name}")
    print(f"成功IV来源：{iv.name}")
    print(f"成功IV(hex)：{iv.data.hex()}")
    print(f"明文长度(bytes)：{len(plaintext)}")
    print(f"明文hex预览：{plaintext[:256].hex()}")

    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        print("明文UTF-8：无法解码，可能不是文本或当前候选不是最终业务明文")
        return

    print("明文UTF-8：可解码")
    print(f"明文内容预览：{text[:1000]}")


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


if __name__ == "__main__":
    raise SystemExit(main())
