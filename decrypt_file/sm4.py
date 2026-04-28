"""SM4 CPU 加解密工具模块。

本模块基于 cryptography 提供 SM4-CBC/CTR 的字节加解密、文件流加解密
和 sha256 文件校验能力，用于建立 CPU 基线以及后续 CPU/GPU 对比验证。
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SM4_BLOCK_BYTES = 16
SM4_BLOCK_BITS = SM4_BLOCK_BYTES * 8
DEFAULT_CHUNK_SIZE = 1024 * 1024

ModeName = Literal["CBC", "CTR"]
PaddingName = Literal["pkcs7", "none"]


def encrypt_bytes(
    plaintext: bytes,
    key: bytes,
    iv: bytes,
    *,
    mode: ModeName = "CBC",
    padding: PaddingName = "pkcs7",
) -> bytes:
    """
    加密字节数据。

    Args:
        plaintext (bytes): 待加密的明文字节。
        key (bytes): SM4 密钥，长度必须为 16 字节。
        iv (bytes): SM4 IV/计数器初始值，长度必须为 16 字节。
        mode (ModeName): 加密模式，支持 CBC 或 CTR。
        padding (PaddingName): CBC 模式下的填充方式，默认 pkcs7。

    Returns:
        bytes: 加密后的密文字节。

    Raises:
        ValueError: key、iv、mode 或 padding 参数不合法时抛出。
    """
    cipher = _build_cipher(key, iv, mode)
    encryptor = cipher.encryptor()
    # CBC 模式需要先按块大小补齐，CTR 模式不需要填充。
    data = _pad(plaintext, mode, padding)
    return encryptor.update(data) + encryptor.finalize()


def decrypt_bytes(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
    *,
    mode: ModeName = "CBC",
    padding: PaddingName = "pkcs7",
) -> bytes:
    """
    解密字节数据。

    Args:
        ciphertext (bytes): 待解密的密文字节。
        key (bytes): SM4 密钥，长度必须为 16 字节。
        iv (bytes): SM4 IV/计数器初始值，长度必须为 16 字节。
        mode (ModeName): 解密模式，支持 CBC 或 CTR。
        padding (PaddingName): CBC 模式下的去填充方式，默认 pkcs7。

    Returns:
        bytes: 解密后的明文字节。

    Raises:
        ValueError: key、iv、mode、padding 或密文填充不合法时抛出。
    """
    cipher = _build_cipher(key, iv, mode)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    # CBC 模式最后需要去掉 PKCS7 填充，CTR 模式保持原始长度。
    return _unpad(plaintext, mode, padding)


def encrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
    iv: bytes,
    *,
    mode: ModeName = "CBC",
    padding: PaddingName = "pkcs7",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """
    流式加密文件。

    Args:
        input_path (str | Path): 明文输入文件路径。
        output_path (str | Path): 密文输出文件路径。
        key (bytes): SM4 密钥，长度必须为 16 字节。
        iv (bytes): SM4 IV/计数器初始值，长度必须为 16 字节。
        mode (ModeName): 加密模式，支持 CBC 或 CTR。
        padding (PaddingName): CBC 模式下的填充方式，默认 pkcs7。
        chunk_size (int): 每次读取文件的字节数。

    Returns:
        None: 函数直接写入 output_path。

    Raises:
        OSError: 文件读写失败时由底层文件操作抛出。
        ValueError: key、iv、mode 或 padding 参数不合法时抛出。
    """
    cipher = _build_cipher(key, iv, mode)
    encryptor = cipher.encryptor()
    padder = _new_padder(mode, padding)

    with Path(input_path).open("rb") as source, Path(output_path).open("wb") as target:
        while chunk := source.read(chunk_size):
            # padder.update 会缓存不足一个块的数据，保证 CBC 输入按 16 字节对齐。
            data = padder.update(chunk) if padder else chunk
            if data:
                target.write(encryptor.update(data))

        # 文件结束时再写入 padding final 数据，避免提前写出不完整块。
        final_data = padder.finalize() if padder else b""
        target.write(encryptor.update(final_data) + encryptor.finalize())


def decrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
    iv: bytes,
    *,
    mode: ModeName = "CBC",
    padding: PaddingName = "pkcs7",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """
    流式解密文件。

    Args:
        input_path (str | Path): 密文输入文件路径。
        output_path (str | Path): 明文输出文件路径。
        key (bytes): SM4 密钥，长度必须为 16 字节。
        iv (bytes): SM4 IV/计数器初始值，长度必须为 16 字节。
        mode (ModeName): 解密模式，支持 CBC 或 CTR。
        padding (PaddingName): CBC 模式下的去填充方式，默认 pkcs7。
        chunk_size (int): 每次读取文件的字节数。

    Returns:
        None: 函数直接写入 output_path。

    Raises:
        OSError: 文件读写失败时由底层文件操作抛出。
        ValueError: key、iv、mode、padding 或密文填充不合法时抛出。
    """
    cipher = _build_cipher(key, iv, mode)
    decryptor = cipher.decryptor()
    unpadder = _new_unpadder(mode, padding)

    with Path(input_path).open("rb") as source, Path(output_path).open("wb") as target:
        while chunk := source.read(chunk_size):
            data = decryptor.update(chunk)
            # unpadder 会保留最后一个块，直到 finalize 时确认 padding。
            if unpadder:
                data = unpadder.update(data)
            if data:
                target.write(data)

        final_data = decryptor.finalize()
        if unpadder:
            final_data = unpadder.update(final_data) + unpadder.finalize()
        target.write(final_data)


def sha256_file(path: str | Path, *, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """
    计算文件 sha256 摘要。

    Args:
        path (str | Path): 待计算摘要的文件路径。
        chunk_size (int): 每次读取文件的字节数。

    Returns:
        str: 文件内容的 sha256 十六进制摘要。

    Raises:
        OSError: 文件读取失败时由底层文件操作抛出。
    """
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _build_cipher(key: bytes, iv: bytes, mode: ModeName) -> Cipher:
    """
    构建 cryptography SM4 Cipher 对象。

    Args:
        key (bytes): SM4 密钥，长度必须为 16 字节。
        iv (bytes): SM4 IV/计数器初始值，长度必须为 16 字节。
        mode (ModeName): 加解密模式，支持 CBC 或 CTR。

    Returns:
        Cipher: 已配置 SM4 算法和模式的 Cipher 对象。

    Raises:
        ValueError: key、iv 或 mode 不合法时抛出。
    """
    # SM4 块大小固定为 16 字节，密钥和 IV 都按该长度校验。
    if len(key) != SM4_BLOCK_BYTES:
        raise ValueError("SM4 key must be 16 bytes")
    if len(iv) != SM4_BLOCK_BYTES:
        raise ValueError("SM4 IV must be 16 bytes")

    normalized_mode = mode.upper()
    if normalized_mode == "CBC":
        cipher_mode = modes.CBC(iv)
    elif normalized_mode == "CTR":
        cipher_mode = modes.CTR(iv)
    else:
        raise ValueError("mode must be CBC or CTR")

    return Cipher(algorithms.SM4(key), cipher_mode)


def _pad(data: bytes, mode: ModeName, padding: PaddingName) -> bytes:
    """
    根据模式对明文执行填充。

    Args:
        data (bytes): 待填充的明文字节。
        mode (ModeName): 加密模式。
        padding (PaddingName): 填充方式。

    Returns:
        bytes: 填充后的明文字节；CTR 或 none 时返回原始数据。

    Raises:
        ValueError: padding 参数不支持时抛出。
    """
    padder = _new_padder(mode, padding)
    if not padder:
        return data
    return padder.update(data) + padder.finalize()


def _unpad(data: bytes, mode: ModeName, padding: PaddingName) -> bytes:
    """
    根据模式对明文执行去填充。

    Args:
        data (bytes): 解密得到的明文字节。
        mode (ModeName): 解密模式。
        padding (PaddingName): 去填充方式。

    Returns:
        bytes: 去填充后的明文字节；CTR 或 none 时返回原始数据。

    Raises:
        ValueError: padding 参数不支持或填充内容不合法时抛出。
    """
    unpadder = _new_unpadder(mode, padding)
    if not unpadder:
        return data
    return unpadder.update(data) + unpadder.finalize()


def _new_padder(mode: ModeName, padding: PaddingName):
    """
    创建 CBC 模式使用的 PKCS7 padder。

    Args:
        mode (ModeName): 加密模式。
        padding (PaddingName): 填充方式。

    Returns:
        object | None: PKCS7 padder；CTR 或 none 时返回 None。

    Raises:
        ValueError: padding 参数不支持时抛出。
    """
    if mode.upper() == "CBC" and padding == "pkcs7":
        return sym_padding.PKCS7(SM4_BLOCK_BITS).padder()
    if padding == "none" or mode.upper() == "CTR":
        return None
    raise ValueError("CBC mode supports pkcs7 or none padding")


def _new_unpadder(mode: ModeName, padding: PaddingName):
    """
    创建 CBC 模式使用的 PKCS7 unpadder。

    Args:
        mode (ModeName): 解密模式。
        padding (PaddingName): 去填充方式。

    Returns:
        object | None: PKCS7 unpadder；CTR 或 none 时返回 None。

    Raises:
        ValueError: padding 参数不支持时抛出。
    """
    if mode.upper() == "CBC" and padding == "pkcs7":
        return sym_padding.PKCS7(SM4_BLOCK_BITS).unpadder()
    if padding == "none" or mode.upper() == "CTR":
        return None
    raise ValueError("CBC mode supports pkcs7 or none padding")
