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
    cipher = _build_cipher(key, iv, mode)
    encryptor = cipher.encryptor()
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
    cipher = _build_cipher(key, iv, mode)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
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
    cipher = _build_cipher(key, iv, mode)
    encryptor = cipher.encryptor()
    padder = _new_padder(mode, padding)

    with Path(input_path).open("rb") as source, Path(output_path).open("wb") as target:
        while chunk := source.read(chunk_size):
            data = padder.update(chunk) if padder else chunk
            if data:
                target.write(encryptor.update(data))

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
    cipher = _build_cipher(key, iv, mode)
    decryptor = cipher.decryptor()
    unpadder = _new_unpadder(mode, padding)

    with Path(input_path).open("rb") as source, Path(output_path).open("wb") as target:
        while chunk := source.read(chunk_size):
            data = decryptor.update(chunk)
            if unpadder:
                data = unpadder.update(data)
            if data:
                target.write(data)

        final_data = decryptor.finalize()
        if unpadder:
            final_data = unpadder.update(final_data) + unpadder.finalize()
        target.write(final_data)


def sha256_file(path: str | Path, *, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _build_cipher(key: bytes, iv: bytes, mode: ModeName) -> Cipher:
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
    padder = _new_padder(mode, padding)
    if not padder:
        return data
    return padder.update(data) + padder.finalize()


def _unpad(data: bytes, mode: ModeName, padding: PaddingName) -> bytes:
    unpadder = _new_unpadder(mode, padding)
    if not unpadder:
        return data
    return unpadder.update(data) + unpadder.finalize()


def _new_padder(mode: ModeName, padding: PaddingName):
    if mode.upper() == "CBC" and padding == "pkcs7":
        return sym_padding.PKCS7(SM4_BLOCK_BITS).padder()
    if padding == "none" or mode.upper() == "CTR":
        return None
    raise ValueError("CBC mode supports pkcs7 or none padding")


def _new_unpadder(mode: ModeName, padding: PaddingName):
    if mode.upper() == "CBC" and padding == "pkcs7":
        return sym_padding.PKCS7(SM4_BLOCK_BITS).unpadder()
    if padding == "none" or mode.upper() == "CTR":
        return None
    raise ValueError("CBC mode supports pkcs7 or none padding")
