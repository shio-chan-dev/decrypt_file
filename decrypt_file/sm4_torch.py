from __future__ import annotations

from pathlib import Path

from .sm4 import DEFAULT_CHUNK_SIZE, SM4_BLOCK_BYTES

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


def decrypt_file_torch(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
    iv: bytes,
    *,
    mode: str = "CBC",
    padding: str = "pkcs7",
    chunk_size: int = DEFAULT_CHUNK_SIZE * 16,
    device: str = "cuda",
) -> None:
    torch = _require_torch()
    torch_device = torch.device(device)
    if torch_device.type == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("CUDA is not available; cannot run GPU SM4 validation")

    normalized_mode = mode.upper()
    if normalized_mode == "CBC":
        _decrypt_cbc_file(input_path, output_path, key, iv, padding, chunk_size, torch_device, torch)
    elif normalized_mode == "CTR":
        _crypt_ctr_file(input_path, output_path, key, iv, chunk_size, torch_device, torch)
    else:
        raise ValueError("mode must be CBC or CTR")


def decrypt_bytes_torch(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
    *,
    mode: str = "CBC",
    padding: str = "pkcs7",
    device: str = "cuda",
) -> bytes:
    torch = _require_torch()
    torch_device = torch.device(device)
    if torch_device.type == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("CUDA is not available; cannot run GPU SM4 validation")

    normalized_mode = mode.upper()
    if normalized_mode == "CBC":
        plain = _decrypt_cbc_chunk(ciphertext, key, iv, torch_device, torch)[0]
        return _pkcs7_unpad(plain) if padding == "pkcs7" else plain
    if normalized_mode == "CTR":
        return _crypt_ctr_chunk(ciphertext, key, iv, 0, torch_device, torch)
    raise ValueError("mode must be CBC or CTR")


def synchronize_device(device: str = "cuda") -> None:
    torch = _require_torch()
    torch_device = torch.device(device)
    if torch_device.type == "cuda":
        torch.cuda.synchronize(torch_device)


def cuda_device_name(device: str = "cuda") -> str:
    torch = _require_torch()
    torch_device = torch.device(device)
    if torch_device.type != "cuda":
        return str(torch_device)
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is not available")
    return torch.cuda.get_device_name(torch_device)


def _decrypt_cbc_file(input_path, output_path, key, iv, padding, chunk_size, device, torch) -> None:
    if len(key) != SM4_BLOCK_BYTES or len(iv) != SM4_BLOCK_BYTES:
        raise ValueError("SM4 key and IV must both be 16 bytes")
    if chunk_size % SM4_BLOCK_BYTES:
        raise ValueError("chunk_size must be a multiple of 16 bytes")

    previous_block = iv
    pending_plain = b""

    with Path(input_path).open("rb") as source, Path(output_path).open("wb") as target:
        while chunk := source.read(chunk_size):
            if len(chunk) % SM4_BLOCK_BYTES:
                raise ValueError("CBC ciphertext length must be a multiple of 16 bytes")

            plain_chunk, previous_block = _decrypt_cbc_chunk(chunk, key, previous_block, device, torch)
            if pending_plain:
                target.write(pending_plain)
            target.write(plain_chunk[:-SM4_BLOCK_BYTES])
            pending_plain = plain_chunk[-SM4_BLOCK_BYTES:]

        if not pending_plain:
            raise ValueError("CBC ciphertext is empty")
        target.write(_pkcs7_unpad(pending_plain) if padding == "pkcs7" else pending_plain)


def _crypt_ctr_file(input_path, output_path, key, iv, chunk_size, device, torch) -> None:
    if len(key) != SM4_BLOCK_BYTES or len(iv) != SM4_BLOCK_BYTES:
        raise ValueError("SM4 key and IV must both be 16 bytes")
    if chunk_size % SM4_BLOCK_BYTES:
        raise ValueError("chunk_size must be a multiple of 16 bytes")

    block_index = 0
    with Path(input_path).open("rb") as source, Path(output_path).open("wb") as target:
        while chunk := source.read(chunk_size):
            target.write(_crypt_ctr_chunk(chunk, key, iv, block_index, device, torch))
            block_index += (len(chunk) + SM4_BLOCK_BYTES - 1) // SM4_BLOCK_BYTES


def _decrypt_cbc_chunk(chunk: bytes, key: bytes, previous_block: bytes, device, torch) -> tuple[bytes, bytes]:
    cipher_blocks = _bytes_to_block_tensor(chunk, device, torch)
    decrypted_blocks = _crypt_blocks(cipher_blocks, _round_keys(key)[::-1], device, torch)

    previous = torch.empty_like(cipher_blocks)
    previous[0] = _bytes_to_block_tensor(previous_block, device, torch)[0]
    if cipher_blocks.shape[0] > 1:
        previous[1:] = cipher_blocks[:-1]

    plain_blocks = torch.bitwise_xor(decrypted_blocks, previous)
    return _block_tensor_to_bytes(plain_blocks), chunk[-SM4_BLOCK_BYTES:]


def _crypt_ctr_chunk(chunk: bytes, key: bytes, iv: bytes, block_index: int, device, torch) -> bytes:
    block_count = (len(chunk) + SM4_BLOCK_BYTES - 1) // SM4_BLOCK_BYTES
    counter_bytes = _counter_blocks(iv, block_index, block_count)
    counter_blocks = _bytes_to_block_tensor(counter_bytes, device, torch)
    key_stream = _crypt_blocks(counter_blocks, _round_keys(key), device, torch)
    data = _bytes_to_tensor(chunk, device, torch)
    stream = key_stream.reshape(-1)[: len(chunk)]
    return bytes(torch.bitwise_xor(data, stream).cpu().tolist())


def _crypt_blocks(blocks, round_keys: list[int], device, torch):
    sbox = torch.tensor(SBOX, dtype=torch.int64, device=device)
    words = _blocks_to_words(blocks, torch)
    x0, x1, x2, x3 = words[:, 0], words[:, 1], words[:, 2], words[:, 3]
    keys = torch.tensor(round_keys, dtype=torch.int64, device=device)

    for rk in keys:
        mixed = torch.bitwise_xor(torch.bitwise_xor(torch.bitwise_xor(x1, x2), x3), rk)
        x0, x1, x2, x3 = x1, x2, x3, torch.bitwise_xor(x0, _round_transform(mixed, sbox, torch))

    return _words_to_blocks(torch.stack((x3, x2, x1, x0), dim=1), torch)


def _blocks_to_words(blocks, torch):
    values = blocks.to(torch.int64)
    return (
        (values[:, 0::4] << 24)
        | (values[:, 1::4] << 16)
        | (values[:, 2::4] << 8)
        | values[:, 3::4]
    )


def _words_to_blocks(words, torch):
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


def _round_transform(value, sbox, torch):
    substituted = _substitute(value, sbox, torch)
    return substituted ^ _rotl_tensor(substituted, 2, torch) ^ _rotl_tensor(substituted, 10, torch) ^ _rotl_tensor(substituted, 18, torch) ^ _rotl_tensor(substituted, 24, torch)


def _substitute(value, sbox, torch):
    return (
        (sbox[(value >> 24) & 0xFF] << 24)
        | (sbox[(value >> 16) & 0xFF] << 16)
        | (sbox[(value >> 8) & 0xFF] << 8)
        | sbox[value & 0xFF]
    )


def _rotl_tensor(value, bits: int, torch):
    return ((value << bits) & MASK32) | (value >> (32 - bits))


def _bytes_to_block_tensor(data: bytes, device, torch):
    if len(data) % SM4_BLOCK_BYTES:
        raise ValueError("data length must be a multiple of 16 bytes")
    return _bytes_to_tensor(data, device, torch).reshape(-1, SM4_BLOCK_BYTES)


def _bytes_to_tensor(data: bytes, device, torch):
    tensor = torch.frombuffer(bytearray(data), dtype=torch.uint8)
    tensor = tensor.to(device)
    return tensor.clone() if device.type == "cpu" else tensor


def _block_tensor_to_bytes(blocks) -> bytes:
    return bytes(blocks.reshape(-1).cpu().tolist())


def _round_keys(key: bytes) -> list[int]:
    if len(key) != SM4_BLOCK_BYTES:
        raise ValueError("SM4 key must be 16 bytes")

    key_words = [int.from_bytes(key[index : index + 4], "big") for index in range(0, SM4_BLOCK_BYTES, 4)]
    k = [word ^ FK[index] for index, word in enumerate(key_words)]
    keys = []

    for index in range(32):
        mixed = k[index + 1] ^ k[index + 2] ^ k[index + 3] ^ CK[index]
        round_key = (k[index] ^ _key_transform(mixed)) & MASK32
        k.append(round_key)
        keys.append(round_key)

    return keys


def _key_transform(value: int) -> int:
    substituted = _substitute_int(value)
    return substituted ^ _rotl_int(substituted, 13) ^ _rotl_int(substituted, 23)


def _substitute_int(value: int) -> int:
    return (
        (SBOX[(value >> 24) & 0xFF] << 24)
        | (SBOX[(value >> 16) & 0xFF] << 16)
        | (SBOX[(value >> 8) & 0xFF] << 8)
        | SBOX[value & 0xFF]
    )


def _rotl_int(value: int, bits: int) -> int:
    return ((value << bits) & MASK32) | (value >> (32 - bits))


def _counter_blocks(iv: bytes, block_index: int, block_count: int) -> bytes:
    base = int.from_bytes(iv, "big") + block_index
    return b"".join(((base + offset) & ((1 << 128) - 1)).to_bytes(SM4_BLOCK_BYTES, "big") for offset in range(block_count))


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("missing PKCS7 padding")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > SM4_BLOCK_BYTES:
        raise ValueError("invalid PKCS7 padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS7 padding bytes")
    return data[:-pad_len]


def _require_torch():
    try:
        import torch
    except ImportError as exc:
        raise RuntimeError("PyTorch is required for GPU SM4 validation") from exc
    return torch
