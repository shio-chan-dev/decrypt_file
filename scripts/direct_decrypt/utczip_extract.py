"""UTES/UESF 业务包观察性解包脚本。

该脚本根据当前真实样例中观察到的 UTES/UESF 分段结构，导出业务包内的
文件段，例如 `.utctmp` 和 `.json`。它不是公司正式解包工具，不负责验签、
打开数字信封或 SM4 解密；正式流程仍应优先使用业务系统里的
`LargeFileUtil.extractAllFiles` 或等价工具。
"""

from __future__ import annotations

import argparse
import shutil
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"UTES"
ENTRY_PREFIX = b"UESF_"
ENTRY_MARKERS = {b"UESF_A", b"UESF_B"}
MAX_NAME_BYTES = 4096
SCAN_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class UtczipEntry:
    """UTczip 文件中的一个可导出分段。"""

    marker: str
    raw_name: str
    output_name: str
    data_offset: int
    data_size: int


def main() -> int:
    """
    解析命令行参数并执行 UTES/UESF 解包。

    Args:
        None: 参数通过命令行传入。

    Returns:
        int: 进程退出码，0 表示执行成功。

    Raises:
        ValueError: 输入文件不是当前脚本支持的 UTES/UESF 格式时抛出。
        FileExistsError: 输出文件已存在且未指定 --overwrite 时抛出。
        OSError: 文件读写失败时由底层文件操作抛出。
    """
    parser = argparse.ArgumentParser(description="Extract observed UTES/UESF business package entries.")
    parser.add_argument("input_file", help="待解包的 .utczip 文件")
    parser.add_argument("--output-dir", default="test_files/extracted", help="导出目录，默认 test_files/extracted")
    parser.add_argument("--list-only", action="store_true", help="只列出分段，不写出文件")
    parser.add_argument("--overwrite", action="store_true", help="允许覆盖已存在的输出文件")
    args = parser.parse_args()

    input_path = Path(args.input_file)
    output_dir = Path(args.output_dir)
    entries = parse_utczip_entries(input_path)

    print("UTES/UESF解包：开始")
    print(f"输入文件：{input_path}")
    print(f"输出目录：{output_dir}")
    print(f"分段数量：{len(entries)}")

    for entry in entries:
        print("")
        print(f"分段标记：{entry.marker}")
        print(f"原始名称：{entry.raw_name}")
        print(f"输出名称：{entry.output_name}")
        print(f"数据偏移：{entry.data_offset}")
        print(f"数据大小(bytes)：{entry.data_size}")

    if args.list_only:
        print("")
        print("解包模式：仅列出，不写出文件")
        print("UTES/UESF解包：结束")
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)
    for entry in entries:
        target_path = output_dir / entry.output_name
        extract_entry(input_path, target_path, entry, args.overwrite)
        print(f"导出文件：{target_path}")

    print("")
    print("UTES/UESF解包：结束")
    return 0


def parse_utczip_entries(path: Path) -> list[UtczipEntry]:
    """
    解析 UTES/UESF 文件中的可导出分段。

    Args:
        path (Path): 待解析的 .utczip 文件路径。

    Returns:
        list[UtczipEntry]: 可导出的分段列表。

    Raises:
        ValueError: 文件头或分段格式不符合当前观察到的 UTES/UESF 结构时抛出。
        OSError: 文件读取失败时由底层文件操作抛出。
    """
    file_size = path.stat().st_size
    entries: list[UtczipEntry] = []

    with path.open("rb") as source:
        if source.read(len(MAGIC)) != MAGIC:
            raise ValueError("input file is not an observed UTES package")

        offset = find_next_marker(source, 0, file_size)
        while offset is not None:
            entry = read_entry(source, offset, file_size)
            if entry is None:
                break
            entries.append(entry)

            # 分段数据结束后继续寻找下一个 UESF 标记。样例文件尾部还有索引信息，
            # 如果读到不像真实文件分段的标记，read_entry 会返回 None 并停止。
            offset = find_next_marker(source, entry.data_offset + entry.data_size, file_size)

    if not entries:
        raise ValueError("no extractable UESF entries found")
    return entries


def read_entry(source, offset: int, file_size: int) -> UtczipEntry | None:
    """
    从指定偏移读取一个 UESF 分段。

    Args:
        source: 已打开的二进制文件对象。
        offset (int): 分段标记起始偏移。
        file_size (int): 输入文件总字节数。

    Returns:
        UtczipEntry | None: 真实文件分段返回条目；遇到尾部索引或非法分段时返回 None。

    Raises:
        OSError: 文件读取失败时由底层文件操作抛出。
    """
    source.seek(offset)
    marker = source.read(6)
    separator = source.read(1)
    if marker not in ENTRY_MARKERS or separator != b"\x00":
        return None

    size_bytes = source.read(8)
    if len(size_bytes) != 8:
        return None
    data_size = int.from_bytes(size_bytes, "little")

    name_bytes = read_null_terminated_name(source)
    if name_bytes is None:
        return None

    data_offset = source.tell()
    if data_size <= 0 or data_offset + data_size > file_size:
        return None

    raw_name = name_bytes.decode("utf-8", errors="replace")
    output_name = normalize_output_name(raw_name, marker.decode("ascii"))
    return UtczipEntry(
        marker=marker.decode("ascii"),
        raw_name=raw_name,
        output_name=output_name,
        data_offset=data_offset,
        data_size=data_size,
    )


def read_null_terminated_name(source) -> bytes | None:
    """
    读取以 NUL 结束的分段名称。

    Args:
        source: 已打开的二进制文件对象。

    Returns:
        bytes | None: 读取成功返回名称字节；名称过长或遇到 EOF 时返回 None。

    Raises:
        OSError: 文件读取失败时由底层文件操作抛出。
    """
    name = bytearray()
    while len(name) <= MAX_NAME_BYTES:
        byte = source.read(1)
        if not byte:
            return None
        if byte == b"\x00":
            return bytes(name)
        name.extend(byte)
    return None


def normalize_output_name(raw_name: str, fallback: str) -> str:
    """
    将分段内的原始文件名转换为安全的本地输出名。

    Args:
        raw_name (str): 分段记录中的原始名称。
        fallback (str): 原始名称为空时使用的后备名称。

    Returns:
        str: 输出文件名，不包含目录分隔符。

    Raises:
        None: 仅执行字符串处理。
    """
    name = raw_name.replace("\\", "/").split("/")[-1].lstrip(".")
    return name or f"{fallback}.bin"


def find_next_marker(source, start: int, file_size: int) -> int | None:
    """
    从指定偏移开始查找下一个 UESF 标记。

    Args:
        source: 已打开的二进制文件对象。
        start (int): 查找起始偏移。
        file_size (int): 输入文件总字节数。

    Returns:
        int | None: 找到时返回标记偏移，否则返回 None。

    Raises:
        OSError: 文件读取失败时由底层文件操作抛出。
    """
    source.seek(start)
    position = start
    overlap = b""
    while position < file_size:
        chunk = source.read(min(SCAN_CHUNK_SIZE, file_size - position))
        if not chunk:
            return None

        data = overlap + chunk
        index = data.find(ENTRY_PREFIX)
        if index >= 0:
            return position - len(overlap) + index

        overlap = data[-(len(ENTRY_PREFIX) - 1) :]
        position += len(chunk)
    return None


def extract_entry(input_path: Path, target_path: Path, entry: UtczipEntry, overwrite: bool) -> None:
    """
    将指定分段写出为本地文件。

    Args:
        input_path (Path): 输入 .utczip 文件路径。
        target_path (Path): 输出文件路径。
        entry (UtczipEntry): 待导出的分段信息。
        overwrite (bool): 是否允许覆盖已有文件。

    Returns:
        None: 函数直接写入 target_path。

    Raises:
        FileExistsError: 输出文件已存在且 overwrite 为 False 时抛出。
        OSError: 文件读写失败时由底层文件操作抛出。
    """
    if target_path.exists() and not overwrite:
        raise FileExistsError(f"output file already exists: {target_path}")

    with input_path.open("rb") as source, target_path.open("wb") as target:
        source.seek(entry.data_offset)
        copy_exact_bytes(source, target, entry.data_size)


def copy_exact_bytes(source, target, total_size: int) -> None:
    """
    从 source 精确复制指定字节数到 target。

    Args:
        source: 输入二进制文件对象。
        target: 输出二进制文件对象。
        total_size (int): 需要复制的总字节数。

    Returns:
        None: 函数直接写入 target。

    Raises:
        EOFError: 输入文件提前结束时抛出。
        OSError: 文件读写失败时由底层文件操作抛出。
    """
    remaining = total_size
    while remaining:
        chunk = source.read(min(SCAN_CHUNK_SIZE, remaining))
        if not chunk:
            raise EOFError("input file ended before entry data was fully copied")
        target.write(chunk)
        remaining -= len(chunk)


if __name__ == "__main__":
    raise SystemExit(main())
