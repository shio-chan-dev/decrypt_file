"""项目入口提示脚本。

当前项目的主要用途是运行 SM4 CPU/GPU 验证脚本，main.py 只保留一个
轻量提示，避免用户误以为这里包含完整验证逻辑。
"""


def main():
    """
    打印 CPU 验证脚本运行提示。

    Args:
        None: 无入参。

    Returns:
        None: 函数只向标准输出打印提示。

    Raises:
        None: 该函数不主动抛出异常。
    """
    print("Run `python3 scripts/validation/sm4_cpu_validation.py` to execute the SM4 CPU validation script.")


if __name__ == "__main__":
    main()
