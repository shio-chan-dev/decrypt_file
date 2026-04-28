# decrypt-file

SM4 文件/字符串解密可行性验证项目。

当前代码先完成 CPU 基线验证，用于确认：

1. SM4-CBC/PKCS7 字符串和文件加解密可以正确往返。
2. SM4-CTR 字符串加解密可以正确往返。
3. 文件解密后可以通过 sha256 与原文件核对。
4. 可以记录 CPU 解密耗时和吞吐量，后续用于 CPU/GPU 对比。

## 项目结构

```text
decrypt_file/
  sm4.py                  # SM4 加解密、文件流处理、sha256 校验
tests/
  test_sm4.py             # 标准库 unittest 自动测试
sm4_cpu_validation.py     # 生成本地样例并执行 CPU 基线验证
main.py                   # 项目入口提示
```

## 运行验证

```bash
python3 sm4_cpu_validation.py
```

也可以指定模式和测试文件大小：

```bash
python3 sm4_cpu_validation.py --mode CBC --size-mb 10
python3 sm4_cpu_validation.py --mode CTR --size-mb 10
```

验证输出文件会生成到 `validation_output/`，该目录已加入 `.gitignore`。

## 运行测试

```bash
python3 -m unittest discover -s tests
```

## 后续 GPU 对比

当前脚本只作为 CPU 基线。后续接入真实 GPU SM4 实现后，应复用同一批 key、IV、模式和测试文件，对比 CPU/GPU 的解密耗时、吞吐量和资源占用。
