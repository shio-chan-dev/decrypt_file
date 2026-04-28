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
  sm4_torch.py            # Torch/CUDA SM4 解密验证实现
tests/
  test_sm4.py             # 标准库 unittest 自动测试
sm4_cpu_validation.py     # 生成本地样例并执行 CPU 基线验证
sm4_gpu_validation.py     # 在 CUDA 服务器执行 CPU/GPU 对比验证
main.py                   # 项目入口提示
```

## 运行验证

完整测试和报告整理流程见：[SM4 测试与 CPU/GPU 对比教程](docs/SM4测试与对比教程.md)。

```bash
python3 sm4_cpu_validation.py
```

也可以指定模式和测试文件大小：

```bash
python3 sm4_cpu_validation.py --mode CBC --size-mb 10
python3 sm4_cpu_validation.py --mode CTR --size-mb 10
```

验证输出文件会生成到 `validation_output/`，该目录已加入 `.gitignore`。

## 运行 GPU 对比验证

GPU 对比脚本需要在已安装 PyTorch 且 CUDA 可用的服务器上运行。本机无 CUDA 时不要用该脚本采集性能数据。

运行前建议先确认 GPU 环境：

```bash
python3 -c "import torch; print(torch.cuda.is_available()); print(torch.cuda.get_device_name(0))"
```

```bash
python3 sm4_gpu_validation.py --mode CBC --size-mb 100 --chunk-mb 16
python3 sm4_gpu_validation.py --mode CTR --size-mb 100 --chunk-mb 16
```

脚本会生成同一份测试密文，分别用 CPU 和 GPU 解密，并输出中文字段：

1. CPU/GPU 解密耗时。
2. CPU/GPU 解密吞吐量。
3. GPU 相对 CPU 加速比。
4. 原始文件、CPU 解密文件、GPU 解密文件的 sha256。

## 运行测试

```bash
python3 -m unittest discover -s tests
```

## 后续 GPU 对比

当前 GPU 脚本是验证版实现，用来确认 CUDA 路径是否可运行并采集 CPU/GPU 对比数据。后续如需生产级性能，需要结合实际数据规模继续优化分块、数据传输和 CUDA 实现方式。
