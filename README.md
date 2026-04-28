# decrypt-file

SM4 文件/字符串解密可行性验证项目。

当前代码用于验证 SM4-CBC + PKCS7 解密方案，并采集 CPU/GPU 对比数据：

1. SM4-CBC/PKCS7 字符串和文件加解密可以正确往返。
2. 文件解密后可以通过 sha256 与原文件核对。
3. 可以记录 CPU/GPU 解密耗时、吞吐量和加速比。
4. 可以把真实加密文件放到 CPU 或 GPU 路径上尝试解密。

## 项目结构

```text
decrypt_file/
  sm4.py                  # SM4 加解密、文件流处理、sha256 校验
  sm4_torch.py            # Torch/CUDA SM4 解密验证实现
tests/
  test_sm4.py             # 标准库 unittest 自动测试
scripts/
  validation/
    sm4_cpu_validation.py       # 生成本地样例并执行 CPU 基线验证
    sm4_gpu_validation.py       # 在 CUDA 服务器执行 CPU/GPU 对比验证
  direct_decrypt/
    sm4_direct_decrypt.py       # 使用 CPU 路径解密真实加密文件或排查小字符串
    sm4_gpu_direct_decrypt.py   # 在 CUDA 服务器解密真实加密文件或排查小字符串
sm4_decrypt_standalone.py # 可单独分发的 CPU/GPU 解密脚本
main.py                   # 项目入口提示
```

## 运行验证

完整测试和报告整理流程见：[SM4 测试与 CPU/GPU 对比教程](docs/SM4测试与对比教程.md)。
真实业务样例复跑步骤见：[SM4 真实业务样例解密教程](docs/SM4真实业务样例解密教程.md)。

```bash
python3 scripts/validation/sm4_cpu_validation.py
```

也可以指定测试文件大小：

```bash
python3 scripts/validation/sm4_cpu_validation.py --size-mb 10
```

脚本固定使用 `SM4-CBC + PKCS7 padding`，不需要传入模式参数。

验证输出文件会生成到 `validation_output/`，该目录已加入 `.gitignore`。

## 运行 GPU 对比验证

GPU 对比脚本需要在已安装 PyTorch 且 CUDA 可用的服务器上运行。本机无 CUDA 时不要用该脚本采集性能数据。

运行前建议先确认 GPU 环境：

```bash
python3 -c "import sys, torch; print(sys.executable); print(torch.__version__); print(torch.version.cuda); print(torch.cuda.is_available()); print(torch.cuda.get_device_name(0))"
```

如果脚本提示 `NVIDIA driver on your system is too old`，通常表示当前 Python 环境里的 PyTorch CUDA 轮子版本高于服务器驱动支持的版本。请用同一个 `python3` 重新安装与驱动兼容的 PyTorch CUDA 版本，例如 CUDA 12.6 环境可优先参考 PyTorch 官网选择 `cu126` 安装命令。

如果是多卡服务器，先用 `nvidia-smi` 查看显存占用，再通过 `--device cuda:2` 这类参数指定较空闲的 GPU。

```bash
python3 scripts/validation/sm4_gpu_validation.py --size-mb 100 --chunk-mb 16 --device cuda:2
```

脚本会生成同一份测试密文，分别用 CPU 和 GPU 解密，并输出中文字段：

1. CPU/GPU 解密耗时。
2. CPU/GPU 解密吞吐量。
3. GPU 相对 CPU 加速比。
4. 原始文件、CPU 解密文件、GPU 解密文件的 sha256。

## 运行真实加密文件解密

如果业务系统提供的是数字信封，例如 `miwen`，需要先按业务系统逻辑打开数字信封，得到真正的 `SM4 key` 和 `IV`。拿到 key/IV 后，再对解包出来的真实加密文件，也就是类似 `encFilePath` 的文件，执行 SM4-CBC/PKCS7 解密。

CPU 路径：

```bash
python3 scripts/direct_decrypt/sm4_direct_decrypt.py \
  --input-file '<encFilePath加密文件路径>' \
  --key-hex '<32位hex密钥>' \
  --iv-hex '<32位hex向量>' \
  --output-file validation_output/plain.bin
```

GPU 路径：

```bash
python3 scripts/direct_decrypt/sm4_gpu_direct_decrypt.py \
  --input-file '<encFilePath加密文件路径>' \
  --key-hex '<32位hex密钥>' \
  --iv-hex '<32位hex向量>' \
  --device cuda:2 \
  --output-file validation_output/plain.bin
```

脚本固定按 `SM4-CBC + PKCS7 padding` 解密。`--ciphertext` 参数仍保留用于小字符串排查，但数字信封本身通常不是最终要解密的 SM4 文件密文。

如果只想拷贝一个脚本到服务器，可以使用单文件版本：

```bash
python3 sm4_decrypt_standalone.py \
  --input-file '<encFilePath加密文件路径>' \
  --key-hex '<32位hex密钥>' \
  --iv-hex '<32位hex向量>' \
  --backend gpu \
  --device cuda:2 \
  --output-file validation_output/plain.bin
```

## 运行测试

```bash
python3 -m unittest discover -s tests
```

## 后续 GPU 对比

当前 GPU 脚本是验证版实现，用来确认 CUDA 路径是否可运行并采集 CPU/GPU 对比数据。后续如需生产级性能，需要结合实际数据规模继续优化分块、数据传输和 CUDA 实现方式。
