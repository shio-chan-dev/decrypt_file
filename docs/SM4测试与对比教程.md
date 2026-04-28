# SM4 测试与 CPU/GPU 对比教程

本文说明如何使用当前项目完成 SM4 正确性验证、CPU 基线测试和 GPU 对比测试。

## 一、测试目标

本项目的测试分三类：

1. 自动测试：确认核心 SM4 工具函数没有被改坏。
2. CPU 基线验证：在本机生成样例文件，验证 SM4 解密正确性并记录 CPU 吞吐量。
3. GPU 对比验证：在 CUDA 服务器上使用同一份密文分别执行 CPU 和 GPU 解密，输出性能对比结果。

建议顺序是：先跑自动测试，再跑 CPU 基线，最后到 GPU 服务器跑 CPU/GPU 对比。

## 二、准备环境

### 1. 基础环境

本项目需要 Python 3.13 或兼容环境，并安装 `cryptography`。

如果使用项目依赖管理工具，可以按 `pyproject.toml` 安装依赖。

### 2. GPU 环境

GPU 对比测试需要额外满足：

1. NVIDIA GPU 可用。
2. CUDA 驱动可用。
3. PyTorch 已安装，并且 `torch.cuda.is_available()` 返回 `True`。

在 GPU 服务器上先执行：

```bash
python3 -c "import torch; print(torch.cuda.is_available()); print(torch.cuda.get_device_name(0))"
```

如果第一行输出 `True`，说明 PyTorch 可以识别 CUDA。

## 三、运行自动测试

在项目根目录执行：

```bash
python3 -m unittest discover -s tests
```

预期结果类似：

```text
....
----------------------------------------------------------------------
Ran 4 tests in 0.070s

OK
```

这一步用于确认：

1. SM4-CBC 字符串加解密正确。
2. SM4-CTR 字符串加解密正确。
3. SM4-CBC 文件加解密后 sha256 一致。
4. 非法 key/IV 会被拒绝。

## 四、运行 CPU 基线验证

### 1. 默认运行

```bash
python3 sm4_cpu_validation.py
```

默认会使用：

1. 模式：`CBC`
2. 测试文件大小：`1MB`
3. 输出目录：`validation_output/sm4_cpu`

### 2. 指定测试模式和文件大小

```bash
python3 sm4_cpu_validation.py --mode CBC --size-mb 100 --output-dir validation_output/cpu_cbc_100m
python3 sm4_cpu_validation.py --mode CTR --size-mb 100 --output-dir validation_output/cpu_ctr_100m
```

参数说明：

1. `--mode`：SM4 模式，可选 `CBC` 或 `CTR`。
2. `--size-mb`：自动生成的测试文件大小，单位 MB。
3. `--output-dir`：测试文件输出目录。

### 3. CPU 输出字段说明

输出示例：

```text
字符串验证：通过
加密模式：SM4-CBC
字符串密文(hex)：...
文件验证：通过
原始文件：validation_output/cpu_cbc_100m/sample_plain.bin
密文文件：validation_output/cpu_cbc_100m/sample_cipher.bin
解密文件：validation_output/cpu_cbc_100m/sample_decrypted.bin
原始文件sha256：...
解密耗时(秒)：0.123456
解密吞吐量(MB/s)：123.45
```

重点看：

1. `字符串验证：通过`：字符串密文可以正确解密。
2. `文件验证：通过`：文件解密后的 sha256 和原始文件一致。
3. `解密耗时(秒)`：CPU 解密该密文文件耗费的时间。
4. `解密吞吐量(MB/s)`：CPU 每秒处理多少 MB 密文。

## 五、运行 GPU 对比验证

GPU 脚本应在 CUDA 服务器上执行。

### 1. 小文件试跑

先用 10MB 确认脚本和环境能跑通：

```bash
python3 sm4_gpu_validation.py --mode CBC --size-mb 10 --chunk-mb 16 --output-dir validation_output/gpu_cbc_10m
python3 sm4_gpu_validation.py --mode CTR --size-mb 10 --chunk-mb 16 --output-dir validation_output/gpu_ctr_10m
```

### 2. 正式对比测试

确认小文件跑通后，再增加文件大小：

```bash
python3 sm4_gpu_validation.py --mode CBC --size-mb 100 --chunk-mb 16 --output-dir validation_output/gpu_cbc_100m
python3 sm4_gpu_validation.py --mode CTR --size-mb 100 --chunk-mb 16 --output-dir validation_output/gpu_ctr_100m
```

如果服务器资源允许，可以继续测试 1GB：

```bash
python3 sm4_gpu_validation.py --mode CBC --size-mb 1024 --chunk-mb 16 --output-dir validation_output/gpu_cbc_1g
python3 sm4_gpu_validation.py --mode CTR --size-mb 1024 --chunk-mb 16 --output-dir validation_output/gpu_ctr_1g
```

### 3. GPU 参数说明

1. `--mode`：SM4 模式，可选 `CBC` 或 `CTR`。
2. `--size-mb`：自动生成的测试文件大小，单位 MB。
3. `--chunk-mb`：每次读取并送入 CPU/GPU 解密的分块大小，单位 MB。
4. `--output-dir`：测试文件输出目录。
5. `--device`：Torch 设备，默认是 `cuda`。

`--size-mb` 越大，越接近真实大文件场景；`--chunk-mb` 会影响文件 IO、CPU/GPU 数据传输和显存占用。

## 六、GPU 输出字段说明

输出示例：

```text
GPU验证：通过
GPU设备：NVIDIA GeForce RTX 4090
加密模式：SM4-CBC
测试文件大小(MB)：100
分块大小(MB)：16
原始文件：validation_output/gpu_cbc_100m/sample_plain.bin
密文文件：validation_output/gpu_cbc_100m/sample_cipher.bin
CPU解密文件：validation_output/gpu_cbc_100m/sample_cpu_decrypted.bin
GPU解密文件：validation_output/gpu_cbc_100m/sample_gpu_decrypted.bin
原始文件sha256：...
CPU解密sha256：...
GPU解密sha256：...
CPU解密耗时(秒)：...
GPU解密耗时(秒)：...
CPU解密吞吐量(MB/s)：...
GPU解密吞吐量(MB/s)：...
GPU相对CPU加速比：...
```

重点看：

1. `GPU验证：通过`：CPU 和 GPU 解密结果都与原始文件一致。
2. `CPU解密sha256`、`GPU解密sha256`：两者应与 `原始文件sha256` 一致。
3. `CPU解密耗时(秒)` 和 `GPU解密耗时(秒)`：直接对比耗时。
4. `CPU解密吞吐量(MB/s)` 和 `GPU解密吞吐量(MB/s)`：直接对比吞吐量。
5. `GPU相对CPU加速比`：大于 1 表示 GPU 更快，小于 1 表示当前验证实现下 GPU 更慢。

## 七、推荐测试矩阵

建议至少跑以下组合：

| 模式 | 文件大小 | 目的 |
| --- | ---: | --- |
| CBC | 10MB | 快速确认环境和正确性 |
| CTR | 10MB | 快速确认环境和正确性 |
| CBC | 100MB | 初步性能对比 |
| CTR | 100MB | 初步性能对比 |
| CBC | 1024MB | 大文件性能对比 |
| CTR | 1024MB | 大文件性能对比 |

如果时间有限，优先跑：

```bash
python3 sm4_gpu_validation.py --mode CBC --size-mb 100 --chunk-mb 16 --output-dir validation_output/gpu_cbc_100m
python3 sm4_gpu_validation.py --mode CTR --size-mb 100 --chunk-mb 16 --output-dir validation_output/gpu_ctr_100m
```

## 八、如何写报告结论

报告中建议至少记录：

1. GPU 型号。
2. CUDA/PyTorch 是否可用。
3. SM4 模式：CBC 或 CTR。
4. 测试文件大小。
5. 分块大小。
6. CPU 解密耗时和吞吐量。
7. GPU 解密耗时和吞吐量。
8. GPU 相对 CPU 加速比。
9. sha256 是否一致。

可以按下面格式整理：

```text
测试环境：
- GPU：
- CUDA/PyTorch：

测试参数：
- SM4 模式：
- 文件大小：
- 分块大小：

正确性结果：
- 原始文件 sha256：
- CPU 解密 sha256：
- GPU 解密 sha256：
- 是否一致：

性能结果：
- CPU 解密耗时：
- GPU 解密耗时：
- CPU 解密吞吐量：
- GPU 解密吞吐量：
- GPU 相对 CPU 加速比：
```

## 九、注意事项

1. 当前 GPU 脚本是验证版实现，用于采集对比数据，不等同于生产级 GPU 密码库。
2. 如果 GPU 加速比不明显，需要结合文件 IO、CPU/GPU 数据传输、分块大小和实际 CUDA 实现方式继续分析。
3. `validation_output/` 已加入 `.gitignore`，本地生成的测试文件不会被提交。
4. 如果要验证真实业务数据，建议使用脱敏样例，不要直接使用生产密钥和敏感文件。
