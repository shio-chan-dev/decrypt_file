# SM4 真实业务样例解密教程

本文记录项目本地 `test_files/` 下这组真实测试样例的使用方式。该样例用于验证业务文件的 `SM4-CBC + PKCS7` 文件流解密，以及后续 CPU/GPU 对比。

`test_files/` 已加入 `.gitignore`，用于存放本地真实测试材料、解包结果和解密输出，不会被提交到仓库。

## 一、样例材料

原始材料目录：

```text
test_files/raw
```

目录中包含：

```text
aecff4a407da400bb40ff1fc6b2e39d5.utczip
信创测试加密证书私钥.sm2
```

含义：

1. `aecff4a407da400bb40ff1fc6b2e39d5.utczip` 是完整业务加密包，不是普通 zip。
2. `信创测试加密证书私钥.sm2` 是打开数字信封时使用的 SM2 证书/私钥材料。
3. `utcsoft83246800` 是本次样例中疑似证书密码，用于解锁 `.sm2` 私钥，不是 SM4 key。

## 二、解包结果

当前样例已经解包到：

```text
test_files/extracted
```

解包后关键文件：

```text
utctmp
json
```

含义：

1. `utctmp` 是真正的 SM4 加密文件，对应业务代码里的 `encFilePath`。
2. `json` 是元数据文件，包含 `sign1`、`sign2`、`miwen`。
3. `miwen` 是数字信封，用于获取 IV 和 SM4 key，不是要直接 SM4 解密的文件密文。

如果需要重新观察或导出当前样例，可以使用项目内的观察性解包脚本：

```bash
python3 scripts/direct_decrypt/utczip_extract.py \
  test_files/raw/aecff4a407da400bb40ff1fc6b2e39d5.utczip \
  --list-only
```

确认分段后再写出文件：

```bash
python3 scripts/direct_decrypt/utczip_extract.py \
  test_files/raw/aecff4a407da400bb40ff1fc6b2e39d5.utczip \
  --output-dir test_files/extracted \
  --overwrite
```

该脚本只是按当前样例观察到的 `UTES/UESF_A/UESF_B` 结构拆出文件段，不负责验签、打开数字信封或 SM4 解密。正式业务流程仍应优先使用公司解包工具或 Java 里的 `LargeFileUtil.extractAllFiles`。

## 三、本次验证参数

本次测试样例已确认可以使用以下参数解密 `utctmp`：

```text
IV：
360108a8cf3016d6d720ec7dd1f8fd1e

SM4 key：
1b9ad1730769af291da0ff795f411696
```

这两个值均为 32 位 hex，也就是 16 字节，符合 SM4-CBC 要求。

## 四、CPU 解密验证

在项目根目录执行：

```bash
python3 scripts/direct_decrypt/sm4_direct_decrypt.py \
  --input-file test_files/extracted/utctmp \
  --key-hex 1b9ad1730769af291da0ff795f411696 \
  --iv-hex 360108a8cf3016d6d720ec7dd1f8fd1e \
  --output-file test_files/output/real_plain_cpu.bin
```

已验证输出：

```text
解密状态：成功
输出文件sha256：cb1d58a1ff5a1eb9c7982b5eb0f89039fba29c022b89ebefb6ccd4a3168e6bb6
```

如果输出文件存在，可以确认文件类型：

```bash
file test_files/output/real_plain_cpu.bin
```

本次验证结果：

```text
PDF document, version 1.3, 6656 page(s)
```

这说明 `utctmp`、IV 和 SM4 key 是匹配的，且 CPU 路径已经完成真实样例解密。

## 五、GPU 解密命令

GPU 验证需要在安装了 PyTorch 且 CUDA 可用的 Python 环境运行。先确认环境：

```bash
python3 -c "import sys, torch; print(sys.executable); print(torch.__version__); print(torch.version.cuda); print(torch.cuda.is_available())"
```

如果 `torch.cuda.is_available()` 为 `True`，执行：

```bash
python3 sm4_decrypt_standalone.py \
  --input-file test_files/extracted/utctmp \
  --key-hex 1b9ad1730769af291da0ff795f411696 \
  --iv-hex 360108a8cf3016d6d720ec7dd1f8fd1e \
  --backend gpu \
  --device cuda:2 \
  --output-file test_files/output/real_plain_gpu.bin
```

如果只想使用项目内 GPU 脚本，也可以执行：

```bash
python3 scripts/direct_decrypt/sm4_gpu_direct_decrypt.py \
  --input-file test_files/extracted/utctmp \
  --key-hex 1b9ad1730769af291da0ff795f411696 \
  --iv-hex 360108a8cf3016d6d720ec7dd1f8fd1e \
  --device cuda:2 \
  --output-file test_files/output/real_plain_gpu.bin
```

GPU 输出文件应与 CPU 输出文件 hash 一致：

```bash
sha256sum test_files/output/real_plain_cpu.bin test_files/output/real_plain_gpu.bin
```

## 六、流程理解

这组测试文件的真实链路是：

```text
aecff...utczip 完整业务包
  ↓
解包得到 utctmp 和 json
  ↓
json.miwen 数字信封用于得到 IV 和 SM4 key
  ↓
使用 IV + SM4 key 解密 utctmp
  ↓
得到真实 PDF 明文文件
```

当前 Python 脚本负责最后一步：

```text
utctmp + IV + SM4 key
  ↓
SM4-CBC + PKCS7 文件流解密
  ↓
明文 PDF
```

脚本不负责完整业务链路中的验签、SM2 证书解锁、数字信封打开和原始 `.utczip` 官方解包逻辑。

## 七、报告记录要点

写报告时建议记录：

1. 输入加密文件：`解包结果/utctmp`
2. 解密模式：`SM4-CBC + PKCS7`
3. IV 和 SM4 key 长度：均为 16 字节
4. CPU 解密结果：成功
5. CPU 输出文件类型：PDF
6. CPU 输出文件 sha256：`cb1d58a1ff5a1eb9c7982b5eb0f89039fba29c022b89ebefb6ccd4a3168e6bb6`
7. GPU 解密结果：待在 CUDA/PyTorch 可用环境补充
