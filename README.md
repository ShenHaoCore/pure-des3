# pure-des3

[![Tests](https://github.com/ShenHaoCore/pure-des3/actions/workflows/tests.yml/badge.svg)](https://github.com/ShenHaoCore/pure-des3/actions/workflows/tests.yml)

纯 Python 标准库实现的 DES 与 3DES（DES-EDE3-CBC），**零第三方依赖**。

## 为什么需要它

Python 标准库没有 DES 系列算法，要用就得装 `pycryptodome` 或 `pyDes`。但在这些场景里装不了依赖：

- 无网络的隔离环境（内网、沙箱、CI runner 不允许装包）；
- 只想加密几个分组，不值得为它引入一个编译型依赖；
- 需要审计全部加密代码，不想引入二进制轮子。

这个库只用 `base64` 加几十行位运算，把 DES / 3DES 完整实现出来，逻辑可以逐行读完。

## 适用与不适用

**适用**：与被固定实现 3DES 的既有系统（老客户端、遗留协议）互操作。

**不适用**：任何新的加密设计。3DES 的有效强度只有 112 位且存在已知的理论弱点，NIST 已于 2023 年正式弃用它。新项目请用 AES-GCM 或 ChaCha20-Poly1305（标准库无实现，那就老老实实装依赖）。

## 用法

```python
from pure_des3 import des3_cbc_encrypt, des3_cbc_decrypt

key = b"0123456789abcdef01234567"   # 24 字节
iv = b"01234567"                    # 8 字节

token = des3_cbc_encrypt("hello world", key, iv)   # -> Base64 字符串
print(des3_cbc_decrypt(token, key, iv))            # -> hello world
```

另提供字节接口 `des3_cbc_encrypt_bytes` / `des3_cbc_decrypt_bytes`，以及单分组原语
`des_encrypt_block` / `des_decrypt_block` / `des3_encrypt_block` / `des3_decrypt_block`。

## 测试

```bash
python -m unittest discover -s tests -v
```

不需要安装任何第三方包。CI 在 Python 3.9 / 3.12 / 最新版上各跑一遍。

## 实现要点

- 3DES 使用 3-key EDE：`E(k1) ∘ D(k2) ∘ E(k3)`。顺序写反**不会报错**，只会算出
  完全错误的结果，所以正确性靠 FIPS 已知向量校验，而不是只做往返测试。
- DES 密钥的每一字节末位是奇偶校验位，会被 PC1 丢弃——翻转它不改变加密结果。
- 明文长度正好是 8 的倍数时，PKCS#7 会补满一整个块（密文因此比明文长 8 字节）。
- 密钥、IV、分组长度不符会立即抛 `ValueError`，不会静默截断。

## 安全说明

- **去填充是严格校验的**：除了检查末字节声明的填充长度是否落在合法区间，还要求末尾
  `n` 个字节**全部**等于 `n`。只做前一步的实现（很常见）会静默接受大量畸形密文，
  去填充后返回被截断的明文。
- 任何解密失败都抛 `ValueError`，绝不返回半截或可疑的明文。
- **3DES 已被弃用**：NIST 于 2023 年正式停止批准 3DES，其有效强度仅 112 位。本库的
  用途是与既有的固定实现互操作；保护新数据请用 AES-GCM 或 ChaCha20-Poly1305。
