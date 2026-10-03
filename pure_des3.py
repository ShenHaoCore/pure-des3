#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""纯标准库的 DES / 3DES（DES-EDE3-CBC）实现，零第三方依赖。

公开 API
--------
============================  ==================================================
``des_encrypt_block``         单分组 DES 加密（8 字节分组 / 8 字节密钥）
``des_decrypt_block``         单分组 DES 解密
``des3_encrypt_block``        单分组 DES-EDE3 加密（24 字节密钥）
``des3_decrypt_block``        单分组 DES-EDE3 解密
``des3_cbc_encrypt_bytes``    CBC + PKCS#7，字节进字节出
``des3_cbc_decrypt_bytes``    CBC + PKCS#7，字节进字节出
``des3_cbc_encrypt``          CBC + PKCS#7，文本进 Base64 出
``des3_cbc_decrypt``          CBC + PKCS#7，Base64 进文本出
``des3_cbc_encrypt_with_random_iv``  随机 IV + CBC + Base64 出
``des3_cbc_decrypt_with_random_iv``  随机 IV + CBC + Base64 进文本出
============================  ==================================================

实现说明
--------
DES 按 FIPS 46-3 完整实现：IP / FP / E / P / PC1 / PC2 置换表与 8 个 S 盒，
16 轮 Feistel 结构。3DES 采用 3-key EDE 模式，加密顺序为
``E(k1) ∘ D(k2) ∘ E(k3)``。

顺序写反不会报错，只会得到完全错误的结果——所以单元测试用 FIPS 已知向量
把它钉死，而不是只做往返测试。

另一个容易踩的点：DES 密钥的每一字节末位是奇偶校验位，PC1 会把它丢掉，
**翻转奇偶位不会改变加密结果**。写密钥变异测试时要避开这一位。

安全提醒
--------
3DES 已被 NIST 于 2023 年正式弃用，有效强度仅 112 位，**不要**用它保护新数据。
本模块的用途是与被固定实现 3DES 的既有系统互操作。

CBC 的安全性要求：
- 每次加密都必须使用全新的随机 IV；
- 仅在受控、可信的上下文中使用此模块，不要把它当作认证加密方案；
- 如需真实性和完整性，必须在应用层使用 HMAC 或 AEAD。
"""

import base64
import hmac
import os

__all__ = [
    "des_encrypt_block",
    "des_decrypt_block",
    "des3_encrypt_block",
    "des3_decrypt_block",
    "des3_cbc_encrypt",
    "des3_cbc_decrypt",
    "des3_cbc_encrypt_bytes",
    "des3_cbc_decrypt_bytes",
    "des3_cbc_encrypt_with_random_iv",
    "des3_cbc_decrypt_with_random_iv",
]

_BLOCK_SIZE = 8
_DES_KEY_SIZE = 8
_DES3_KEY_SIZE = 24

# ---------------------------------------------------------------------------
# 置换表与 S 盒（FIPS 46-3）
# ---------------------------------------------------------------------------

_IP = (
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
)

_FP = (
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
)

_E = (
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
)

_P = (
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
)

_PC1 = (
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
)

_PC2 = (
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
)

_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

_SBOX = (
    (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
    (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
    (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),
    (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),
    (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),
    (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),
    (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),
    (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11),
)

# ---------------------------------------------------------------------------
# 位运算与分组原语
# ---------------------------------------------------------------------------


def _permute(value, table, in_bits):
    """按 ``table`` 把 ``in_bits`` 位整数重排为 ``len(table)`` 位整数。"""
    out = 0
    for pos in table:
        out = (out << 1) | ((value >> (in_bits - pos)) & 1)
    return out


def _des_subkeys(key8):
    """由 8 字节密钥派生 16 个 48 位子密钥。"""
    permuted = _permute(int.from_bytes(key8, "big"), _PC1, 64)
    c = (permuted >> 28) & 0x0FFFFFFF
    d = permuted & 0x0FFFFFFF
    subkeys = []
    for shift in _SHIFTS:
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF
        subkeys.append(_permute((c << 28) | d, _PC2, 56))
    return subkeys


def _des_feistel(right, subkey):
    """轮函数 f(R, K)。"""
    mixed = _permute(right, _E, 32) ^ subkey
    out = 0
    for index in range(8):
        six = (mixed >> (42 - 6 * index)) & 0x3F
        row = ((six >> 5) << 1) | (six & 1)
        col = (six >> 1) & 0x0F
        out = (out << 4) | _SBOX[index][row * 16 + col]
    return _permute(out, _P, 32)


def _crypt_block(block8, subkeys):
    """对单个 8 字节分组做 DES 变换（子密钥顺序决定加密 / 解密）。"""
    permuted = _permute(int.from_bytes(block8, "big"), _IP, 64)
    left = (permuted >> 32) & 0xFFFFFFFF
    right = permuted & 0xFFFFFFFF
    for subkey in subkeys:
        left, right = right, left ^ _des_feistel(right, subkey)
    return _permute((right << 32) | left, _FP, 64).to_bytes(8, "big")


# ---------------------------------------------------------------------------
# 参数校验
# ---------------------------------------------------------------------------


def _require_length(name, value, expected):
    if len(value) != expected:
        raise ValueError("%s 长度非法" % name)


def _require_block(block8):
    _require_length("分组", block8, _BLOCK_SIZE)


def _require_des_key(key8):
    _require_length("DES 密钥", key8, _DES_KEY_SIZE)


def _require_des3_key(key24):
    _require_length("3DES 密钥", key24, _DES3_KEY_SIZE)


def _require_iv(iv8):
    _require_length("IV", iv8, _BLOCK_SIZE)


def _zeroize(data):
    """尽力清零可变字节容器，降低明文/密钥残留风险。"""
    if isinstance(data, bytearray):
        data[:] = b"\x00" * len(data)
    elif isinstance(data, memoryview):
        data.cast("B")[:] = b"\x00" * len(data)


# ---------------------------------------------------------------------------
# 单分组加解密
# ---------------------------------------------------------------------------


def des_encrypt_block(block8, key8):
    """单分组 DES 加密。``block8`` 与 ``key8`` 均为 8 字节。"""
    _require_block(block8)
    _require_des_key(key8)
    return _crypt_block(block8, _des_subkeys(key8))


def des_decrypt_block(block8, key8):
    """单分组 DES 解密。"""
    _require_block(block8)
    _require_des_key(key8)
    return _crypt_block(block8, list(reversed(_des_subkeys(key8))))


def des3_encrypt_block(block8, key24):
    """单分组 DES-EDE3 加密：``E(k1) ∘ D(k2) ∘ E(k3)``。"""
    _require_block(block8)
    _require_des3_key(key24)
    step = des_encrypt_block(block8, key24[0:8])
    step = des_decrypt_block(step, key24[8:16])
    return des_encrypt_block(step, key24[16:24])


def des3_decrypt_block(block8, key24):
    """单分组 DES-EDE3 解密：``D(k1) ∘ E(k2) ∘ D(k3)``。"""
    _require_block(block8)
    _require_des3_key(key24)
    step = des_decrypt_block(block8, key24[16:24])
    step = des_encrypt_block(step, key24[8:16])
    return des_decrypt_block(step, key24[0:8])


# ---------------------------------------------------------------------------
# PKCS#7 填充
# ---------------------------------------------------------------------------


def _pkcs7_pad(data, block_size=_BLOCK_SIZE):
    padding = block_size - len(data) % block_size
    return data + bytes([padding]) * padding


def _pkcs7_unpad(data, block_size=_BLOCK_SIZE):
    """去除 PKCS#7 填充，并完整校验填充的合法性。

    校验分两步，缺一不可：

    1. 末字节声明的填充长度必须落在 ``1..block_size`` 且不超过数据长度；
    2. 末尾 ``padding`` 个字节必须**全部**等于 ``padding``。

    只检查第 1 步（很多实现就这么写）会让大量畸形密文被静默接受，去填充后
    得到截断的明文。第 2 步是判别填充正确性的唯一依据，也是抵御 padding
    oracle 攻击的前提。
    """
    if not data:
        raise ValueError("空数据无法去填充")
    padding = data[-1]
    if padding < 1 or padding > block_size or padding > len(data):
        raise ValueError("PKCS#7 填充非法：长度字节 %d 超出 1..%d" % (padding, block_size))
    tail = data[-padding:]
    if not hmac.compare_digest(tail, bytes([padding]) * padding):
        raise ValueError("PKCS#7 填充非法：末尾 %d 字节不全是 0x%02X" % (padding, padding))
    return data[:-padding]


# ---------------------------------------------------------------------------
# DES-EDE3-CBC
# ---------------------------------------------------------------------------


def des3_cbc_encrypt_bytes(data, key24, iv8):
    """3DES-CBC 加密，返回密文字节。``data`` 为明文字节。"""
    _require_des3_key(key24)
    _require_iv(iv8)
    padded = _pkcs7_pad(data)
    previous = iv8
    chunks = []
    try:
        for offset in range(0, len(padded), _BLOCK_SIZE):
            block = bytes(a ^ b for a, b in zip(padded[offset:offset + _BLOCK_SIZE], previous))
            previous = des3_encrypt_block(block, key24)
            chunks.append(previous)
        return b"".join(chunks)
    finally:
        # 只做尽力清零：用于临时字节序列和 IV 值。
        _zeroize(bytearray(previous))


def des3_cbc_decrypt_bytes(data, key24, iv8):
    """3DES-CBC 解密，返回去填充后的明文字节。"""
    _require_des3_key(key24)
    _require_iv(iv8)
    if not data or len(data) % _BLOCK_SIZE:
        raise ValueError("密文长度必须是 %d 的整数倍" % _BLOCK_SIZE)
    previous = iv8
    chunks = []
    try:
        for offset in range(0, len(data), _BLOCK_SIZE):
            block = data[offset:offset + _BLOCK_SIZE]
            plain = des3_decrypt_block(block, key24)
            chunks.append(bytes(a ^ b for a, b in zip(plain, previous)))
            previous = block
        return _pkcs7_unpad(b"".join(chunks))
    finally:
        _zeroize(bytearray(previous))


def des3_cbc_encrypt(plaintext, key24, iv8):
    """3DES-CBC 加密文本，返回 Base64 字符串。

    ``plaintext`` 以 UTF-8 编码后加密；密钥 24 字节、IV 8 字节。
    """
    if not isinstance(plaintext, str):
        raise TypeError("plaintext 必须是 str，字节数据请用 des3_cbc_encrypt_bytes")
    return base64.b64encode(des3_cbc_encrypt_bytes(plaintext.encode("utf-8"), key24, iv8)).decode("ascii")


def des3_cbc_encrypt_with_random_iv(plaintext, key24):
    """随机生成 IV 并返回 ``IV || 密文`` 的 Base64 字符串。"""
    if not isinstance(plaintext, str):
        raise TypeError("plaintext 必须是 str，字节数据请用 des3_cbc_encrypt_bytes")
    _require_des3_key(key24)
    iv8 = os.urandom(_BLOCK_SIZE)
    ciphertext = des3_cbc_encrypt_bytes(plaintext.encode("utf-8"), key24, iv8)
    return base64.b64encode(iv8 + ciphertext).decode("ascii")


def des3_cbc_decrypt(ciphertext_b64, key24, iv8):
    """解密 ``des3_cbc_encrypt`` 产出的 Base64 密文，返回文本。

    与 :func:`des3_cbc_encrypt` 对称，只接受 ``str``；字节密文请用
    :func:`des3_cbc_decrypt_bytes`。
    """
    if not isinstance(ciphertext_b64, str):
        raise TypeError("ciphertext_b64 必须是 str，字节数据请用 des3_cbc_decrypt_bytes")
    try:
        data = base64.b64decode(ciphertext_b64, validate=True)
    except ValueError as exc:
        raise ValueError("Base64 密文格式非法") from exc
    try:
        return des3_cbc_decrypt_bytes(data, key24, iv8).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("解密失败或明文不是有效 UTF-8") from exc


def des3_cbc_decrypt_with_random_iv(ciphertext_b64, key24):
    """解密 ``des3_cbc_encrypt_with_random_iv`` 产出的 Base64 结果。"""
    if not isinstance(ciphertext_b64, str):
        raise TypeError("ciphertext_b64 必须是 str，字节数据请用 des3_cbc_decrypt_bytes")
    try:
        data = base64.b64decode(ciphertext_b64, validate=True)
    except ValueError as exc:
        raise ValueError("Base64 密文格式非法") from exc
    if len(data) < _BLOCK_SIZE or len(data) % _BLOCK_SIZE:
        raise ValueError("随机 IV + 密文的长度非法")
    iv8 = data[:_BLOCK_SIZE]
    ciphertext = data[_BLOCK_SIZE:]
    try:
        return des3_cbc_decrypt_bytes(ciphertext, key24, iv8).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("解密失败或明文不是有效 UTF-8") from exc
