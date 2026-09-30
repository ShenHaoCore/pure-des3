#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pure_des3 最小可运行示例：加密、解密、IV 的作用、篡改检测。

运行：
    python examples/roundtrip.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pure_des3 import des3_cbc_decrypt, des3_cbc_encrypt


def main():
    key = bytes.fromhex("0123456789abcdeffedcba9876543210aabbccddeeff0011")
    iv = bytes.fromhex("0011223344556677")

    plaintext = "hello, 3DES"
    token = des3_cbc_encrypt(plaintext, key, iv)

    print("明文       :", plaintext)
    print("Base64 密文:", token)
    print("解密结果   :", des3_cbc_decrypt(token, key, iv))

    other = des3_cbc_encrypt(plaintext, key, bytes(8))
    print("换 IV 之后 :", other, "（与上面", "不同" if other != token else "相同", "）")

    tampered = token[:-4] + ("A" if token[-4] != "A" else "B") + token[-3:]
    try:
        des3_cbc_decrypt(tampered, key, iv)
    except ValueError as exc:
        print("篡改检测   : ValueError:", exc)
    else:
        print("篡改检测   : 未报错——填充恰好合法，属小概率事件，不会返回原文")
        print("             篡改后的明文:", des3_cbc_decrypt(tampered, key, iv))


if __name__ == "__main__":
    main()
