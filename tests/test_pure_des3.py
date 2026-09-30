#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pure_des3 的单元测试 —— 纯标准库 unittest，无需安装任何依赖。

运行：
    python -m unittest discover -s tests -v
"""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pure_des3


class TestDesKnownVectors(unittest.TestCase):
    """用 FIPS 已知向量钉死 DES 正确性。

    ICV（初始置换 / 逆置换 / S 盒 / 子密钥调度）任一环节写错，往返测试仍可能
    通过（加解密互逆），所以必须用外部向量校验。
    """

    def test_fips_vector_now_is_t(self):
        key = bytes.fromhex("0123456789ABCDEF")
        block = b"Now is t"
        cipher = pure_des3.des_encrypt_block(block, key)
        self.assertEqual(cipher.hex().upper(), "3FA40E8A984D4815")

    def test_fips_vector_zeros_output(self):
        key = bytes.fromhex("0E329232EA6D0D73")
        block = bytes.fromhex("8787878787878787")
        cipher = pure_des3.des_encrypt_block(block, key)
        self.assertEqual(cipher, bytes(8))

    def test_known_vector_decrypts(self):
        key = bytes.fromhex("0123456789ABCDEF")
        cipher = bytes.fromhex("3FA40E8A984D4815")
        self.assertEqual(pure_des3.des_decrypt_block(cipher, key), b"Now is t")

    def test_roundtrip_is_identity_for_all_blocks(self):
        key = bytes.fromhex("0123456789ABCDEF")
        for block in (bytes(8), b"\xff" * 8, bytes(range(8)), b"Now is t"):
            cipher = pure_des3.des_encrypt_block(block, key)
            self.assertNotEqual(cipher, block, "固定点不应出现")
            self.assertEqual(pure_des3.des_decrypt_block(cipher, key), block)


class TestDes3Ede(unittest.TestCase):
    """3DES 的 EDE 顺序：写反不报错，只会算错，所以单独验证。"""

    KEY = bytes.fromhex("0123456789abcdeffedcba9876543210aabbccddeeff0011")

    def test_ede_order_matches_manual_composition(self):
        block = b"Now is t"
        expected = pure_des3.des_encrypt_block(
            pure_des3.des_decrypt_block(
                pure_des3.des_encrypt_block(block, self.KEY[0:8]), self.KEY[8:16]
            ),
            self.KEY[16:24],
        )
        self.assertEqual(pure_des3.des3_encrypt_block(block, self.KEY), expected)

    def test_ede_roundtrip(self):
        block = b"Now is t"
        cipher = pure_des3.des3_encrypt_block(block, self.KEY)
        self.assertNotEqual(cipher, block)
        self.assertEqual(pure_des3.des3_decrypt_block(cipher, self.KEY), block)

    def test_key_parts_are_all_used(self):
        """三段密钥任一段改变，结果都应不同。

        变异必须避开每字节的最低位：那是 DES 密钥的奇偶校验位，会被 PC1
        丢弃，只翻转它不会改变任何子密钥（见下一个用例）。
        """
        block = b"Now is t"
        base = pure_des3.des3_encrypt_block(block, self.KEY)
        for index in (0, 8, 16):
            with self.subTest(key_part=index // 8 + 1):
                mutated = bytearray(self.KEY)
                mutated[index] ^= 0x02
                self.assertNotEqual(pure_des3.des3_encrypt_block(block, bytes(mutated)), base)

    def test_parity_bits_do_not_affect_result(self):
        """DES 密钥每字节的第 8 位是奇偶校验位，PC1 会丢弃它。

        翻转全部 8 个奇偶位不改变任何一个子密钥，密文因此完全一致。
        """
        key = bytes.fromhex("0123456789ABCDEF")
        parity_flipped = bytearray(key)
        for index in range(8):
            parity_flipped[index] ^= 0x01
        self.assertNotEqual(bytes(parity_flipped), key)
        self.assertEqual(
            pure_des3.des_encrypt_block(b"Now is t", bytes(parity_flipped)),
            pure_des3.des_encrypt_block(b"Now is t", key),
        )


class TestCbcApi(unittest.TestCase):

    KEY = bytes.fromhex("0123456789abcdeffedcba9876543210aabbccddeeff0011")
    IV = b"01234567"

    def test_text_roundtrip(self):
        for text in ("", "Now is t", "hello world", "起点中文网 · 签到", "a" * 1000):
            with self.subTest(text=text[:20]):
                cipher = pure_des3.des3_cbc_encrypt(text, self.KEY, self.IV)
                self.assertEqual(pure_des3.des3_cbc_decrypt(cipher, self.KEY, self.IV), text)

    def test_ciphertext_is_block_aligned_base64(self):
        cipher = pure_des3.des3_cbc_encrypt("hello world", self.KEY, self.IV)
        raw = base64.b64decode(cipher)
        self.assertEqual(len(raw) % 8, 0)
        self.assertEqual(len(raw), 16)

    def test_iv_changes_ciphertext(self):
        a = pure_des3.des3_cbc_encrypt("same input", self.KEY, b"01234567")
        b = pure_des3.des3_cbc_encrypt("same input", self.KEY, b"76543210")
        self.assertNotEqual(a, b)

    def test_block_aligned_plaintext_gets_extra_block(self):
        """明文正好是 8 的倍数时，PKCS#7 必须补满一个整块。"""
        data = b"12345678"
        cipher = pure_des3.des3_cbc_encrypt_bytes(data, self.KEY, self.IV)
        self.assertEqual(len(cipher), 16)
        self.assertEqual(pure_des3.des3_cbc_decrypt_bytes(cipher, self.KEY, self.IV), data)

    def test_short_plaintext_gets_one_block(self):
        cipher = pure_des3.des3_cbc_encrypt_bytes(b"x", self.KEY, self.IV)
        self.assertEqual(len(cipher), 8)

    def test_empty_plaintext_gets_one_block(self):
        cipher = pure_des3.des3_cbc_encrypt_bytes(b"", self.KEY, self.IV)
        self.assertEqual(len(cipher), 8)
        self.assertEqual(pure_des3.des3_cbc_decrypt_bytes(cipher, self.KEY, self.IV), b"")


class TestPkcs7Strictness(unittest.TestCase):
    """去填充必须完整校验，不能只看末字节。"""

    KEY = bytes.fromhex("0123456789abcdeffedcba9876543210aabbccddeeff0011")
    IV = b"01234567"

    def _raw_cbc_encrypt(self, data):
        """对手工构造的分组序列做 CBC 加密，绕过上层填充逻辑。"""
        previous = self.IV
        out = b""
        for offset in range(0, len(data), 8):
            block = bytes(a ^ b for a, b in zip(data[offset:offset + 8], previous))
            previous = pure_des3.des3_encrypt_block(block, self.KEY)
            out += previous
        return out

    def test_consistent_padding_accepted(self):
        for claimed in range(1, 9):
            with self.subTest(claimed=claimed):
                plain = b"A" * (8 - claimed) + bytes([claimed]) * claimed
                cipher = self._raw_cbc_encrypt(plain)
                self.assertEqual(
                    pure_des3.des3_cbc_decrypt_bytes(cipher, self.KEY, self.IV), b"A" * (8 - claimed)
                )

    def test_inconsistent_padding_rejected(self):
        """末字节声明补 2 字节，但只有最后一个字节是 0x02。"""
        plain = b"AAAAAA" + b"\x00\x02"
        cipher = self._raw_cbc_encrypt(plain)
        with self.assertRaises(ValueError) as ctx:
            pure_des3.des3_cbc_decrypt_bytes(cipher, self.KEY, self.IV)
        self.assertIn("不全是", str(ctx.exception))

    def test_padding_length_zero_rejected(self):
        plain = b"AAAAAAA\x00"
        with self.assertRaises(ValueError) as ctx:
            pure_des3.des3_cbc_decrypt_bytes(self._raw_cbc_encrypt(plain), self.KEY, self.IV)
        self.assertIn("超出", str(ctx.exception))

    def test_padding_length_over_block_size_rejected(self):
        plain = b"AAAAAAA\x10"
        with self.assertRaises(ValueError):
            pure_des3.des3_cbc_decrypt_bytes(self._raw_cbc_encrypt(plain), self.KEY, self.IV)

    def test_full_block_padding_is_valid(self):
        """整块填充（8 个 0x08）是合法的，不能误判。"""
        plain = bytes([8]) * 8
        cipher = self._raw_cbc_encrypt(plain)
        self.assertEqual(pure_des3.des3_cbc_decrypt_bytes(cipher, self.KEY, self.IV), b"")

    def test_tampered_last_block_is_detected(self):
        """篡改密文末块：绝大多数情况下填充校验会拦下，绝不能静默返回垃圾。"""
        cipher = bytearray(pure_des3.des3_cbc_encrypt_bytes(b"hello world", self.KEY, self.IV))
        rejected = 0
        for bit in range(8):
            mutated = bytearray(cipher)
            mutated[-1] ^= (1 << bit)
            try:
                pure_des3.des3_cbc_decrypt_bytes(bytes(mutated), self.KEY, self.IV)
            except ValueError:
                rejected += 1
        self.assertGreaterEqual(rejected, 7, "8 个位翻转至少应拦下 7 个")


class TestValidation(unittest.TestCase):

    KEY = bytes.fromhex("0123456789abcdeffedcba9876543210aabbccddeeff0011")
    IV = b"01234567"

    def test_bad_key_length(self):
        for bad in (b"", b"12345678", self.KEY + b"\x00"):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    pure_des3.des3_cbc_encrypt("x", bad, self.IV)

    def test_bad_des_key_length(self):
        for bad in (b"", b"short", b"123456789"):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    pure_des3.des_encrypt_block(b"12345678", bad)

    def test_bad_iv_length(self):
        for bad in (b"", b"1234567", b"123456789"):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    pure_des3.des3_cbc_encrypt("x", self.KEY, bad)

    def test_bad_block_length(self):
        with self.assertRaises(ValueError):
            pure_des3.des_encrypt_block(b"short", b"12345678")

    def test_ciphertext_not_block_multiple(self):
        with self.assertRaises(ValueError):
            pure_des3.des3_cbc_decrypt_bytes(b"1234567", self.KEY, self.IV)
        with self.assertRaises(ValueError):
            pure_des3.des3_cbc_decrypt_bytes(b"", self.KEY, self.IV)

    def test_encrypt_rejects_bytes(self):
        with self.assertRaises(TypeError):
            pure_des3.des3_cbc_encrypt(b"bytes not str", self.KEY, self.IV)


if __name__ == "__main__":
    unittest.main(verbosity=2)
