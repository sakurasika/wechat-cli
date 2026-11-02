"""Linux Config.Cipher 扫描的内存布局测试。

布局来自 WeChat Linux 4.1.13.26 x86_64：名字视图在节点 +0x10，
Config* 在 +0x28，密钥 Data 的指针/长度在 Config+0x18/+0x20。
这里只用合成密钥，不包含任何真实账号材料。
"""

import hashlib
import hmac
import os
import struct
import unittest

from wechat_cli.keys.common import (
    CONFIG_CIPHER_NAME,
    CONFIG_XOR_MASK,
    PAGE_SZ,
    decode_config_cipher_blob,
    passphrase_candidates,
    verify_enc_key,
    xor_repeat,
)
from wechat_cli.keys.scanner_linux import _scan_config_cipher


def _page_for(enc_key, salt):
    page = bytearray(os.urandom(PAGE_SZ))
    page[:16] = salt
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=32)
    digest = hmac.new(mac_key, bytes(page[16:PAGE_SZ - 64]), hashlib.sha512)
    digest.update(struct.pack("<I", 1))
    page[PAGE_SZ - 64:] = digest.digest()
    if not verify_enc_key(enc_key, bytes(page)):
        raise AssertionError("synthetic page did not verify")
    return bytes(page)


class _Image:
    def __init__(self):
        self.parts = []

    def add(self, addr, data):
        self.parts.append((addr, bytes(data)))
        return self

    def regions(self):
        return [(addr, len(data)) for addr, data in self.parts]

    def read(self, addr, size):
        buf = bytearray(size)
        hit = False
        for base, data in self.parts:
            start = max(addr, base)
            end = min(addr + size, base + len(data))
            if start < end:
                buf[start - addr:end - addr] = data[start - base:end - base]
                hit = True
        if not hit:
            return None
        return bytes(buf)


def _plant_cipher(image, blob, name_addr=0x100000, node_addr=0x200000,
                  config_addr=0x300000, blob_addr=0x400000,
                  ptr_off=0x18, len_off=0x20):
    image.add(name_addr, CONFIG_CIPHER_NAME + b"\x00")
    node = bytearray(0x40)
    struct.pack_into("<Q", node, 0x00, node_addr)
    struct.pack_into("<Q", node, 0x08, node_addr + 0x100)
    struct.pack_into("<Q", node, 0x10, name_addr)
    struct.pack_into("<Q", node, 0x18, len(CONFIG_CIPHER_NAME))
    struct.pack_into("<Q", node, 0x20, 1)
    struct.pack_into("<Q", node, 0x28, config_addr)
    image.add(node_addr, node)
    header = bytearray(0xB0)
    struct.pack_into("<Q", header, ptr_off, blob_addr)
    struct.pack_into("<Q", header, len_off, len(blob))
    image.add(config_addr, header)
    image.add(blob_addr, blob)


def _run_scan(image, salt, page, rel="session/session.db"):
    salt_hex = salt.hex()
    db_files = [(rel, "/tmp/" + rel, PAGE_SZ, salt_hex, page)]
    salt_to_dbs = {salt_hex: [rel]}
    key_map = {}
    remaining = {salt_hex}
    _scan_config_cipher(
        1,
        image.regions(),
        image.read,
        image.read,
        db_files,
        salt_to_dbs,
        key_map,
        remaining,
    )
    return key_map, remaining


class ConfigCipherLinuxTests(unittest.TestCase):
    def test_mask_is_32_byte_cycle(self):
        self.assertEqual(len(CONFIG_XOR_MASK), 32)
        raw = b"x'" + b"ab" * 48 + b"'"
        self.assertEqual(xor_repeat(xor_repeat(raw)), raw)
        self.assertEqual(decode_config_cipher_blob(xor_repeat(raw)), raw)

    def test_direct_hex_literal_at_linux_offsets(self):
        enc_key = bytes(range(32))
        salt = bytes(range(16, 32))
        page = _page_for(enc_key, salt)
        literal = b"x'" + (enc_key.hex() + salt.hex()).encode() + b"'"
        image = _Image()
        _plant_cipher(image, xor_repeat(literal))
        key_map, remaining = _run_scan(image, salt, page)
        self.assertEqual(key_map, {salt.hex(): enc_key.hex()})
        self.assertEqual(remaining, set())

    def test_windows_blob_offset_is_not_enough(self):
        enc_key = bytes(range(32))
        salt = bytes(range(16, 32))
        page = _page_for(enc_key, salt)
        literal = b"x'" + (enc_key.hex() + salt.hex()).encode() + b"'"
        image = _Image()
        _plant_cipher(image, xor_repeat(literal), ptr_off=0x90, len_off=0x98)
        key_map, remaining = _run_scan(image, salt, page)
        self.assertEqual(key_map, {})
        self.assertEqual(remaining, {salt.hex()})

    def test_second_data_field_is_also_checked(self):
        enc_key = bytes((index * 3 + 1) & 0xFF for index in range(32))
        salt = bytes(range(48, 64))
        page = _page_for(enc_key, salt)
        literal = b"x'" + (enc_key.hex() + salt.hex()).encode() + b"'"
        image = _Image()
        _plant_cipher(image, xor_repeat(literal), ptr_off=0x98, len_off=0xA0)
        key_map, remaining = _run_scan(image, salt, page, rel="message/message_0.db")
        self.assertEqual(key_map, {salt.hex(): enc_key.hex()})
        self.assertEqual(remaining, set())

    def test_passphrase_blob_derives_enc_key(self):
        passphrase = bytes((index * 7 + 3) & 0xFF for index in range(32))
        self.assertEqual(passphrase_candidates(passphrase), [passphrase])
        salts = [bytes(range(32, 48)), bytes(range(64, 80))]
        pages = []
        expected = {}
        for salt in salts:
            enc_key = hashlib.pbkdf2_hmac(
                "sha512", passphrase, salt, 256000, dklen=32
            )
            pages.append(_page_for(enc_key, salt))
            expected[salt.hex()] = enc_key.hex()
        image = _Image()
        _plant_cipher(image, xor_repeat(passphrase))
        db_files = []
        salt_to_dbs = {}
        for index, (salt, page) in enumerate(zip(salts, pages)):
            rel = f"message/message_{index}.db"
            salt_hex = salt.hex()
            db_files.append((rel, "/tmp/" + rel, PAGE_SZ, salt_hex, page))
            salt_to_dbs[salt_hex] = [rel]
        key_map = {}
        remaining = set(salt_to_dbs)
        _scan_config_cipher(
            1, image.regions(), image.read, image.read,
            db_files, salt_to_dbs, key_map, remaining,
        )
        self.assertEqual(remaining, set())
        self.assertEqual(key_map, expected)


if __name__ == "__main__":
    unittest.main()
