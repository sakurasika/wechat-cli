"""
跨平台共享的内存扫描逻辑：HMAC 验证、DB 收集、hex 模式匹配与结果输出。

从 wechat-decrypt/key_scan_common.py 适配，save_results 改为返回 dict。
Config.Cipher 的 XOR 掩码与 x'<hex>' 解码是 Windows / Linux 4.1+ 共用的。
"""

import hashlib
import hmac as hmac_mod
import json
import os
import re
import struct

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
SQLITE_HDR = b"SQLite format 3\x00"

# SQLCipher 4 标准：passphrase -> enc_key 的 PBKDF2 轮数
PBKDF2_ITERATIONS = 256000


def verify_enc_key(enc_key, db_page1):
    """通过 HMAC-SHA512 校验 page 1 验证 enc_key 是否正确。"""
    salt = db_page1[:SALT_SZ]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)
    hmac_data = db_page1[SALT_SZ: PAGE_SZ - 80 + 16]
    stored_hmac = db_page1[PAGE_SZ - 64: PAGE_SZ]
    hm = hmac_mod.new(mac_key, hmac_data, hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hm.digest() == stored_hmac


def derive_keys_from_passphrase(passphrase, db_files, salt_to_dbs, print_fn=None):
    """用 32 字节 passphrase 对每个 salt 做 PBKDF2，派生并校验 enc_key。

    微信 4.1+ 内存里通常只剩 passphrase，需要再派生才能得到真正的 AES 密钥。
    每个 salt 约需数百毫秒（256000 轮 SHA-512），库多时整体可能要几十秒。

    Returns:
        dict: salt_hex -> enc_key_hex
    """
    if isinstance(passphrase, str):
        passphrase = bytes.fromhex(passphrase)
    key_map = {}
    total = len(salt_to_dbs)
    for i, salt_hex in enumerate(salt_to_dbs):
        salt = bytes.fromhex(salt_hex)
        enc_key = hashlib.pbkdf2_hmac(
            "sha512", passphrase, salt, PBKDF2_ITERATIONS, dklen=KEY_SZ
        )
        for _rel, _path, _sz, s, page1 in db_files:
            if s == salt_hex and verify_enc_key(enc_key, page1):
                key_map[salt_hex] = enc_key.hex()
                break
        if print_fn and ((i + 1) % 5 == 0 or i == total - 1):
            print_fn(f"  PBKDF2 派生: {i + 1}/{total} ({len(key_map)} 验证通过)")
    return key_map


# 微信 4.1+ 把密钥材料放在 WCDB Config.Cipher 对象里，并用这段 32 字节掩码 XOR。
# Linux 4.1.13.26 的 .rodata 与 Windows 扫描用的是同一组字节；循环周期是 32
# （二进制里按 index & 0x1f 取掩码）。
CONFIG_CIPHER_NAME = b"com.Tencent.WCDB.Config.Cipher"
CONFIG_XOR_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b"
    "450048844c2448488944254048584c24"
)
CONFIG_BLOB_MAX = 1024
CONFIG_LITERAL_RE = re.compile(rb"[xX]'([0-9a-fA-F]{64,192})'")
_HEX_ASCII = b"0123456789abcdefABCDEF"


def xor_repeat(data, mask=None):
    """用循环掩码 XOR。默认掩码即 Config.Cipher 的 32 字节常量。"""
    if mask is None:
        mask = CONFIG_XOR_MASK
    if not mask:
        return b""
    return bytes(value ^ mask[index % len(mask)] for index, value in enumerate(data))


def probable_32_byte_key(data):
    """粗过滤明显不是密钥的 32 字节（全 0 / 全 FF / 熵太低）。"""
    return (
        len(data) == KEY_SZ
        and len(set(data)) >= 15
        and data not in {b"\x00" * KEY_SZ, b"\xff" * KEY_SZ}
    )


def decode_config_cipher_blob(blob):
    """XOR 还原 Config.Cipher 里的密钥材料。过长或空 blob 返回空。"""
    if not blob or len(blob) > CONFIG_BLOB_MAX:
        return b""
    return xor_repeat(blob, CONFIG_XOR_MASK)


def config_cipher_key_candidates(blob):
    """从 Config.Cipher blob 解码出候选 (enc_key_hex, embedded_salt_or_None)。

    embedded_salt 是字面量里紧跟 32 字节 key 的 16 字节 salt（hex），没有则为 None。
    """
    decoded = decode_config_cipher_blob(blob)
    if not decoded:
        return []
    out = []
    seen = set()
    for match in CONFIG_LITERAL_RE.finditer(decoded):
        run = match.group(1).decode("ascii").lower()
        starts = [0]
        if len(run) > 96:
            starts.extend(range(0, len(run) - 63, 32))
            starts.append(len(run) - 64)
        for start in dict.fromkeys(starts):
            if start < 0 or start + 64 > len(run):
                continue
            enc_key_hex = run[start:start + 64]
            try:
                enc_key = bytes.fromhex(enc_key_hex)
            except ValueError:
                continue
            if not probable_32_byte_key(enc_key):
                continue
            embedded_salt = None
            if start + 96 <= len(run):
                embedded_salt = run[start + 64:start + 96]
            item = (enc_key_hex, embedded_salt)
            if item not in seen:
                seen.add(item)
                out.append(item)
    return out


def passphrase_candidates(decoded):
    """从已解码的 Config.Cipher 材料里收集 32 字节 passphrase。

    Linux 4.1+ 常直接存 passphrase，而不是 x'<enc_key><salt>'。
    只接受：整段就是 32 字节（尾部可有少量 NUL）、64 位 hex，或 x'<64hex>'。
    """
    if not decoded:
        return []
    found = []
    seen = set()

    def add(raw):
        if probable_32_byte_key(raw) and raw not in seen:
            seen.add(raw)
            found.append(raw)

    if KEY_SZ <= len(decoded) <= KEY_SZ + 8 and decoded[KEY_SZ:].strip(b"\x00") == b"":
        add(decoded[:KEY_SZ])

    stripped = decoded.strip(b"\x00 \r\n\t")
    if len(stripped) == 64 and all(byte in _HEX_ASCII for byte in stripped):
        try:
            add(bytes.fromhex(stripped.decode("ascii")))
        except ValueError:
            pass

    for match in CONFIG_LITERAL_RE.finditer(decoded):
        run = match.group(1)
        if len(run) != 64:
            continue
        try:
            add(bytes.fromhex(run.decode("ascii")))
        except ValueError:
            continue
    return found


def collect_db_files(db_dir):
    """遍历 db_dir 收集所有 .db 文件及其 salt。

    返回 (db_files, salt_to_dbs):
      db_files: [(rel_path, abs_path, size, salt_hex, page1_bytes), ...]
      salt_to_dbs: {salt_hex: [rel_path, ...]}
    """
    db_files = []
    salt_to_dbs = {}
    for root, dirs, files in os.walk(db_dir):
        for name in files:
            if not name.endswith(".db") or name.endswith("-wal") or name.endswith("-shm"):
                continue
            path = os.path.join(root, name)
            size = os.path.getsize(path)
            if size < PAGE_SZ:
                continue
            with open(path, "rb") as f:
                page1 = f.read(PAGE_SZ)
            # 明文 SQLite（未加密）—— salt 会变成 "SQLite format 3\0"，跳过
            if page1.startswith(SQLITE_HDR):
                continue
            rel = os.path.relpath(path, db_dir)
            # 若扫描根目录高于 db_storage，仍按相对 db_storage 存键名
            marker = f"{os.sep}db_storage{os.sep}"
            idx = rel.find(marker)
            if idx >= 0:
                rel = rel[idx + len(marker):]
            elif rel.startswith(f"db_storage{os.sep}"):
                rel = rel[len(f"db_storage{os.sep}"):]
            salt = page1[:SALT_SZ].hex()
            db_files.append((rel, path, size, salt, page1))
            salt_to_dbs.setdefault(salt, []).append(rel)
    return db_files, salt_to_dbs


def scan_memory_for_keys(data, hex_re, db_files, salt_to_dbs, key_map,
                         remaining_salts, base_addr, pid, print_fn):
    """扫描一段内存数据，匹配 hex 模式并验证密钥。

    返回本次扫描匹配到的 hex 模式数量。
    """
    matches = 0
    for m in hex_re.finditer(data):
        hex_str = m.group(1).decode()
        addr = base_addr + m.start()
        matches += 1
        hex_len = len(hex_str)

        if hex_len == 96:
            enc_key_hex = hex_str[:64]
            salt_hex = hex_str[64:]
            if salt_hex in remaining_salts:
                enc_key = bytes.fromhex(enc_key_hex)
                for rel, path, sz, s, page1 in db_files:
                    if s == salt_hex and verify_enc_key(enc_key, page1):
                        key_map[salt_hex] = enc_key_hex
                        remaining_salts.discard(salt_hex)
                        dbs = salt_to_dbs[salt_hex]
                        print_fn(f"\n  [FOUND] salt={salt_hex}")
                        print_fn(f"    enc_key={enc_key_hex}")
                        print_fn(f"    PID={pid} 地址: 0x{addr:016X}")
                        print_fn(f"    数据库: {', '.join(dbs)}")
                        break

        elif hex_len == 64:
            if not remaining_salts:
                continue
            enc_key_hex = hex_str
            enc_key = bytes.fromhex(enc_key_hex)
            for rel, path, sz, salt_hex_db, page1 in db_files:
                if salt_hex_db in remaining_salts and verify_enc_key(enc_key, page1):
                    key_map[salt_hex_db] = enc_key_hex
                    remaining_salts.discard(salt_hex_db)
                    dbs = salt_to_dbs[salt_hex_db]
                    print_fn(f"\n  [FOUND] salt={salt_hex_db}")
                    print_fn(f"    enc_key={enc_key_hex}")
                    print_fn(f"    PID={pid} 地址: 0x{addr:016X}")
                    print_fn(f"    数据库: {', '.join(dbs)}")
                    break

        elif hex_len > 96 and hex_len % 2 == 0:
            enc_key_hex = hex_str[:64]
            salt_hex = hex_str[-32:]
            if salt_hex in remaining_salts:
                enc_key = bytes.fromhex(enc_key_hex)
                for rel, path, sz, s, page1 in db_files:
                    if s == salt_hex and verify_enc_key(enc_key, page1):
                        key_map[salt_hex] = enc_key_hex
                        remaining_salts.discard(salt_hex)
                        dbs = salt_to_dbs[salt_hex]
                        print_fn(f"\n  [FOUND] salt={salt_hex} (long hex {hex_len})")
                        print_fn(f"    enc_key={enc_key_hex}")
                        print_fn(f"    PID={pid} 地址: 0x{addr:016X}")
                        print_fn(f"    数据库: {', '.join(dbs)}")
                        break

    return matches


def cross_verify_keys(db_files, salt_to_dbs, key_map, print_fn):
    """用已找到的 key 交叉验证未匹配的 salt。"""
    missing_salts = set(salt_to_dbs.keys()) - set(key_map.keys())
    if not missing_salts or not key_map:
        return
    print_fn(f"\n还有 {len(missing_salts)} 个 salt 未匹配，尝试交叉验证...")
    for salt_hex in list(missing_salts):
        for rel, path, sz, s, page1 in db_files:
            if s == salt_hex:
                for known_salt, known_key_hex in key_map.items():
                    enc_key = bytes.fromhex(known_key_hex)
                    if verify_enc_key(enc_key, page1):
                        key_map[salt_hex] = known_key_hex
                        print_fn(f"  [CROSS] salt={salt_hex} 可用 key from salt={known_salt}")
                        missing_salts.discard(salt_hex)
                break


def save_results(db_files, salt_to_dbs, key_map, output_path, print_fn):
    """保存密钥结果到 JSON 文件。

    Args:
        db_files: collect_db_files 返回的 db_files
        salt_to_dbs: collect_db_files 返回的 salt_to_dbs
        key_map: {salt_hex: enc_key_hex}
        output_path: 输出 JSON 文件路径
        print_fn: 日志输出函数

    Returns:
        dict: salt_hex -> enc_key_hex 映射

    Raises:
        RuntimeError: 未提取到任何密钥
    """
    print_fn(f"\n{'=' * 60}")
    print_fn(f"结果: {len(key_map)}/{len(salt_to_dbs)} salts 找到密钥")

    result = {}
    for rel, path, sz, salt_hex, page1 in db_files:
        if salt_hex in key_map:
            result[rel] = {
                "enc_key": key_map[salt_hex],
                "salt": salt_hex,
                "size_mb": round(sz / 1024 / 1024, 1)
            }
            print_fn(f"  OK: {rel} ({sz / 1024 / 1024:.1f}MB)")
        else:
            print_fn(f"  MISSING: {rel} (salt={salt_hex})")

    if not result:
        print_fn(f"\n[!] 未提取到任何密钥")
        raise RuntimeError("未能从任何微信进程中提取到密钥")

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print_fn(f"\n密钥保存到: {output_path}")

    missing = [rel for rel, path, sz, salt_hex, page1 in db_files if salt_hex not in key_map]
    if missing:
        print_fn(f"\n未找到密钥的数据库:")
        for rel in missing:
            print_fn(f"  {rel}")

    return key_map
