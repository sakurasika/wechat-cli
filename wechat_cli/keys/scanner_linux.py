"""Linux 密钥提取 — 通过 /proc 读取微信进程内存

微信 4.1+ 不再把明文 x'<hex>' 留在内存里。Linux 4.1.13.26 仍把材料放在
WCDB Config.Cipher 对象中，并用与 Windows 相同的 32 字节掩码 XOR。
节点布局（名字在 +0x10，Config* 在 +0x28）与 Windows 扫描一致；blob 偏移不同：
CipherConfig 的 Data 成员从 +0x10 起，缓冲区指针在 +0x18、长度在 +0x20
（另一份 Data 在 +0x90，对应 +0x98/+0xA0）。解码后若是 x'<hex>' 则直接校验，
若是 32 字节 passphrase 则再做 PBKDF2。都未命中时回退老版本 hex 扫描。
"""

import functools
import hashlib
import os
import re
import struct
import time

from .common import (
    CONFIG_BLOB_MAX,
    CONFIG_CIPHER_NAME,
    PBKDF2_ITERATIONS,
    collect_db_files,
    config_cipher_key_candidates,
    cross_verify_keys,
    decode_config_cipher_blob,
    derive_keys_from_passphrase,
    passphrase_candidates,
    probable_32_byte_key,
    save_results,
    scan_memory_for_keys,
    verify_enc_key,
)

print = functools.partial(print, flush=True)


def _safe_readlink(path):
    try:
        return os.path.realpath(os.readlink(path))
    except OSError:
        return ""


_KNOWN_COMMS = {"wechat", "wechatappex", "weixin"}
_INTERPRETER_PREFIXES = ("python", "bash", "sh", "zsh", "node", "perl", "ruby")


def _is_wechat_process(pid):
    """检查 pid 是否为微信进程。"""
    if pid == os.getpid():
        return False
    try:
        with open(f"/proc/{pid}/comm") as f:
            comm = f.read().strip()
        if comm.lower() in _KNOWN_COMMS:
            return True
        exe_path = _safe_readlink(f"/proc/{pid}/exe")
        exe_name = os.path.basename(exe_path)
        if any(exe_name.lower().startswith(p) for p in _INTERPRETER_PREFIXES):
            return False
        return "wechat" in exe_name.lower() or "weixin" in exe_name.lower()
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        return False


def _get_pids():
    """返回所有疑似微信主进程的 (pid, rss_kb) 列表，按内存降序。"""
    pids = []
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        pid = int(pid_str)
        try:
            if not _is_wechat_process(pid):
                continue
            with open(f"/proc/{pid}/statm") as f:
                rss_pages = int(f.read().split()[1])
            rss_kb = rss_pages * 4
            pids.append((pid, rss_kb))
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            continue

    if not pids:
        raise RuntimeError("未检测到 Linux 微信进程")

    pids.sort(key=lambda item: item[1], reverse=True)
    for pid, rss_kb in pids:
        exe_path = _safe_readlink(f"/proc/{pid}/exe")
        print(f"[+] WeChat PID={pid} ({rss_kb // 1024}MB) {exe_path}")
    return pids


_SKIP_MAPPINGS = {"[vdso]", "[vsyscall]", "[vvar]"}
_SKIP_PATH_PREFIXES = ("/usr/lib/", "/lib/", "/usr/share/")


def _get_readable_regions(pid):
    """解析 /proc/<pid>/maps，返回可读内存区域列表。"""
    regions = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue
            if "r" not in parts[1]:
                continue
            if len(parts) >= 6:
                mapping_name = parts[5]
                if mapping_name in _SKIP_MAPPINGS:
                    continue
                mapping_lower = mapping_name.lower()
                if (any(mapping_name.startswith(p) for p in _SKIP_PATH_PREFIXES)
                        and "wcdb" not in mapping_lower
                        and "wechat" not in mapping_lower
                        and "weixin" not in mapping_lower):
                    continue
            start_s, end_s = parts[0].split("-")
            start = int(start_s, 16)
            size = int(end_s, 16) - start
            if 0 < size < 500 * 1024 * 1024:
                regions.append((start, size))
    return regions


def _check_permissions():
    """检查是否有读取进程内存的权限。"""
    if os.geteuid() == 0:
        return
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_eff = int(line.split(":")[1].strip(), 16)
                    CAP_SYS_PTRACE = 1 << 19
                    if cap_eff & CAP_SYS_PTRACE:
                        return
                    break
    except (OSError, ValueError):
        pass
    raise RuntimeError(
        "需要 root 权限或 CAP_SYS_PTRACE 才能读取进程内存\n"
        "请使用: sudo wechat-cli init\n"
        "或授予 capability: sudo setcap cap_sys_ptrace=ep $(which python3)"
    )


# 用户态指针上限。4.1.13 的 Config* / buffer* 都落在这以下。
_MAX_USER_ADDRESS = 0x0000_8000_0000_0000
# (buffer_ptr_offset, length_offset) inside CipherConfig. See module docstring.
_CIPHER_BLOB_FIELDS = ((0x18, 0x20), (0x98, 0xA0))


def _u64_from(data, offset):
    if offset < 0 or offset + 8 > len(data):
        return 0
    return struct.unpack_from("<Q", data, offset)[0]


def _read_mem(mem, addr, size):
    if size <= 0:
        return None
    try:
        mem.seek(addr)
        data = mem.read(size)
    except (OSError, OverflowError, ValueError):
        return None
    if not data:
        return None
    return data


_READ_CHUNK = 2 * 1024 * 1024


def _iter_region_data(regions, read_region, chunk_size=_READ_CHUNK):
    """按块读出可读区域。单次 read 可能短于请求长度，读多少就推进多少。"""
    for base, size in regions:
        offset = 0
        while offset < size:
            current = min(chunk_size, size - offset)
            data = read_region(base + offset, current)
            if not data:
                offset += current
                continue
            step = min(len(data), current)
            yield base + offset, data[:step]
            offset += step if step > 0 else current


def _find_bytes(regions, read_region, needle):
    addresses = set()
    if not needle:
        return addresses
    for base, data in _iter_region_data(regions, read_region):
        pos = data.find(needle)
        while pos >= 0:
            addresses.add(base + pos)
            pos = data.find(needle, pos + 1)
    return addresses


def _verify_direct_key_candidate(
    enc_key_hex, embedded_salt, db_files, salt_to_dbs, key_map, remaining_salts, pid
):
    if not remaining_salts:
        return 0
    try:
        enc_key = bytes.fromhex(enc_key_hex)
    except ValueError:
        return 0
    if not probable_32_byte_key(enc_key):
        return 0
    target_salts = (
        [embedded_salt] if embedded_salt in remaining_salts else list(remaining_salts)
    )
    matched = 0
    for salt_hex in target_salts:
        if salt_hex not in remaining_salts:
            continue
        for _rel, _path, _sz, salt, page1 in db_files:
            if salt == salt_hex and verify_enc_key(enc_key, page1):
                key_map[salt_hex] = enc_key_hex
                remaining_salts.discard(salt_hex)
                dbs = salt_to_dbs[salt_hex]
                print(f"\n  [FOUND] salt={salt_hex} (Config.Cipher)")
                print(f"    enc_key={enc_key_hex}")
                print(f"    PID={pid}")
                print(f"    数据库: {', '.join(dbs)}")
                matched += 1
                break
    return matched


def _passphrase_matches_salt(passphrase, salt_hex, db_files):
    salt = bytes.fromhex(salt_hex)
    enc_key = hashlib.pbkdf2_hmac(
        "sha512", passphrase, salt, PBKDF2_ITERATIONS, dklen=32
    )
    for _rel, _path, _sz, salt_db, page1 in db_files:
        if salt_db == salt_hex and verify_enc_key(enc_key, page1):
            return True
    return False


def _apply_passphrase(passphrase, db_files, salt_to_dbs, key_map, remaining_salts, pid):
    """用一个 passphrase 试少量 salt；命中后再给剩余库做 PBKDF2。"""
    if not remaining_salts or not probable_32_byte_key(passphrase):
        return 0
    matched_probe = False
    for index, salt_hex in enumerate(list(remaining_salts)):
        if index >= 3:
            break
        if _passphrase_matches_salt(passphrase, salt_hex, db_files):
            matched_probe = True
            break
    if not matched_probe:
        return 0
    subset = {salt: salt_to_dbs[salt] for salt in remaining_salts}
    print(f"  [INFO] PID={pid} Config.Cipher passphrase 命中，开始 PBKDF2 派生")
    derived = derive_keys_from_passphrase(passphrase, db_files, subset, print)
    matched = 0
    for salt_hex, enc_key_hex in derived.items():
        if salt_hex not in remaining_salts:
            continue
        key_map[salt_hex] = enc_key_hex
        remaining_salts.discard(salt_hex)
        dbs = salt_to_dbs[salt_hex]
        print(f"\n  [FOUND] salt={salt_hex} (Config.Cipher passphrase)")
        print(f"    enc_key={enc_key_hex}")
        print(f"    PID={pid}")
        print(f"    数据库: {', '.join(dbs)}")
        matched += 1
    return matched


def _consume_cipher_blob(
    blob, db_files, salt_to_dbs, key_map, remaining_salts, pid, tried_passphrases
):
    """解码一个 blob。返回 (matched_salts, direct_candidates, passphrases_tried)。"""
    decoded = decode_config_cipher_blob(blob)
    if not decoded or not remaining_salts:
        return 0, 0, 0
    matched = 0
    direct = 0
    for enc_key_hex, embedded_salt in config_cipher_key_candidates(blob):
        direct += 1
        matched += _verify_direct_key_candidate(
            enc_key_hex,
            embedded_salt,
            db_files,
            salt_to_dbs,
            key_map,
            remaining_salts,
            pid,
        )
    tried = 0
    if remaining_salts and not matched:
        for passphrase in passphrase_candidates(decoded):
            if passphrase in tried_passphrases:
                continue
            tried_passphrases.add(passphrase)
            tried += 1
            matched += _apply_passphrase(
                passphrase, db_files, salt_to_dbs, key_map, remaining_salts, pid
            )
            if not remaining_salts:
                break
    return matched, direct, tried


def _scan_config_cipher(
    pid, regions, read_region, read_mem, db_files, salt_to_dbs, key_map, remaining_salts
):
    """微信 4.1+：定位 WCDB Config.Cipher，解码并校验密钥。"""
    needle_addresses = _find_bytes(regions, read_region, CONFIG_CIPHER_NAME)
    if not needle_addresses:
        print(f"[INFO] PID={pid} 未找到 Config.Cipher 字符串")
        return 0

    pair_patterns = [
        struct.pack("<Q", addr) + struct.pack("<Q", len(CONFIG_CIPHER_NAME))
        for addr in needle_addresses
    ]
    seen_configs = set()
    tried_passphrases = set()
    matched_salts = 0
    node_count = 0
    candidate_count = 0
    passphrase_tries = 0

    for base, data in _iter_region_data(regions, read_region):
        if not remaining_salts:
            break
        for pattern in pair_patterns:
            pos = data.find(pattern)
            while pos >= 0 and remaining_salts:
                qaddr = base + pos
                if qaddr < 0x10:
                    pos = data.find(pattern, pos + 1)
                    continue
                node = read_mem(qaddr - 0x10, 0x50)
                if not node or len(node) < 0x40:
                    pos = data.find(pattern, pos + 1)
                    continue
                if (
                    _u64_from(node, 0x10) not in needle_addresses
                    or _u64_from(node, 0x18) != len(CONFIG_CIPHER_NAME)
                ):
                    pos = data.find(pattern, pos + 1)
                    continue
                config_ptr = _u64_from(node, 0x28)
                if not (0x10000 <= config_ptr < _MAX_USER_ADDRESS):
                    pos = data.find(pattern, pos + 1)
                    continue
                if config_ptr in seen_configs:
                    pos = data.find(pattern, pos + 1)
                    continue
                seen_configs.add(config_ptr)
                node_count += 1

                header = read_mem(config_ptr, 0xB0)
                if not header or len(header) < 0x28:
                    pos = data.find(pattern, pos + 1)
                    continue
                for ptr_off, len_off in _CIPHER_BLOB_FIELDS:
                    if not remaining_salts:
                        break
                    if len_off + 8 > len(header):
                        continue
                    data_ptr = _u64_from(header, ptr_off)
                    data_len = _u64_from(header, len_off)
                    if not (
                        0 < data_len <= CONFIG_BLOB_MAX
                        and 0x10000 <= data_ptr < _MAX_USER_ADDRESS
                    ):
                        continue
                    blob = read_mem(data_ptr, int(data_len))
                    if not blob or len(blob) != data_len:
                        continue
                    matched, direct, tried = _consume_cipher_blob(
                        blob,
                        db_files,
                        salt_to_dbs,
                        key_map,
                        remaining_salts,
                        pid,
                        tried_passphrases,
                    )
                    candidate_count += direct
                    passphrase_tries += tried
                    matched_salts += matched
                pos = data.find(pattern, pos + 1)

    if matched_salts:
        print(
            f"[+] Config.Cipher 扫描命中 {matched_salts}/{len(salt_to_dbs)} salts "
            f"(pid={pid}, candidates={candidate_count}, "
            f"passphrases_tried={passphrase_tries})"
        )
    else:
        print(
            f"[INFO] Config.Cipher 扫描未验证到密钥 "
            f"(pid={pid}, nodes={node_count}, candidates={candidate_count}, "
            f"passphrases_tried={passphrase_tries})"
        )
    return matched_salts


def _scan_hex_regions(
    mem, regions, hex_re, db_files, salt_to_dbs, key_map, remaining_salts,
    pid, t0, total_bytes, all_hex_matches,
):
    """老版本 x'<hex>' 扫描。返回累计 hex 模式数量。"""
    scanned_bytes = 0
    chunks = 0
    for base, data in _iter_region_data(regions, lambda addr, size: _read_mem(mem, addr, size)):
        if not remaining_salts:
            break
        scanned_bytes += len(data)
        chunks += 1
        all_hex_matches += scan_memory_for_keys(
            data, hex_re, db_files, salt_to_dbs,
            key_map, remaining_salts, base, pid, print,
        )
        if chunks % 200 == 0:
            elapsed = time.time() - t0
            progress = scanned_bytes / total_bytes * 100 if total_bytes else 100
            print(
                f"  [{progress:.1f}%] {len(key_map)}/{len(salt_to_dbs)} salts matched, "
                f"{all_hex_matches} hex patterns, {elapsed:.1f}s"
            )
    return all_hex_matches


def extract_keys(db_dir, output_path, pid=None):
    """提取 Linux 微信数据库密钥。

    Args:
        db_dir: 微信数据库目录
        output_path: all_keys.json 输出路径
        pid: 可选，指定 PID（默认自动检测）

    Returns:
        dict: salt_hex -> enc_key_hex 映射
    """
    _check_permissions()

    print("=" * 60)
    print("  提取 Linux 微信数据库密钥（内存扫描）")
    print("=" * 60)

    db_files, salt_to_dbs = collect_db_files(db_dir)
    if not db_files:
        raise RuntimeError(f"在 {db_dir} 未找到可解密的 .db 文件")

    print(f"\n找到 {len(db_files)} 个数据库, {len(salt_to_dbs)} 个不同的 salt")
    for salt_hex, dbs in sorted(salt_to_dbs.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  salt {salt_hex}: {', '.join(dbs)}")

    pids = _get_pids() if pid is None else [(pid, 0)]

    hex_re = re.compile(rb"x'([0-9a-fA-F]{64,192})'")
    key_map = {}
    remaining_salts = set(salt_to_dbs.keys())
    all_hex_matches = 0
    announced_hex = False
    t0 = time.time()

    print("\n[*] 尝试 Config.Cipher 运行时扫描（微信 4.1+）...")
    for pid_val, _rss_kb in pids:
        try:
            regions = _get_readable_regions(pid_val)
        except PermissionError:
            print(f"[WARN] 无法读取 /proc/{pid_val}/maps，权限不足，跳过")
            continue
        except (FileNotFoundError, ProcessLookupError):
            print(f"[WARN] PID {pid_val} 已退出，跳过")
            continue

        total_bytes = sum(size for _, size in regions)
        total_mb = total_bytes / 1024 / 1024
        print(f"\n[*] 扫描 PID={pid_val} ({total_mb:.0f}MB, {len(regions)} 区域)")

        try:
            mem = open(f"/proc/{pid_val}/mem", "rb")
        except PermissionError:
            print(f"[WARN] 无法打开 /proc/{pid_val}/mem，权限不足，跳过")
            continue
        except (FileNotFoundError, ProcessLookupError):
            print(f"[WARN] PID {pid_val} 已退出，跳过")
            continue

        if not _is_wechat_process(pid_val):
            print(f"[WARN] PID {pid_val} 已不是微信进程，跳过")
            mem.close()
            continue

        def _read_region(base, size, _mem=mem):
            return _read_mem(_mem, base, size)

        try:
            _scan_config_cipher(
                pid_val,
                regions,
                _read_region,
                _read_region,
                db_files,
                salt_to_dbs,
                key_map,
                remaining_salts,
            )
            if remaining_salts:
                if not announced_hex:
                    if key_map:
                        print(
                            f"[INFO] Config.Cipher 部分命中: "
                            f"{len(key_map)}/{len(salt_to_dbs)} salts，"
                            "继续尝试老版本内存扫描补齐"
                        )
                    else:
                        print("[INFO] Config.Cipher 未命中，回退到老版本 x'<hex>' 内存扫描")
                    announced_hex = True
                all_hex_matches = _scan_hex_regions(
                    mem, regions, hex_re, db_files, salt_to_dbs,
                    key_map, remaining_salts, pid_val, t0, total_bytes,
                    all_hex_matches,
                )
        finally:
            mem.close()

        if not remaining_salts:
            print("\n[+] 所有密钥已找到，跳过剩余进程")
            break

    elapsed = time.time() - t0
    print(f"\n扫描完成: {elapsed:.1f}s, {len(pids)} 个进程, {all_hex_matches} hex 模式")

    if not key_map:
        raise RuntimeError(
            "未能从进程内存提取到密钥。微信 4.1+ 会先做 Config.Cipher 扫描"
            "（XOR 解码后，x'<hex>' 直接校验，32 字节材料再按 passphrase 做 PBKDF2），"
            "再回退老版本 x'<hex>' 内存扫描；请确认微信已登录、数据目录正确，"
            "并使用 sudo（或 CAP_SYS_PTRACE）运行。"
        )

    cross_verify_keys(db_files, salt_to_dbs, key_map, print)
    return save_results(db_files, salt_to_dbs, key_map, output_path, print)
