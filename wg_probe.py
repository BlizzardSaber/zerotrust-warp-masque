#!/usr/bin/env python3
"""
wg_probe — 对 WARP 端点做真实 WireGuard 握手探测（不需要管理员权限）。

原理: 用注册设备时的密钥对构造 Noise_IK Handshake Initiation (type 1) 发到
端点 UDP 端口；若收到 Handshake Response (type 2)，说明:
  1) UDP 链路可达  2) 端点正确  3) Cloudflare 接受我们的公钥（设备注册有效）
比 ICMP ping 准确：WARP 是 UDP 服务，ping 不通不代表节点不可用。

用法: .venv/bin/python wg_probe.py [host:port ...]   # 缺省测内置端点列表
"""

import hashlib
import hmac
import json
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"

ACCOUNT = Path(__file__).resolve().parent / "out" / "warp-account.json"


def H(data):
    return hashlib.blake2s(data).digest()


def MAC(key, data):
    return hmac.new(key, data, hashlib.blake2s).digest()


def tai64n():
    now = time.time()
    secs = 0x400000000000000A + int(now)
    nanos = int((now % 1) * 1e9)
    return struct.pack(">QI", secs, nanos)


def build_initiation(static_priv_bytes, server_pub_b64):
    server_pub = __import__("base64").b64decode(server_pub_b64)
    epriv = X25519PrivateKey.generate()
    epub = epriv.public_key().public_bytes_raw()

    c = H(CONSTRUCTION)
    h = H(c + IDENTIFIER)
    h = H(h + server_pub)
    h = H(h + epub)
    c = MAC(c, epub)
    k = MAC(c, b"\x01")
    static_pub = X25519PrivateKey.from_private_bytes(
        static_priv_bytes).public_key().public_bytes_raw()
    enc_static = ChaCha20Poly1305(k).encrypt(b"\x00" * 12, static_pub, h)
    h = H(h + enc_static)
    ss = epriv.exchange(X25519PublicKey.from_public_bytes(server_pub))
    c = MAC(c, ss)
    k = MAC(c, b"\x01")
    enc_ts = ChaCha20Poly1305(k).encrypt(b"\x00" * 12, tai64n(), h)
    h = H(h + enc_ts)

    sender_index = struct.unpack("<I", __import__("os").urandom(4))[0]
    msg = struct.pack("<II", 1, sender_index) + epub + enc_static + enc_ts
    mac1 = MAC(H(LABEL_MAC1 + server_pub), msg)[:16]
    return msg + mac1 + b"\x00" * 16


def probe(target, packet, timeout=4.0):
    host, port = target.rsplit(":", 1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, (host, int(port)))
        data, _ = s.recvfrom(128)
        t = struct.unpack("<I", data[:4])[0]
        if t == 2:
            return "OK (收到握手响应, 端点可用)"
        if t == 3:
            return "COOKIE (服务器繁忙要求cookie, 端点可达)"
        return f"? 收到未知类型 {t}"
    except socket.timeout:
        return "超时 (无响应)"
    except OSError as e:
        return f"错误 {e}"
    finally:
        s.close()


def main():
    acct = json.loads(ACCOUNT.read_text())
    priv = __import__("base64").b64decode(acct["private_key"])
    server_pub = acct.get("peer_public_key") or \
        "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    packet = build_initiation(priv, server_pub)

    targets = sys.argv[1:] or [
        "198.18.9.147:2408",           # 系统 fake-IP (经 Surge 路由)
        "162.159.192.1:2408", "162.159.192.5:2408", "162.159.192.10:2408",
        "162.159.193.1:2408", "162.159.193.5:2408", "162.159.193.10:2408",
        "162.159.194.1:2408", "162.159.194.10:2408",
        "162.159.195.1:2408", "162.159.195.5:2408", "162.159.195.10:2408",
        "162.159.192.1:894", "162.159.192.1:500",
        "162.159.192.1:4500", "162.159.192.1:1701",
    ]
    print(f"设备公钥已注册端点探测（WireGuard 真实握手, 超时 4s）:\n")
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(lambda t: (t, probe(t, packet)), targets))
    for t, r in results:
        print(f"  {t:<28} {r}")
    ok = [t for t, r in results if r.startswith("OK")]
    print(f"\n可用端点: {len(ok)}/{len(targets)}")
    if ok:
        print("建议把配置里的 endpoint 换成上面任一 OK 的地址。")


if __name__ == "__main__":
    main()
