#!/usr/bin/env python3
"""
zerotrust2wg — 用 Cloudflare Zero Trust (WARP Teams) 的 Team Token 注册设备，
导出可直接使用的 WireGuard 配置。

用法:
    python3 zerotrust2wg.py <team_token>     # 直接传 token
    python3 zerotrust2wg.py --clip           # 从剪贴板读 token (macOS pbpaste)

注意: Team Token (JWT) 只有 60 秒有效期，拿到后必须立刻运行。

输出文件（脚本同目录 out/ 下）:
    warp-account.json     账户完整信息（device id、license、reserved 等，妥善保存）
    warp-wireguard.conf   标准 WireGuard 配置
    warp-surge.txt        Surge 配置片段（含 client-id）
    warp-singbox.json     sing-box wireguard outbound
"""

import base64
import datetime
import json
import random
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.cloudflareclient.com/v0a2158/reg"
DNS = "162.159.36.1, 2606:4700:4700::1111"
PEER_FALLBACK = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
ENDPOINT_FALLBACK = "engage.cloudflareclient.com:2408"
HEADERS_BASE = {
    "User-Agent": "okhttp/3.12.1",
    "CF-Client-Version": "a-6.10-2158",
    "Content-Type": "application/json",
}


def gen_keypair():
    """用系统 openssl 生成 X25519 密钥对（macOS 自带）。"""
    pem = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "x25519"],
        capture_output=True, check=True).stdout
    priv_der = subprocess.run(
        ["openssl", "pkey", "-outform", "DER"],
        input=pem, capture_output=True, check=True).stdout
    pub_der = subprocess.run(
        ["openssl", "pkey", "-pubout", "-outform", "DER"],
        input=pem, capture_output=True, check=True).stdout
    # PKCS8/X25519 的 DER 尾部 32 字节即原始密钥
    return (base64.b64encode(priv_der[-32:]).decode(),
            base64.b64encode(pub_der[-32:]).decode())


def clean_token(raw):
    """兼容网页工具复制出的 'token=xxx' / '?token=xxx' / 带 URL 形式。"""
    t = raw.strip().strip('"').strip("'")
    for prefix in ("?token=", "token="):
        if t.startswith(prefix):
            t = t[len(prefix):]
    return t


def api_request(method, path, headers, body=None):
    req = urllib.request.Request(
        f"https://api.cloudflareclient.com/v0a2158{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def register(pub_key, token):
    """注册设备；Team Token 通过 Cf-Access-Jwt-Assertion 头生效。"""
    install_id = "".join(random.choices(string.ascii_letters + string.digits, k=22))
    fcm_token = f"{install_id}:APA91b" + "".join(
        random.choices(string.ascii_letters + string.digits, k=134))
    body = {
        "key": pub_key,
        "install_id": install_id,
        "fcm_token": fcm_token,
        "tos": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"),
        "model": "PC",
        "serial_number": install_id,
        "locale": "zh_CN",
    }
    headers = dict(HEADERS_BASE)
    if token:
        headers["Cf-Access-Jwt-Assertion"] = token

    last_err = None
    for attempt in range(3):  # 偶发 1015 限流时重试
        try:
            return api_request("POST", "/reg", headers, body)
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            if "1015" in detail and attempt < 2:
                last_err = f"HTTP {e.code}: {detail}"
                print(f"  被限流(error 1015)，10 秒后重试 ({attempt + 1}/3) ...")
                time.sleep(10)
                continue
            raise TeamTokenError(e.code, detail) from None
        except urllib.error.URLError as e:
            raise SystemExit(f"\n网络错误: {e.reason}")
    raise TeamTokenError(0, last_err or "unknown")


def delete_device(device_id, device_token):
    """删除误注册的 free 设备，避免在账户里留垃圾。"""
    try:
        api_request("DELETE", f"/reg/{device_id}", {
            **HEADERS_BASE, "Authorization": f"Bearer {device_token}"})
        print(f"  已自动删除误注册的 free 设备 {device_id}")
    except Exception:
        print(f"  （自动清理失败，可忽略）")


class TeamTokenError(Exception):
    def __init__(self, code, detail):
        self.code = code
        self.detail = detail


def pick_addresses(resp):
    addr = ((resp.get("config") or {}).get("interface") or {}).get("addresses") or {}
    v4, v6 = addr.get("v4"), addr.get("v6")
    if not v4:  # 兼容旧版响应的顶层结构
        for a in resp.get("addresses", []):
            v4 = v4 or a.get("v4")
            v6 = v6 or a.get("v6")
    return v4, v6


def pick_peer(resp):
    peers = ((resp.get("config") or {}).get("peers")
             or resp.get("peers") or [])
    for p in peers:
        ep = p.get("endpoint") or {}
        # v4/v6 的端口可能是占位的 :0，host 才是可用端点
        endpoint = ep.get("host") or ENDPOINT_FALLBACK
        return p.get("public_key") or PEER_FALLBACK, endpoint
    return PEER_FALLBACK, ENDPOINT_FALLBACK


def validate_team_or_cleanup(resp):
    """确认注册到的是 Zero Trust team；若是 free(未生效)则自动删设备并退出。"""
    acct = resp.get("account", {})
    acct_type = acct.get("account_type", "")
    if "team" in acct_type.lower():
        return acct
    print("\n[!] Token 未生效：注册到的是 free 账户而不是你的 Zero Trust。"
          "\n    最常见原因是 token 已过 60 秒有效期。")
    if resp.get("id") and resp.get("token"):
        delete_device(resp["id"], resp["token"])
    raise SystemExit("请重新获取 token 后立刻运行。")


def generate_wireguard_qr(out):
    """为当前 WireGuard 配置生成 Shadowrocket 可扫描的二维码。"""
    conf = out / "warp-wireguard.conf"
    if not conf.exists():
        raise SystemExit("未找到 out/warp-wireguard.conf，无法生成二维码。")
    text = conf.read_text()
    # 兼容本功能加入前生成的旧配置：把账户里保存的 client-id 写为
    # Shadowrocket 需要的 Reserved 字段，再编码二维码。
    if "\nReserved =" not in text:
        account_file = out / "warp-account.json"
        if account_file.exists():
            reserved = json.loads(account_file.read_text()).get("reserved") or []
            if reserved:
                text = text.replace(
                    "PersistentKeepalive = 25\n",
                    "PersistentKeepalive = 25\nReserved = " +
                    ", ".join(str(b) for b in reserved) + "\n")
                conf.write_text(text)
    try:
        import qrcode
    except ImportError:
        raise SystemExit("缺少二维码组件。请执行: python3 -m pip install -r requirements.txt")
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,
                       box_size=10, border=4)
    qr.add_data(text)
    qr.make(fit=True)
    qr.make_image(fill_color="black", back_color="white").save(
        out / "warp-wireguard-qr.png")


def write_outputs(resp, priv, pub):
    """把注册结果写成 4 个配置文件（供 zerotrust2wg / zt_login 共用）。"""
    acct = resp.get("account", {})
    acct_type = acct.get("account_type", "")

    v4, v6 = pick_addresses(resp)
    peer_pub, endpoint = pick_peer(resp)
    cid = (resp.get("config") or {}).get("client_id")
    reserved = list(base64.b64decode(cid)) if cid else []
    reserved_slash = "/".join(str(b) for b in reserved)

    out = Path(__file__).resolve().parent / "out"
    out.mkdir(exist_ok=True)

    (out / "warp-account.json").write_text(json.dumps({
        "device_id": resp.get("id"),
        "device_token": resp.get("token"),
        "account_id": acct.get("id"),
        "account_type": acct_type,
        "license": acct.get("license"),
        "private_key": priv,
        "public_key": pub,
        "addresses": {"v4": v4, "v6": v6},
        "peer_public_key": peer_pub,
        "endpoint": endpoint,
        "reserved": reserved,
        "created_at": datetime.datetime.now().isoformat(timespec="seconds"),
    }, indent=2, ensure_ascii=False))

    lines = [
        "[Interface]",
        f"PrivateKey = {priv}",
        f"Address = {v4}/32" + (f", {v6}/128" if v6 else ""),
        f"DNS = {DNS}",
        "MTU = 1280",
        "",
        "[Peer]",
        f"PublicKey = {peer_pub}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        f"Endpoint = {endpoint}",
        "PersistentKeepalive = 25",
        f"Reserved = {', '.join(str(b) for b in reserved)}",
        "",
        "# Cloudflare WARP 需要 Reserved/client-id；请使用支持该字段的客户端。",
    ]
    (out / "warp-wireguard.conf").write_text("\n".join(lines) + "\n")

    surge = [
        "[Proxy]",
        "WARP = wireguard, section-name=Cloudflare, test-url=http://cp.cloudflare.com/generate_204",
        "",
        "[WireGuard Cloudflare]",
        f"private-key = {priv}",
        f"self-ip = {v4}",
    ]
    if v6:
        surge.append(f"self-ip-v6 = {v6}")
    surge += [
        f"dns-server = {DNS}",
        "mtu = 1280",
        f"peer = (public-key = {peer_pub}, allowed-ips = \"0.0.0.0/0, ::/0\", "
        f"endpoint = {endpoint}, client-id = {reserved_slash})",
    ]
    (out / "warp-surge.txt").write_text("\n".join(surge) + "\n")

    host, port = endpoint.rsplit(":", 1)
    singbox = {
        "type": "wireguard",
        "tag": "warp-out",
        "server": host,
        "server_port": int(port),
        "local_address": [f"{v4}/32"] + ([f"{v6}/128"] if v6 else []),
        "private_key": priv,
        "peer_public_key": peer_pub,
        "reserved": reserved,
        "mtu": 1280,
    }
    (out / "warp-singbox.json").write_text(
        json.dumps(singbox, indent=2, ensure_ascii=False) + "\n")

    generate_wireguard_qr(out)

    print(f"""
Zero Trust 注册成功 ✔  配置已写入 {out}/

  设备 ID:    {resp.get('id')}
  账户类型:   {acct_type}
  IPv4/IPv6:  {v4} / {v6}
  Endpoint:   {endpoint}
  Reserved:   {reserved_slash}

文件说明:
  warp-wireguard.conf  标准 WireGuard 配置（官方客户端不认 reserved 字段）
  warp-surge.txt       Surge 片段，含 client-id，直接粘贴即用
  warp-singbox.json    sing-box wireguard outbound
  warp-wireguard-qr.png Shadowrocket 扫码导入二维码（含私钥，勿外传）
  warp-account.json    账户信息存档（含私钥，勿外传）

设备会出现在 Zero Trust 后台 Settings → WARP Client → Devices 列表里。
验证: 走 WARP 出口访问 https://www.cloudflare.com/cdn-cgi/trace ，
      显示 warp=on / warp=plus 即成功。
""")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--qr":
        generate_wireguard_qr(Path(__file__).resolve().parent / "out")
        print("WireGuard 二维码已生成: out/warp-wireguard-qr.png")
        return
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    arg = sys.argv[1]
    if arg in ("--clip", "-c"):
        token = clean_token(subprocess.run(
            ["pbpaste"], capture_output=True, check=True).stdout.decode())
    else:
        token = clean_token(arg)

    print("[1/3] 生成 X25519 密钥对 ...")
    priv, pub = gen_keypair()

    print("[2/3] 调用 Cloudflare API 注册 Zero Trust 设备（Token 需在 60 秒有效期内）...")
    try:
        resp = register(pub, token)
    except TeamTokenError as e:
        print(f"\n注册失败: HTTP {e.code}\n{e.detail[:500]}")
        if e.code in (401, 403):
            print("\nToken 无效或已过期（只有 60 秒寿命）。"
                  "请回网页重新拿一个新 token，复制后立刻重跑本脚本"
                  "（可用 --clip 直接读剪贴板）。")
        sys.exit(2)

    validate_team_or_cleanup(resp)

    print("[3/3] 生成配置文件 ...")
    write_outputs(resp, priv, pub)


if __name__ == "__main__":
    main()
