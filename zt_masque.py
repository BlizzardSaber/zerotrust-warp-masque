#!/usr/bin/env python3
"""
zt_masque.py — 把 Cloudflare Zero Trust (WARP) 设备切换到 MASQUE 模式，
导出 usque（开源 WARP MASQUE 客户端）可直接使用的 config.json。

原理（与官方客户端 warp-cli "tunnel protocol set MASQUE" 同一条 API）:
    PATCH https://api.cloudflareclient.com/v0a4471/reg/<device_id>
    Authorization: Bearer <device_token>
    {"key": "<P-256 公钥 SPKI DER 的 base64>", "key_type": "secp256r1",
     "tunnel_type": "masque"}
切换后设备改用 HTTP/3 (QUIC, UDP 443, cf-connect-ip) 接入，
对网络而言就是普通 HTTPS/QUIC 流量，端口也和网页流量一致。

用法:
    .venv/bin/python zt_masque.py            # 把 out/warp-account.json 里的 Zero Trust
                                             # 设备切换为 MASQUE（不影响原 WireGuard 密钥，
                                             # --revert 随时切回）
    .venv/bin/python zt_masque.py --revert   # 切回 WireGuard，原 Surge 配置继续可用
    .venv/bin/python zt_masque.py --check    # 只查看设备当前状态，不做修改
    .venv/bin/python zt_masque.py --free     # 注册一台免费 WARP 设备并开 MASQUE
                                             # （不碰 Zero Trust，可当免费落地/测试）
    .venv/bin/python zt_masque.py --new [组织名] [邮箱]
                                             # OTP 登录拿新 team token，注册全新 Zero Trust
                                             # 设备并直接开 MASQUE（不动现有设备）

输出:
    out/warp-masque.json        usque config 格式（含 P-256 私钥，勿外传）
    out/debug_masque_resp.json  API 原始响应（排查用）

使用节点（usque 二进制: github.com/Diniboy1123/usque/releases）:
    usque -c out/warp-masque.json --sni-address zt-masque.cloudflareclient.com socks
    → 本地 SOCKS5 127.0.0.1:1080（Zero Trust 设备用 zt-masque SNI，
      免费设备用 consumer-masque.cloudflareclient.com）
"""

import base64
import datetime
import json
import random
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent))
from zerotrust2wg import validate_team_or_cleanup  # noqa: E402  (--new 模式复用 team 校验)

API = "https://api.cloudflareclient.com/v0a4471"
HEADERS = {
    "User-Agent": "WARP for Android",
    "CF-Client-Version": "a-6.35-4471",
    "Content-Type": "application/json; charset=UTF-8",
    "Connection": "Keep-Alive",
}
OUT_DIR = Path(__file__).resolve().parent / "out"
NODES_DIR = OUT_DIR / "masque-nodes"
ACCOUNT_JSON = OUT_DIR / "warp-account.json"
DEFAULT_EP_V4 = "162.159.198.1"
DEFAULT_EP_V6 = "2606:4700:103::"
EP_H2_V4 = "162.159.198.2"
SNI_TEAM = "zt-masque.cloudflareclient.com"
SNI_FREE = "consumer-masque.cloudflareclient.com"


def _run(cmd, input=None):
    return subprocess.run(cmd, input=input, capture_output=True,
                          check=True).stdout


def gen_ec_keypair():
    """生成 P-256 密钥对。

    返回 (sec1_priv_b64, spki_pub_b64):
      sec1_priv_b64 — SEC1 DER 私钥的 base64，写进 usque config 的 private_key
      spki_pub_b64  — SPKI DER 公钥的 base64，PATCH 上传给 Cloudflare
    """
    pem = _run(["openssl", "ecparam", "-name", "prime256v1",
                "-genkey", "-noout"])
    sec1_der = _run(["openssl", "ec", "-outform", "DER"], input=pem)
    spki_der = _run(["openssl", "ec", "-pubout", "-outform", "DER"], input=pem)
    return (base64.b64encode(sec1_der).decode(),
            base64.b64encode(spki_der).decode())


def api(method, path, token=None, body=None):
    headers = dict(HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{API}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def register_device(jwt=None):
    """注册新设备（先按 WireGuard 注册，拿到 device id/token，再 PATCH 成 masque）。"""
    body = {
        # 随机 32 字节伪装 X25519 公钥，注册后马上会被 PATCH 覆盖
        "key": base64.b64encode(random.randbytes(32)).decode(),
        "install_id": "",  # usque 的注册请求 install_id 留空
        "fcm_token": "",
        "tos": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"),
        "model": "PC",
        "serial_number": "".join(random.choices(
            "0123456789abcdef", k=16)),
        "os_version": "",
        "key_type": "curve25519",
        "tunnel_type": "wireguard",
        "locale": "zh_CN",
    }
    headers = {}
    if jwt:
        headers["CF-Access-Jwt-Assertion"] = jwt
    # 带 JWT 头注册，这里单独发，避免 api() 签名耦合
    req = urllib.request.Request(
        f"{API}/reg", data=json.dumps(body).encode(),
        headers={**HEADERS, **headers}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def enroll_masque(device_id, device_token, spki_pub_b64, name=None):
    body = {
        "key": spki_pub_b64,
        "key_type": "secp256r1",
        "tunnel_type": "masque",
    }
    if name:
        body["name"] = name
    return api("PATCH", f"/reg/{device_id}", token=device_token, body=body)


def revert_wireguard(device_id, device_token, wg_pub_b64):
    """切回 WireGuard：把保存的 X25519 公钥 PATCH 回去。"""
    return api("PATCH", f"/reg/{device_id}", token=device_token, body={
        "key": wg_pub_b64,
        "key_type": "curve25519",
        "tunnel_type": "wireguard",
    })


def host_only(ep):
    """'162.159.198.1:0' -> '162.159.198.1'；'[2606:4700:103::]:0' -> '2606:4700:103::'。"""
    if not ep:
        return ""
    if ep.startswith("["):
        ep = ep[1:].split("]", 1)[0]
    if ep.endswith(":0"):  # API 返回的端口是占位 :0，实际端口由 usque 决定(443)
        ep = ep[:-2]
    return ep


def pick_addresses(resp):
    addr = ((resp.get("config") or {}).get("interface") or {}).get("addresses") or {}
    return addr.get("v4", ""), addr.get("v6", "")


def save_debug(resp):
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "debug_masque_resp.json").write_text(
        json.dumps(resp, indent=2, ensure_ascii=False))


def build_and_save(resp, priv_b64, access_token):
    peers = ((resp.get("config") or {}).get("peers") or [])
    peer = peers[0] if peers else {}
    ep = peer.get("endpoint") or {}
    v4, v6 = pick_addresses(resp)
    acct = resp.get("account", {})
    is_team = "team" in (acct.get("account_type") or "").lower()

    cfg = {
        "private_key": priv_b64,
        "endpoint_v4": host_only(ep.get("v4")) or DEFAULT_EP_V4,
        "endpoint_v6": host_only(ep.get("v6")) or DEFAULT_EP_V6,
        "endpoint_h2_v4": EP_H2_V4,
        "endpoint_h2_v6": "",
        "endpoint_pub_key": peer.get("public_key", ""),
        "id": resp.get("id"),
        "access_token": access_token,
        "ipv4": v4,
        "ipv6": v6,
    }
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "warp-masque.json").write_text(
        json.dumps(cfg, indent=2, ensure_ascii=False) + "\n")

    sni = SNI_TEAM if is_team else SNI_FREE
    # Shadowrocket 的 MASQUE 分享格式。二维码内含私钥和 access token 等敏感
    # 凭据，导出的 PNG/链接只能交给受信任的设备，不能公开分享。
    node_name = f"masque-{cfg['id'] or 'unknown'}"
    node_cfg = dict(cfg, sni=sni)
    NODES_DIR.mkdir(exist_ok=True)
    node_json = NODES_DIR / f"{node_name}.json"
    node_json.write_text(json.dumps(node_cfg, indent=2, ensure_ascii=False) + "\n")
    link = "masque://{}:443?{}#{}".format(
        cfg["endpoint_v4"],
        urlencode({
            "publicKey": cfg["endpoint_pub_key"],
            "privateKey": cfg["private_key"],
            "ip": cfg["ipv4"],
            "dns": "162.159.36.1",
            "mtu": "1280",
            "sni": sni,
            "udp": "1",
            "cc": "cubic",
            "keepalive": "30",
            "flag": "CDN",
        }),
        node_name,
    )
    link_file = NODES_DIR / f"{node_name}.txt"
    link_file.write_text(link + "\n")
    try:
        import qrcode
    except ImportError:
        sys.exit("缺少二维码组件。请执行: python3 -m pip install -r requirements.txt")
    qr_file = NODES_DIR / f"{node_name}.png"
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,
                       box_size=10, border=4)
    qr.add_data(link)
    qr.make(fit=True)
    qr.make_image(fill_color="black", back_color="white").save(qr_file)
    print(f"""
MASQUE 节点已导出到 {OUT_DIR / 'warp-masque.json'} ✔
Shadowrocket 导入二维码: {qr_file} ✔
节点链接（含敏感凭据）: {link_file}

  设备 ID:     {cfg['id']}
  账户类型:    {acct.get('account_type', '?')}{'（Zero Trust，用 zt-masque SNI）' if is_team else '（免费，用 consumer-masque SNI）'}
  Endpoint:    {cfg['endpoint_v4']}:443 (UDP/HTTP/3){', ' + cfg['endpoint_v6'] if cfg['endpoint_v6'] else ''}
  隧道内地址:  {cfg['ipv4']} / {cfg['ipv6']}

未自动启动本地 SOCKS5。请在 ./manage.sh 菜单中先查看/选择节点，再手动启动。

验证: 挂上代理访问 https://www.cloudflare.com/cdn-cgi/trace 显示 warp=on 即成功。
""")
    return cfg


def cmd_list():
    """列出已导出的节点；不启动任何本地代理。"""
    if not NODES_DIR.exists():
        print("暂无已导出的 MASQUE 节点。")
        return
    nodes = sorted(NODES_DIR.glob("masque-*.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    if not nodes:
        print("暂无已导出的 MASQUE 节点。")
        return
    for i, path in enumerate(nodes, 1):
        cfg = json.loads(path.read_text())
        print(f"{i}) {path.name}: {cfg.get('endpoint_v4', '?')}:443  "
              f"IP {cfg.get('ipv4', '?')}  SNI {cfg.get('sni', '?')}")


def load_account():
    if not ACCOUNT_JSON.exists():
        sys.exit(f"未找到 {ACCOUNT_JSON}。先跑一次 zt_login.py，"
                 "或用 --free / --new 注册新设备。")
    return json.loads(ACCOUNT_JSON.read_text())


def cmd_switch():
    """默认: 现有 Zero Trust 设备切换为 MASQUE。"""
    acct = load_account()
    print("[1/2] 生成 P-256 密钥对 ...")
    priv_b64, pub_b64 = gen_ec_keypair()
    print(f"[2/2] PATCH 设备 {acct['device_id']} 为 masque 模式 ...")
    try:
        resp = enroll_masque(acct["device_id"], acct["device_token"], pub_b64)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        sys.exit(f"PATCH 失败: HTTP {e.code}\n{detail[:800]}\n"
                 "（若 Zero Trust 后台把 Tunnel Protocol 强制为 WireGuard，"
                 "需管理员放开或改用 --new）")
    save_debug(resp)
    build_and_save(resp, priv_b64, acct["device_token"])
    print("原 WireGuard 密钥未动，随时可用 --revert 切回（Surge 配置不变）。")


def cmd_revert():
    acct = load_account()
    wg_pub = acct.get("public_key")
    if not wg_pub:
        sys.exit("warp-account.json 里没有 public_key，无法切回。")
    print(f"PATCH 设备 {acct['device_id']} 回 wireguard 模式 ...")
    try:
        resp = revert_wireguard(acct["device_id"], acct["device_token"], wg_pub)
    except urllib.error.HTTPError as e:
        sys.exit(f"切回失败: HTTP {e.code}\n{e.read().decode(errors='replace')[:500]}")
    save_debug(resp)
    print("已切回 WireGuard ✔  原 warp-wireguard.conf / Surge 配置可继续使用。")
    print("（可用 --check 确认 tunnel_type 已变回 wireguard）")


def cmd_check():
    acct = load_account()
    try:
        resp = api("GET", f"/reg/{acct['device_id']}",
                   token=acct["device_token"])
    except urllib.error.HTTPError as e:
        sys.exit(f"查询失败: HTTP {e.code}\n{e.read().decode(errors='replace')[:500]}")
    keep = {k: resp.get(k) for k in
            ("id", "model", "name", "key_type", "tunnel_type", "created",
             "updated")}
    keep["account"] = {k: (resp.get("account") or {}).get(k)
                       for k in ("account_type", "license", "organization")}
    keep["policy"] = resp.get("policy")
    print(json.dumps(keep, indent=2, ensure_ascii=False))


def cmd_free():
    print("[1/3] 注册免费 WARP 设备（无需登录）...")
    resp = register_device()
    token = resp.get("token")
    if not resp.get("id") or not token:
        sys.exit(f"注册返回异常:\n{json.dumps(resp, indent=2)[:500]}")
    print(f"      设备 {resp['id']} ({(resp.get('account') or {}).get('account_type', '?')})")
    print("[2/3] 生成 P-256 密钥对并 PATCH 为 masque ...")
    priv_b64, pub_b64 = gen_ec_keypair()
    resp = enroll_masque(resp["id"], token, pub_b64)
    save_debug(resp)
    print("[3/3] 导出 usque 配置 ...")
    build_and_save(resp, priv_b64, token)


def cmd_new():
    org = (sys.argv[2] if len(sys.argv) > 2
           else input("组织名 (xxx.cloudflareaccess.com 里的 xxx): ").strip())
    email = (sys.argv[3] if len(sys.argv) > 3 else input("登录邮箱: ").strip())

    from zt_login import AccessLogin, find_token
    a = AccessLogin(org)
    a.start()
    print("提交邮箱，请查收一次性验证码 ...")
    _, html1 = a.submit_email(email)
    if not a.parse_code_form(html1):
        sys.exit("未解析到验证码表单，稍后再试（注意 OTP 发码限频）。")
    code = input("输入验证码: ").strip()
    final_url, final_html = a.submit_code(code)
    jwt = find_token(a, final_url, final_html)
    if not jwt:
        sys.exit("未能提取 team token。")

    print("[1/3] 用 team token 注册全新 Zero Trust 设备 ...")
    resp = register_device(jwt)
    validate_team_or_cleanup(resp)
    token = resp.get("token")
    print("[2/3] 生成 P-256 密钥对并 PATCH 为 masque ...")
    priv_b64, pub_b64 = gen_ec_keypair()
    resp = enroll_masque(resp["id"], token, pub_b64)
    save_debug(resp)
    print("[3/3] 导出 usque 配置 ...")
    build_and_save(resp, priv_b64, token)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode in ("", "--switch"):
        cmd_switch()
    elif mode == "--revert":
        cmd_revert()
    elif mode == "--check":
        cmd_check()
    elif mode == "--free":
        cmd_free()
    elif mode == "--new":
        cmd_new()
    elif mode == "--list":
        cmd_list()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
