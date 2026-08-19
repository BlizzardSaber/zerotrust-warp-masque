# Zero Trust WARP 工具箱

把 Cloudflare Zero Trust (WARP Teams) 一键提取为 **WireGuard** 或 **MASQUE** 节点，
并在本地以 SOCKS5 形式托管隧道。MASQUE 导出会同时生成可由 Shadowrocket 扫描导入的二维码；SOCKS5 必须在菜单中手动选择节点后启动。全程本机直连 Cloudflare 官方 API，凭据不经过任何第三方。

## 功能

- **OTP 登录**：本地复刻 Cloudflare Access 邮箱验证码登录，拿 Zero Trust Team Token
- **WireGuard 注册**：注册设备并导出 WireGuard / Surge / sing-box 配置
- **MASQUE 注册**：注册（或切换）设备为 MASQUE 模式，导出 [usque](https://github.com/Diniboy1123/usque) 配置和 Shadowrocket `masque://` 二维码
- **隧道托管**：usque 转本地 SOCKS5（仅绑定 127.0.0.1），UDP/HTTP/3 优先、TCP/HTTP/2 自动回退
- **管理面板**：`./manage.sh` 一站式菜单

## 快速开始

```bash
git clone https://github.com/BlizzardSaber/zerotrust-warp-masque.git
cd zerotrust-warp-masque

./manage.sh            # 打开菜单
# 11) 下载/更新 usque 二进制
#  6) 注册新 Zero Trust 设备（输入组织名 + 邮箱，去邮箱拿 6 位验证码，
#     另开终端执行: echo 验证码 > /tmp/zt_otp_code.txt）
#  1) 启动隧道（先 UDP 443，不通自动切 TCP 443）
#  5) 查看节点信息（含代理客户端表单的逐字段填法）
```

首次使用请安装二维码依赖：`python3 -m pip install -r requirements.txt`。此外需要 `openssl`（macOS/Linux 自带）+ [usque](https://github.com/Diniboy1123/usque/releases) 二进制（菜单 12 自动下载）。

## 文件说明

| 文件 | 作用 |
|---|---|
| `manage.sh` | 管理面板 / 命令行（start·stop·status·log·info） |
| `zt_login.py` | Zero Trust OTP 登录 → Team Token → WireGuard 注册导出 |
| `zerotrust2wg.py` | 用 Team Token 注册设备，导出 WireGuard/Surge/sing-box 配置 |
| `zt_masque.py` | 设备 MASQUE 化（注册/切换/回退/查询），导出 usque 配置 |
| `zt_new_run.py` | 非交互驱动：OTP 登录 → 注册全新设备 → MASQUE（配合 manage.sh 6） |
| `wg_probe.py` | WireGuard 端点连通性探测 |
| `out/`（本地生成） | 所有凭据与配置；`masque-nodes/` 含历史节点、二维码和导入链接，**已 gitignore，勿外传** |

## 代理客户端接入

MASQUE 节点导出后，使用菜单 1 查看节点。二维码位于 `out/masque-nodes/*.png`，可在 Shadowrocket 的扫码导入中使用。二维码和对应 `.txt` 链接包含私钥，不能公开分享。

如需把某个节点在本机作为 SOCKS5 使用：先在菜单 2 选择节点（此时不会启动代理），再在菜单 3 手动启动。字段对照见 `./manage.sh info`：

```
地址 162.159.197.2   端口 443   SNI zt-masque.cloudflareclient.com
私钥/公钥/子网IP ← out/warp-masque.json   MTU 1280   UDP转发开
HTTP2: 团队边缘建议开（UDP 被墙时 TCP 443 可用）；免费节点两者皆可
```

或在任意客户端里直接用本地 SOCKS5：`socks5, 127.0.0.1, 1080`。

## 已知网络行为（实测，2026-08）

- WireGuard 端口（2408/894/500/4500/1701 → 162.159.192-195）全被丢弃
- MASQUE 团队边缘 `162.159.197.2` 的 UDP/TCP 443 拦截**动态变化**，故 manage.sh 自动回退
- 免费边缘 `162.159.198.2` 支持 HTTP/2 (TCP)，团队边缘 TCP 备用端口同样全通

## 致谢与许可

- MASQUE 接入基于开源客户端 [usque](https://github.com/Diniboy1123/usque)（其 RESEARCH.md 提供了协议逆向细节）
- 仅供学习与个人合法网络接入使用；请遵守 Cloudflare 服务条款及当地法律。
