# Zero Trust WARP 工具箱

把 Cloudflare Zero Trust (WARP Teams) 一键提取为 **WireGuard** 或 **MASQUE** 节点，
并在本地以 SOCKS5 形式托管隧道。MASQUE 导出会同时生成可由 Shadowrocket 扫描导入的二维码；SOCKS5 必须在菜单中手动选择节点后启动。全程本机直连 Cloudflare 官方 API，凭据不经过任何第三方。

## 功能

- **OTP 登录**：本地复刻 Cloudflare Access 邮箱验证码登录，拿 Zero Trust Team Token
- **WireGuard 注册**：注册设备并导出 WireGuard / Surge / sing-box 配置和 Shadowrocket 二维码
- **MASQUE 注册**：注册（或切换）设备为 MASQUE 模式，导出 [usque](https://github.com/Diniboy1123/usque) 配置和 Shadowrocket `masque://` 二维码
- **隧道托管**：usque 转本地 SOCKS5（仅绑定 127.0.0.1），UDP/HTTP/3 优先、TCP/HTTP/2 自动回退
- **管理面板**：`./manage.sh` 一站式菜单

## 快速开始

```bash
git clone https://github.com/BlizzardSaber/zerotrust-warp-masque.git
cd zerotrust-warp-masque

./manage.sh            # 打开菜单
#  1) 提取 WireGuard 节点与二维码
#  2) 提取 MASQUE 节点与二维码
#  3) 选择 MASQUE 节点后，手动启动或停止本地 SOCKS5
#  4) 查看 SOCKS5 状态与当前所用节点信息
#  5) 查看已获取的节点及二维码位置
```

首次使用请安装二维码依赖：`python3 -m pip install -r requirements.txt`。此外需要 `openssl`（macOS/Linux 自带）和用于本地 MASQUE SOCKS5 的 [usque](https://github.com/Diniboy1123/usque/releases) 二进制。

## 文件说明

| 文件 | 作用 |
|---|---|
| `manage.sh` | 五项式管理面板（提取 WireGuard、提取 MASQUE、SOCKS5 控制、状态、节点查看） |
| `zt_login.py` | Zero Trust OTP 登录 → Team Token → WireGuard 注册导出 |
| `zerotrust2wg.py` | 用 Team Token 注册设备，导出 WireGuard/Surge/sing-box 配置 |
| `zt_masque.py` | 设备 MASQUE 化（注册/切换/回退/查询），导出 usque 配置 |
| `zt_new_run.py` | 非交互驱动：OTP 登录 → 注册全新设备 → MASQUE（配合 manage.sh 6） |
| `wg_probe.py` | WireGuard 端点连通性探测 |
| `out/`（本地生成） | 所有凭据与配置；`masque-nodes/` 含历史节点、二维码和导入链接，**已 gitignore，勿外传** |

## 代理客户端接入

WireGuard 的二维码为 `out/warp-wireguard-qr.png`；MASQUE 二维码为 `out/masque-nodes/*.png`。两者均可在 Shadowrocket 的扫码导入中使用。二维码和对应配置包含私钥，不能公开分享。

如需把某个 MASQUE 节点在本机作为 SOCKS5 使用：在菜单 3 选择节点并确认启动；再次进入菜单 3 可停止它。菜单 4 会显示运行状态、本地 SOCKS5 地址、当前 MASQUE 节点、远端地址、SNI、隧道 IP 和出口测试结果，不会输出私钥或令牌。

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
