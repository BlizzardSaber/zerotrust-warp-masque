#!/usr/bin/env bash
# ============================================================
#  Zero Trust WARP 工具箱
#  用法:
#    ./manage.sh            # 交互菜单
#    ./manage.sh start|stop|status|info
# ============================================================
set -u
cd "$(dirname "$0")"

PY=.venv/bin/python; [ -x "$PY" ] || PY=python3
USQUE=./usque
DEFAULT_CFG=out/warp-masque.json
SELECTED_CFG=out/selected-masque-node.txt
PIDFILE=out/usque.pid
LOG=out/usque.log

c_green() { printf "\033[32m%s\033[0m\n" "$1"; }
c_red()   { printf "\033[31m%s\033[0m\n" "$1"; }
c_dim()   { printf "\033[2m%s\033[0m\n" "$1"; }

die() { c_red "✘ $1"; exit 1; }

# 默认使用最近导出的节点；在菜单中选择历史节点后，后续手动启动会使用所选节点。
current_cfg() {
    if [ -f "$SELECTED_CFG" ]; then
        local selected
        selected=$(head -n 1 "$SELECTED_CFG")
        case "$selected" in
            out/masque-nodes/*.json) [ -f "$selected" ] && { echo "$selected"; return; } ;;
        esac
    fi
    echo "$DEFAULT_CFG"
}

# ---------- 隧道控制 ----------

running() {
    [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

# 优先读取所选节点保存的 SNI；旧配置再按最近注册响应判断 team/free。
detect_sni() {
    local t="team"
    if [ -n "${CFG:-}" ] && [ -f "$CFG" ]; then
        local saved
        saved=$("$PY" -c "import json; print(json.load(open('$CFG')).get('sni', ''))" 2>/dev/null || true)
        [ -n "$saved" ] && { echo "$saved"; return; }
    fi
    if [ -f out/debug_masque_resp.json ]; then
        t=$("$PY" -c "import json;print((json.load(open('out/debug_masque_resp.json')).get('account') or {}).get('account_type','team'))" 2>/dev/null || echo team)
    fi
    case "$t" in
        *team*) echo "zt-masque.cloudflareclient.com" ;;
        *)      echo "consumer-masque.cloudflareclient.com" ;;
    esac
}

trace_test() {
    local out
    out=$(curl -s --max-time 15 --socks5-hostname 127.0.0.1:1080 \
        https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null \
        | grep -E "^(warp|ip|colo|loc)=")
    [ -n "$out" ] || return 1
    echo "$out" | sed "s/^/    /"
}

# 启动一次隧道尝试: $1 = 附加参数; 成功返回 0
launch() {
    local sni; sni=$(detect_sni)
    mkdir -p out
    nohup "$USQUE" -c "$CFG" socks -b 127.0.0.1 -p 1080 \
        --sni-address "$sni" $1 --always-reconnect > "$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 5
    if running && trace_test; then return 0; fi
    stop >/dev/null 2>&1
    return 1
}

start() {
    CFG=$(current_cfg)
    [ -x "$USQUE" ] || die "usque 不存在；请将 usque 放到项目目录后重试"
    [ -f "$CFG" ] || die "没有 MASQUE 节点；请先提取 MASQUE 节点"
    if running; then c_green "隧道已在运行 (pid $(cat "$PIDFILE"))"; exit 0; fi
    local mode="${1:-auto}"
    # 本网络对 162.159.197.x 的 TCP/UDP 拦截会动态变化，auto 模式两种都探测
    if [ "$mode" = "auto" ] || [ "$mode" = "udp" ]; then
        c_dim "尝试 HTTP/3 (UDP 443) ..."
        if launch ""; then ok "HTTP/3 (QUIC)"; return 0; fi
        [ "$mode" = "udp" ] && { fail; exit 1; }
    fi
    if [ "$mode" = "auto" ] || [ "$mode" = "tcp" ]; then
        c_dim "尝试 HTTP/2 (TCP 443) ..."
        if launch "--http2"; then ok "HTTP/2 (TCP)"; return 0; fi
    fi
    fail
    exit 1
}

ok() {
    c_green "✅ MASQUE 隧道已启动 [$1]"
    c_dim  "    SOCKS5  127.0.0.1:1080 (仅本机)"
    c_dim  "    日志    $LOG"
    c_dim  "    出口信息:"
    trace_test
}

fail() {
    c_red "❌ UDP 和 TCP 都连不上（网络对 162.159.197.x 的拦截又变化了）"
    c_dim "    可稍后重试，或检查网络是否允许 Cloudflare MASQUE 流量"
}

stop() {
    if running; then
        local pid; pid=$(cat "$PIDFILE")
        kill "$pid" 2>/dev/null
        sleep 1
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
        rm -f "$PIDFILE"
        c_green "✅ 已停止 (pid $pid)"
    else
        pkill -f "usque -c out/warp-masque" 2>/dev/null
        rm -f "$PIDFILE"
        c_dim "隧道本来就没在运行"
    fi
}

status() {
    if running; then
        c_green "● 隧道运行中 (pid $(cat "$PIDFILE"))"
        local cfg; cfg=$(current_cfg)
        if [ -f "$cfg" ]; then
            "$PY" - "$cfg" <<'EOF'
import json, sys
from pathlib import Path
cfg = json.load(open(sys.argv[1]))
print("  SOCKS5 地址 : 127.0.0.1:1080")
print(f"  当前节点    : {Path(sys.argv[1]).name}")
print(f"  MASQUE 端点 : {cfg.get('endpoint_v4', '?')}:443")
print(f"  SNI         : {cfg.get('sni', '自动识别')}")
print(f"  隧道 IPv4   : {cfg.get('ipv4', '?')}")
EOF
        fi
        echo "  出口信息:"
        trace_test || c_red "  隧道进程在，但出口测试失败（可能正在重连，稍后再试）"
    else
        c_red "○ 隧道未运行"
    fi
}

log() {
    [ -f "$LOG" ] || die "暂无日志"
    tail -n 30 "$LOG"
}

info() {
    local cfg; cfg=$(current_cfg)
    [ -f "$cfg" ] || die "没有 $cfg"
    "$PY" - "$cfg" <<'EOF'
import base64, json, subprocess, sys
cfg = json.load(open(sys.argv[1]))
pem = subprocess.run(["openssl", "ec", "-inform", "DER"],
                     input=base64.b64decode(cfg["private_key"]),
                     capture_output=True, check=True).stdout
spki = subprocess.run(["openssl", "ec", "-pubout", "-outform", "DER"],
                      input=pem, capture_output=True, check=True).stdout
server_b64 = next(iter(__import__("re").findall(r"[A-Za-z0-9+/]{60,}={0,2}", cfg["endpoint_pub_key"])), "")
print(f"""节点信息 ({sys.argv[1]})
  Endpoint v4 : {cfg['endpoint_v4']}:443 (UDP/HTTP3)
  Endpoint v6 : [{cfg['endpoint_v6']}]:443
  隧道内地址  : {cfg['ipv4']} / {cfg['ipv6']}
  设备 ID     : {cfg['id']}

填代理客户端表单用:
  地址    {cfg['endpoint_v4']}
  端口    443
  私钥    {cfg['private_key']}
  公钥    {server_b64}
  子网IP  {cfg['ipv4']}
  DNS     162.159.36.1
  MTU     1280
  SNI     zt-masque.cloudflareclient.com (Zero Trust) / consumer-masque.cloudflareclient.com (免费)
  HTTP2   关 (团队边缘无 TCP 回退; 免费节点可开)
  客户端公钥(备用) {base64.b64encode(spki).decode()}""")
EOF
}

select_node() {
    local -a nodes
    nodes=(out/masque-nodes/masque-*.json)
    [ -e "${nodes[0]}" ] || die "暂无已导出的 MASQUE 节点"
    echo "已导出的 MASQUE 节点："
    local i=1 node
    for node in "${nodes[@]}"; do
        echo "  $i) ${node##*/}"
        i=$((i + 1))
    done
    local n
    read -r -p "选择节点编号（直接回车取消）: " n
    [ -n "$n" ] || return 1
    case "$n" in *[!0-9]*) c_red "请输入编号"; return 1 ;; esac
    [ "$n" -ge 1 ] && [ "$n" -le "${#nodes[@]}" ] || { c_red "编号无效"; return 1; }
    printf '%s\n' "${nodes[$((n - 1))]}" > "$SELECTED_CFG"
    c_green "✅ 已选择 ${nodes[$((n - 1))]##*/}；尚未启动 SOCKS5。"
}

# ---------- 菜单 ----------

extract_wireguard() {
    "$PY" zt_login.py
}

extract_masque() {
    "$PY" zt_masque.py --new
}

socks_control() {
    if running; then
        c_green "SOCKS5 正在运行：127.0.0.1:1080"
        c_dim "当前节点：$(current_cfg)"
        read -r -p "输入 1 停止；直接回车返回：" action
        [ "$action" = "1" ] && stop
        return
    fi
    echo "请选择要启动为 SOCKS5 的 MASQUE 节点："
    select_node || return
    read -r -p "确认启动 127.0.0.1:1080？[Y/n] " answer
    case "${answer:-Y}" in
        Y|y) start ;;
        *) c_dim "已取消；未启动 SOCKS5。" ;;
    esac
}

show_nodes() {
    echo "WireGuard："
    if [ -f out/warp-wireguard.conf ]; then
        "$PY" zerotrust2wg.py --qr >/dev/null || c_red "  WireGuard 二维码生成失败"
        echo "  配置文件：out/warp-wireguard.conf"
        [ -f out/warp-wireguard-qr.png ] && echo "  导入二维码：out/warp-wireguard-qr.png"
    else
        echo "  暂无已提取的 WireGuard 节点"
    fi
    echo
    echo "MASQUE："
    "$PY" zt_masque.py --list
    if compgen -G 'out/masque-nodes/*.png' > /dev/null; then
        echo "  二维码目录：out/masque-nodes/"
    fi
    echo
    c_dim "二维码和配置均含私钥，请勿公开分享。"
}

menu() {
    while true; do
        echo
        echo "====== Zero Trust WARP 节点工具 ======"
        echo "  1) 提取 WireGuard 节点与二维码"
        echo "  2) 提取 MASQUE 节点与二维码"
        echo "  3) MASQUE SOCKS5：选择节点并启动/停止"
        echo "  4) 查看当前 SOCKS5 状态"
        echo "  5) 查看已获取的节点与二维码"
        echo "  0) 退出"
        read -r -p "选择: " n
        case "$n" in
            1) extract_wireguard ;;
            2) extract_masque ;;
            3) socks_control ;;
            4) status ;;
            5) show_nodes ;;
            0|q) exit 0 ;;
            *) c_dim "无效选项" ;;
        esac
    done
}

case "${1:-menu}" in
    start) start "${2:-auto}" ;;
    stop)  stop ;;
    status) status ;;
    log)   log ;;
    info)  info ;;
    menu)  menu ;;
    *)     echo "用法: $0 [start [auto|udp|tcp]|stop|status|info|menu]"; exit 1 ;;
esac
