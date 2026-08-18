#!/usr/bin/env bash
# ============================================================
#  Zero Trust WARP 工具箱 — MASQUE 隧道管理面板
#  用法:
#    ./manage.sh            # 交互菜单
#    ./manage.sh start      # 直接启动隧道
#    ./manage.sh stop|status|log|info|menu
# ============================================================
set -u
cd "$(dirname "$0")"

PY=.venv/bin/python; [ -x "$PY" ] || PY=python3
USQUE=./usque
CFG=out/warp-masque.json
PIDFILE=out/usque.pid
LOG=out/usque.log

c_green() { printf "\033[32m%s\033[0m\n" "$1"; }
c_red()   { printf "\033[31m%s\033[0m\n" "$1"; }
c_dim()   { printf "\033[2m%s\033[0m\n" "$1"; }

die() { c_red "✘ $1"; exit 1; }

# ---------- 隧道控制 ----------

running() {
    [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

# 根据最近一次注册响应判断 team/free，自动选 SNI
detect_sni() {
    local t="team"
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
    [ -x "$USQUE" ] || die "usque 不存在，先跑菜单 11 下载（或手动放到本目录）"
    [ -f "$CFG" ] || die "没有 $CFG，先用菜单 6/7/10 注册设备"
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
    c_dim "    可稍后重试，或用菜单 3 复测；也可把流量经 Surge TUN 代理链转发"
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
    [ -f "$CFG" ] || die "没有 $CFG"
    "$PY" - "$CFG" <<'EOF'
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

# ---------- 设备注册 ----------

reg_new() {
    local org email
    read -r -p "组织名 (xxx.cloudflareaccess.com 的 xxx，默认 blizzardsaber): " org
    org=${org:-blizzardsaber}
    read -r -p "登录邮箱: " email
    [ -n "$email" ] || die "邮箱不能为空"
    rm -f /tmp/zt_otp_code.txt
    "$PY" zt_new_run.py "$org" "$email" /tmp/zt_otp_code.txt
}

reg_new_bg() {
    # 后台跑 reg_new 的流程：发码后提示用户输码写文件，前端进程轮询
    echo
    c_dim "提示: 验证码邮件发出后，再开一个终端执行:"
    c_dim "  echo 验证码 > /tmp/zt_otp_code.txt"
    reg_new
}

switch_masque() {
    "$PY" zt_masque.py
    c_dim "提示: 切换后如隧道在跑，请 stop 再 start 以加载新配置"
}

revert_wg()      { "$PY" zt_masque.py --revert; }
check_device()   { "$PY" zt_masque.py --check; }
reg_free()       { "$PY" zt_masque.py --free; }

dl_usque() {
    local os arch url
    os=$(uname -s | tr "[:upper:]" "[:lower:]")
    case $(uname -m) in
        arm64|aarch64) arch=arm64 ;;
        x86_64)        arch=amd64 ;;
        *) die "不支持的架构 $(uname -m)" ;;
    esac
    echo "下载 usque ($os/$arch) ..."
    url=$(curl -s "https://api.github.com/repos/Diniboy1123/usque/releases/latest" \
        | "$PY" - "os=$os" "arch=$arch" <<'EOF'
import json, sys
kv = dict(a.split("=", 1) for a in sys.argv[1:])
for a in json.load(sys.stdin).get("assets", []):
    if a["name"].endswith(f"_{kv['os']}_{kv['arch']}.zip"):
        print(a["browser_download_url"]); break
EOF
)
    [ -n "$url" ] || die "没找到对应平台的 release 资产"
    curl -sL -o /tmp/usque.zip "$url" || die "下载失败"
    unzip -o -j -q /tmp/usque.zip -d . && rm -f /tmp/usque.zip
    chmod +x ./usque
    c_green "✅ usque 已就绪: $(./usque version 2>/dev/null || echo ./usque)"
}

# ---------- 菜单 ----------

menu() {
    while true; do
        echo
        echo "====== Zero Trust WARP 工具箱 ======"
        echo "  1) 启动 MASQUE 隧道        2) 停止隧道"
        echo "  3) 状态 + 出口测试         4) 查看日志"
        echo "  5) 查看节点信息            6) 注册新 Zero Trust 设备 (OTP)"
        echo "  7) 现有设备切到 MASQUE     8) 切回 WireGuard"
        echo "  9) 查询设备状态            10) 注册免费 WARP 设备"
        echo " 11) 下载/更新 usque         0) 退出"
        read -r -p "选择: " n
        case "$n" in
            1) start ;;
            2) stop ;;
            3) status ;;
            4) log ;;
            5) info ;;
            6) reg_new_bg ;;
            7) switch_masque ;;
            8) revert_wg ;;
            9) check_device ;;
            10) reg_free ;;
            11) dl_usque ;;
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
    *)     echo "用法: $0 [start [auto|udp|tcp]|stop|status|log|info|menu]"; exit 1 ;;
esac
