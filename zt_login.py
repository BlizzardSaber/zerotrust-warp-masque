#!/usr/bin/env python3
"""
zt_login.py — 本地复刻 Zero Trust 网页工具：直接对接 Cloudflare 官方
Access 登录接口拿 Team Token，并在 token 尚未过期时立刻注册 WARP 设备、
导出 WireGuard 配置。

与第三方网页工具的区别:
  - 邮箱 / 一次性验证码只在你本机 <-> cloudflareaccess.com 之间传输
  - 拿到 token 后 0 秒延迟注册，不用抢 60 秒时效
  - 私钥本地生成，只在本地保存

用法:
    .venv/bin/python zt_login.py [组织名] [邮箱]
    # 组织名即 xxx.cloudflareaccess.com 中的 xxx，两项缺省时会交互询问
"""

import base64
import datetime
import html as html_mod
import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from zerotrust2wg import (  # noqa: E402
    gen_keypair, register, validate_team_or_cleanup, write_outputs)

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15")
# Cloudflare Access 一次性验证码(OTP)连接器的固定 ID
OTP_CONNECTOR = "00000000-0000-0000-0000-000000000000"
JWT_RE = re.compile(r"[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")
OUT_DIR = Path(__file__).resolve().parent / "out"


class AccessLogin:
    def __init__(self, org):
        self.base = f"https://{org}.cloudflareaccess.com"
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))
        self.opener.addheaders = [("User-Agent", UA)]
        self.action = None       # 第一步(邮箱)表单
        self.kid = ""
        self.code_action = None  # 第二步(验证码)表单
        self.code_fields = {}

    def _open(self, url, data=None):
        req = urllib.request.Request(
            url, data=data, method="POST" if data else "GET")
        return self.opener.open(req, timeout=30)

    def start(self):
        """/warp -> 302 官方登录页，取第一步表单 action 和 kid。"""
        r = self._open(f"{self.base}/warp")
        page_url = r.geturl()
        body = r.read().decode(errors="replace")
        self.kid = urllib.parse.parse_qs(
            urllib.parse.urlparse(page_url).query).get("kid", [""])[0]
        m = (re.search(r"<form[^>]*action='([^']+)'", body)
             or re.search(r'<form[^>]*action="([^"]+)"', body))
        if not m:
            raise RuntimeError("登录页解析失败（Cloudflare 可能改版了）")
        self.action = self.abs_url(m.group(1))
        return page_url

    def abs_url(self, action):
        """表单 action 可能是相对路径(如 /cdn-cgi/access/callback)。"""
        return urllib.parse.urljoin(self.base + "/", html_mod.unescape(action))

    def submit_email(self, email):
        fields = [
            ("client_id", self.kid),
            ("connector_id", OTP_CONNECTOR),
            ("connector_type", "OTP"),
            ("redirect_url", "/warp"),
            ("email", email),
        ]
        r = self._open(self.action, urllib.parse.urlencode(fields).encode())
        return r.geturl(), r.read().decode(errors="replace")

    def parse_code_form(self, body):
        """从「输入验证码」页面解析 callback 表单(含一次性 nonce)。"""
        for fm in re.finditer(r"<form[^>]*>[\s\S]*?</form>", body):
            block = fm.group(0)
            if not re.search(r'(?:name|id)="code"', block):
                continue
            am = (re.search(r"action='([^']+)'", block)
                  or re.search(r'action="([^"]+)"', block))
            if am:
                self.code_action = self.abs_url(am.group(1))
            for inp in re.findall(r"<input[^>]*>", block):
                nm = (re.search(r'name="([^"]+)"', inp)
                      or re.search(r"name='([^']+)'", inp))
                vl = (re.search(r'value="([^"]*)"', inp)
                      or re.search(r"value='([^']*)'", inp))
                if nm and nm.group(1) != "code":
                    self.code_fields[nm.group(1)] = (
                        html_mod.unescape(vl.group(1)) if vl else "")
            return self.code_action is not None
        return False

    def submit_code(self, code):
        fields = dict(self.code_fields)
        fields["code"] = code
        r = self._open(self.code_action, urllib.parse.urlencode(fields).encode())
        return r.geturl(), r.read().decode(errors="replace")


def jwt_payload(tok):
    try:
        p = tok.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


def find_token(a, final_url, final_html):
    """从 cookie / 页面 / URL 里找出带 warp 声明的 enrollment JWT。"""
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "debug_warp_page.html").write_text(final_html)

    cands = {c.value for c in a.jar}
    cands |= set(JWT_RE.findall(final_html))
    for v in urllib.parse.parse_qs(
            urllib.parse.urlparse(final_url).query).values():
        cands.update(v)

    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    for t in cands:
        if t.count(".") != 2:
            continue
        p = jwt_payload(t)
        # 严格匹配 enrollment token: 官方签发、type=app、warp=true、未过期
        if (p.get("type") == "app" and p.get("warp") is True
                and p.get("exp", 0) > now
                and str(p.get("iss", "")).endswith(".cloudflareaccess.com")):
            return t
    return None


def save_debug(name, text):
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / name).write_text(text)


def main():
    org = (sys.argv[1] if len(sys.argv) > 1
           else input("组织名 (xxx.cloudflareaccess.com 里的 xxx): ").strip())
    email = (sys.argv[2] if len(sys.argv) > 2
             else input("登录邮箱: ").strip())

    a = AccessLogin(org)
    print("[1/5] 打开官方登录页 ...")
    try:
        page = a.start()
    except Exception as e:
        sys.exit(f"打开登录页失败: {e}\n（确认组织名拼写、以及 Zero Trust 后台"
                 " Login methods 已开启 One-time PIN）")
    print(f"      {page[:90]}")

    print("[2/5] 提交邮箱，请 Cloudflare 发送一次性验证码 ...")
    try:
        url1, html1 = a.submit_email(email)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            sys.exit("Cloudflare 拒绝了发码请求（429 限频）。OTP 邮件有频率上限，"
                     "一般等 ~1 小时后解除，期间别反复重试。")
        raise
    save_debug("debug_email_step.html", html1)
    if re.search(r"(?i)too many|try again later|an error occurred", html1):
        sys.exit("Cloudflare 返回了错误提示（很可能限频），页面已存到 "
                 "out/debug_email_step.html。等 ~1 小时再试。")
    if not a.parse_code_form(html1):
        sys.exit("发码请求已发出，但未解析到验证码输入表单。页面已存到 "
                 "out/debug_email_step.html，发回来排查。")

    print("[3/5] 去邮箱查收验证码（发件人 noreply@notify.cloudflare.com）")
    code = input("      输入验证码: ").strip()

    print("[4/5] 验证验证码并提取 WARP Team Token ...")
    final_url, final_html = a.submit_code(code)
    if "/cdn-cgi/access/login" in final_url or \
            "<title>Sign in" in final_html[:3000]:
        save_debug("debug_warp_page.html", final_html)
        sys.exit("验证码提交后仍停留在登录页（验证码错/过期，或已被使用）。"
                 "页面已存到 out/debug_warp_page.html，重跑换新码。")

    token = find_token(a, final_url, final_html)
    if not token:
        sys.exit("未能提取 token。最终页面已存到 out/debug_warp_page.html，"
                 "发回来排查。")
    p = jwt_payload(token)
    print(f"      Token OK（邮箱 {p.get('email')}，"
          f"有效期至 {datetime.datetime.fromtimestamp(p['exp'])}）")

    print("[5/5] 立刻注册设备并导出配置 ...")
    priv, pub = gen_keypair()
    resp = register(pub, token)
    validate_team_or_cleanup(resp)
    write_outputs(resp, priv, pub)


if __name__ == "__main__":
    main()
