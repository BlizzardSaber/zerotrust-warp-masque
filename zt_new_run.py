#!/usr/bin/env python3
"""一次性驱动（配合 zt_masque.py --new 的非交互版）:
OTP 登录 -> 注册全新 Zero Trust 设备 -> PATCH 为 MASQUE -> 导出 usque 配置。

用法: .venv/bin/python zt_new_run.py <组织名> <邮箱> <验证码文件>
脚本发完验证码邮件后轮询 <验证码文件>（最长 15 分钟），把 6 位验证码写进
该文件即可继续。日志按阶段打印标记（WAITING_FOR_CODE / DONE 等）。
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from zt_login import AccessLogin, find_token, save_debug  # noqa: E402
from zt_masque import (  # noqa: E402
    build_and_save, enroll_masque, gen_ec_keypair, register_device,
    save_debug as save_masque_debug)
from zerotrust2wg import validate_team_or_cleanup  # noqa: E402


def main():
    org, email, code_file = sys.argv[1], sys.argv[2], Path(sys.argv[3])

    a = AccessLogin(org)
    a.start()
    print("LOGIN_PAGE_OK", flush=True)

    _, html1 = a.submit_email(email)
    save_debug("debug_email_step2.html", html1)
    if not a.parse_code_form(html1):
        print("CODE_FORM_MISSING: 发码页解析失败，见 out/debug_email_step2.html",
              flush=True)
        sys.exit(1)
    print("EMAIL_SUBMITTED: 验证码已发往邮箱", flush=True)

    print("WAITING_FOR_CODE", flush=True)
    deadline = time.time() + 900
    code = ""
    while time.time() < deadline:
        if code_file.exists() and code_file.read_text().strip():
            code = code_file.read_text().strip()
            break
        time.sleep(1)
    if not code:
        print("CODE_TIMEOUT: 15 分钟内未收到验证码", flush=True)
        sys.exit(1)

    final_url, final_html = a.submit_code(code)
    jwt = find_token(a, final_url, final_html)
    if not jwt:
        print("TOKEN_NOT_FOUND: 验证码错误/过期，见 out/debug_warp_page.html",
              flush=True)
        sys.exit(1)
    print("TOKEN_OK", flush=True)

    resp = register_device(jwt)
    validate_team_or_cleanup(resp)
    token = resp["token"]
    print(f"DEVICE_REGISTERED: {resp['id']} "
          f"({(resp.get('account') or {}).get('account_type')})", flush=True)

    priv_b64, pub_b64 = gen_ec_keypair()
    resp = enroll_masque(resp["id"], token, pub_b64)
    save_masque_debug(resp)
    build_and_save(resp, priv_b64, token)
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
