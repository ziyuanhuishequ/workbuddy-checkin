#!/usr/bin/env python3
"""接口自测脚本。

用法（先把服务跑起来）：
    python tools/selftest_api.py http://127.0.0.1:8848 你的控制台密码

会真实调用一次腾讯的 auth/state 接口来申请登录链接，验证登录链路是通的
（不会完成登录，也不会消耗任何账号额度）。
另外会校验「上传令牌」那条路的解析与错误提示。
"""

from __future__ import annotations

import sys
import time

import requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8848").rstrip("/")
PASSWORD = sys.argv[2] if len(sys.argv) > 2 else ""

results: list[tuple[bool, str, str]] = []


def check(name: str, condition: bool, extra: str = "") -> bool:
    results.append((bool(condition), name, str(extra)))
    flag = "PASS" if condition else "FAIL"
    print(f"[{flag}] {name}" + (f"  → {extra}" if extra else ""))
    return bool(condition)


def main() -> int:
    session = requests.Session()

    r = session.get(f"{BASE}/api/health", timeout=10)
    check("健康检查", r.status_code == 200 and r.json().get("ok"), r.text[:80])

    r = session.get(f"{BASE}/api/accounts", timeout=10)
    check("未登录访问被拒（401）", r.status_code == 401, f"HTTP {r.status_code}")

    if PASSWORD:
        r = session.post(f"{BASE}/api/login", json={"password": "definitely-wrong"}, timeout=10)
        check("错误密码被拒（401）", r.status_code == 401, f"HTTP {r.status_code}")

        r = session.post(f"{BASE}/api/login", json={"password": PASSWORD}, timeout=10)
        check("正确密码登录成功", r.status_code == 200, r.text[:80])
        if r.status_code != 200:
            return report()

        r = session.get(f"{BASE}/api/me", timeout=10)
        check("会话有效", r.json().get("authed") is True)

        r = session.get(f"{BASE}/api/overview", timeout=10)
        payload = r.json().get("data", {}) if r.status_code == 200 else {}
        check("概览接口", r.status_code == 200 and "accounts" in payload, str(payload)[:120])

        r = session.get(f"{BASE}/api/accounts", timeout=10)
        check("账号列表", r.status_code == 200 and isinstance(r.json().get("data"), list))

        r = session.get(f"{BASE}/api/logs?limit=10", timeout=10)
        check("日志接口", r.status_code == 200 and isinstance(r.json().get("data"), list))

        r = session.get(f"{BASE}/api/settings", timeout=10)
        settings = r.json().get("data", {}) if r.status_code == 200 else {}
        check("设置读取", r.status_code == 200 and "checkin_time" in settings,
              f"签到时间={settings.get('checkin_time')}")

        # 写设置 + 读回
        r = session.post(f"{BASE}/api/settings", json={"checkin_time": "07:35"}, timeout=10)
        ok_save = r.status_code == 200 and r.json()["data"]["checkin_time"] == "07:35"
        check("设置保存", ok_save)
        r = session.post(f"{BASE}/api/settings", json={"checkin_time": "25:99"}, timeout=10)
        check("非法时间被忽略", r.json()["data"]["checkin_time"] == "07:35",
              r.json()["data"]["checkin_time"])

        # 失效账号清理（v1.3.0）
        # 注意：这里只做「预览」和「绝对清不到东西的空跑」，绝不带 days=0，
        # 否则会在真实服务器上把用户所有失效账号删掉。
        r = session.get(f"{BASE}/api/accounts/expired?days=0", timeout=10)
        edata = r.json().get("data", {}) if r.status_code == 200 else {}
        check("失效账号预览", r.status_code == 200 and isinstance(edata.get("count"), int),
              f"当前 {edata.get('count')} 个需重新登录")

        r = session.post(f"{BASE}/api/accounts/cleanup", json={"days": 99999}, timeout=15)
        cdata = r.json().get("data", {}) if r.status_code == 200 else {}
        check("清理接口可用（安全空跑，不删任何账号）",
              r.status_code == 200 and cdata.get("removed") == 0, str(cdata.get("message", "")))

        r = session.get(f"{BASE}/api/settings", timeout=10)
        check("自动清理开关存在", "auto_cleanup_days" in r.json().get("data", {}),
              f"当前 {r.json().get('data', {}).get('auto_cleanup_days')} 天")

        # 登录链路：真实调用上游 auth/state，拿一条电脑端登录链接
        r = session.post(f"{BASE}/api/qr/start", timeout=40)
        if r.status_code == 200:
            data = r.json()["data"]
            auth_url = str(data.get("auth_url", ""))
            check("申请登录链接（真实调用上游）", auth_url.startswith("https://"), auth_url[:70])
            check("返回 state", len(data.get("state", "")) > 10, data.get("state", "")[:20] + "…")
            check("不再下发二维码图片", "qr" not in data, "已删除二维码功能" if "qr" not in data else "仍返回 qr")
            check("链接带 platform=CLI 与 state", "platform=CLI" in auth_url and "state=" in auth_url)

            sid = data.get("sid")
            time.sleep(1)
            r = session.get(f"{BASE}/api/qr/poll/{sid}", timeout=30)
            status = r.json()["data"]["status"] if r.status_code == 200 else "?"
            check("轮询返回等待登录", status == "pending", status)

            r = session.post(f"{BASE}/api/qr/cancel/{sid}", timeout=10)
            check("取消登录会话", r.status_code == 200)

            r = session.get(f"{BASE}/api/qr/poll/{sid}", timeout=10)
            check("取消后会话失效", r.json()["data"]["status"] == "expired",
                  r.json()["data"].get("message", ""))
        else:
            check("申请登录链接（真实调用上游）", False, f"HTTP {r.status_code} {r.text[:100]}")

        # 账号导入的参数校验
        r = session.post(f"{BASE}/api/accounts/import", json={"access_token": ""}, timeout=10)
        check("空 token 被拒（400）", r.status_code == 400, r.text[:80])
        r = session.post(f"{BASE}/api/accounts/import-batch", json={"text": "   \n#注释\n"}, timeout=10)
        check("空批量被拒（400）", r.status_code == 400, r.text[:80])

        # 上传令牌：认不出的内容必须给中文提示，不能 500
        # 注意：这里只喂废话，绝不会真的往库里加账号。
        join_token = settings.get("join_token", "")
        import_url = f"{BASE}/api/join/import?t={join_token}"
        r = session.post(import_url, json={"text": "这不是令牌，只是一段废话"}, timeout=15)
        detail = ""
        try:
            detail = str(r.json().get("detail", ""))
        except Exception:
            detail = r.text[:80]
        check("自助导入·废话被拒（400）", r.status_code == 400, f"HTTP {r.status_code} {detail[:60]}")
        check("自助导入·错误提示可读", any(w in detail for w in ("令牌", "凭据", "解析")), detail[:60])
        r = session.post(import_url, json={"text": ""}, timeout=15)
        check("自助导入·空内容被拒（400）", r.status_code == 400, f"HTTP {r.status_code}")
        r = session.post(f"{BASE}/api/join/import?t=wrong-token", json={"text": "x" * 40}, timeout=15)
        check("自助导入·错误链接被拒（403）", r.status_code == 403, f"HTTP {r.status_code}")

        r = session.post(f"{BASE}/api/logout", timeout=10)
        check("退出登录", r.status_code == 200)
        r = session.get(f"{BASE}/api/accounts", timeout=10)
        check("退出后访问被拒", r.status_code == 401)

    return report()


def report() -> int:
    failed = [item for item in results if not item[0]]
    print("\n" + "=" * 58)
    print(f"共 {len(results)} 项，通过 {len(results) - len(failed)}，失败 {len(failed)}")
    for _, name, extra in failed:
        print(f"  ✗ {name} {extra}")
    print("=" * 58)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
