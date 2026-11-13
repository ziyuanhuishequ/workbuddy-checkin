"""业务编排层：签到、续期、自检、通知。

API 层和后台调度都调这里，保证两边行为完全一致。
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

import requests

from . import config, db, portal, wb

logger = logging.getLogger("workbuddy.service")

# 批量签到时并发数：账号多也不用等太久，同时对上游足够克制
MAX_WORKERS = 4


class AccountNotFound(Exception):
    pass


# --------------------------------------------------------------------------- #
# 账号加载 / 令牌续期
# --------------------------------------------------------------------------- #

def load_account(account_id: int) -> dict[str, Any]:
    account = db.get_account(account_id, with_secrets=True)
    if account is None:
        raise AccountNotFound(f"账号 {account_id} 不存在")
    return account


def token_expiring(account: dict[str, Any], lead: Optional[int] = None) -> bool:
    """令牌是不是该续期了。

    到期时间未知（=0）时返回 True：宁可多续一次，也不要等它过期后
    只能靠 401 才发现 —— 那时候很多网关连 refresh 都会一起拒掉。
    """
    expires_at = int(account.get("expires_at") or 0)
    if expires_at <= 0:
        return True
    if lead is None:
        lead = db.get_int_setting("refresh_lead_seconds", 1800)
    return expires_at - int(time.time()) <= int(lead)


def refresh_account(account_id: int, force: bool = False, notify: bool = False) -> dict[str, Any]:
    """续期 accessToken（自动登录的核心）。返回 {ok, message, account}。"""
    account = load_account(account_id)
    refresh_token = account.get("refresh_token") or ""
    if not refresh_token:
        message = "没有 refreshToken，需要重新登录"
        db.update_account(account_id, status="expired", last_error=message)
        db.add_log("refresh", False, message, account_id=account_id,
                   uid=account.get("uid", ""), nickname=account.get("nickname", ""))
        return {"ok": False, "message": message, "account": db.get_account(account_id)}
    if not force and not token_expiring(account):
        return {"ok": True, "message": "令牌仍有效，跳过续期", "account": account}

    try:
        payload = wb.refresh_tokens(
            access_token=account.get("access_token") or "",
            refresh_token=refresh_token,
            enterprise_id=account.get("enterprise_id") or "",
            domain=account.get("domain") or "",
        )
    except wb.WbAuthError as exc:
        db.update_account(account_id, status="expired", last_error=str(exc))
        db.add_log("refresh", False, str(exc), account_id=account_id,
                   uid=account.get("uid", ""), nickname=account.get("nickname", ""))
        if notify:
            _notify("WorkBuddy 登录失效", f"账号 {account.get('nickname') or account.get('uid')} 需要重新登录：{exc}")
        return {"ok": False, "message": str(exc), "account": db.get_account(account_id)}
    except wb.WbError as exc:
        db.update_account(account_id, last_error=str(exc))
        db.add_log("refresh", False, f"续期失败：{exc}", account_id=account_id,
                   uid=account.get("uid", ""), nickname=account.get("nickname", ""))
        return {"ok": False, "message": str(exc), "account": db.get_account(account_id)}

    now = int(time.time())
    expires_in = int(payload.get("expiresIn") or 0)
    refresh_expires_in = int(payload.get("refreshExpiresIn") or 0)
    was_expired = str(account.get("status") or "") == "expired"
    db.update_tokens(
        account_id,
        access_token=str(payload.get("accessToken") or ""),
        refresh_token=str(payload.get("refreshToken") or ""),
        expires_at=now + expires_in if expires_in else 0,
        refresh_expires_at=now + refresh_expires_in if refresh_expires_in else 0,
        domain=str(payload.get("domain") or ""),
    )
    remaining_hours = round(expires_in / 3600, 1) if expires_in else 0
    message = f"续期成功，新令牌有效期 {remaining_hours} 小时" if remaining_hours else "续期成功"
    db.add_log("refresh", True, message, account_id=account_id,
               uid=account.get("uid", ""), nickname=account.get("nickname", ""))
    # 之前被判失效、现在靠 refreshToken 自己救回来了 —— 对用户来说就是「重新登录成功」
    if was_expired:
        try:
            notify_login_success(
                db.get_account(account_id, with_secrets=True) or account,
                None,
                reason="登录凭据过期，已自动续期恢复（无需重新登录）",
            )
        except Exception:
            logger.exception("自动恢复登录的通知发送失败：account_id=%s", account_id)
    return {"ok": True, "message": message, "account": db.get_account(account_id)}


def ensure_live_account(account_id: int) -> dict[str, Any]:
    """签到前先确保令牌是新鲜的（快过期 / 到期时间未知就先续期）。"""
    account = load_account(account_id)
    if db.get_bool_setting("auto_refresh", True) and account.get("refresh_token") and token_expiring(account):
        result = refresh_account(account_id)
        if result.get("ok"):
            account = load_account(account_id)
    return account


# --------------------------------------------------------------------------- #
# 签到
# --------------------------------------------------------------------------- #

def _recover_and_retry(account_id: int) -> dict[str, Any]:
    """凭据被判失效时，先用 refreshToken 自动「重新登录」一次。

    这是 v1.1.0 的关键修复：老版本只要接口回 401 就直接把账号标成
    「需重新登录」，哪怕 refreshToken 还是好的 —— 于是每天都要手动扫码。
    现在先自动换令牌，换到了就立刻重试，用户完全无感。
    """
    if not db.get_bool_setting("auto_refresh", True):
        return {"ok": False, "message": "自动续期已关闭"}
    account = load_account(account_id)
    if not account.get("refresh_token"):
        return {"ok": False, "message": "没有 refreshToken，只能重新登录"}
    return refresh_account(account_id, force=True)


def checkin_account(account_id: int, trigger: str = "manual") -> dict[str, Any]:
    """对单个账号执行签到，并把结果写进数据库和日志。"""
    account = db.get_account(account_id)
    if account is None:
        raise AccountNotFound(f"账号 {account_id} 不存在")
    if not account.get("enabled"):
        return {"ok": False, "skipped": True, "message": "账号已停用", "account": account}

    live = ensure_live_account(account_id)

    uid = str(account.get("uid") or "")
    # 今天这个 uid 已经真签过了？直接返回，绝不再打上游 daily-checkin。
    # 上游的「已签到」判断并不可靠（重扫后同一个账号还会返回成功并再发一次积分），
    # 所以这里用本地标记兜住：一天一个 uid 只允许真正领取一次。
    mark = db.get_checkin_mark(uid)
    already_marked = mark is not None
    if already_marked:
        result = wb.CheckinResult(True, "今日已签到", None, False)
    else:
        try:
            result = wb.checkin(live)
        except wb.WbAuthError as exc:
            result = wb.CheckinResult(False, str(exc), auth_failed=True)
        except wb.WbError as exc:
            db.add_log("checkin", False, f"[{trigger}] {exc}", account_id=account_id,
                       uid=account.get("uid", ""), nickname=account.get("nickname", ""))
            notify_account_result(live, wb.CheckinResult(False, str(exc)))
            return {"ok": False, "message": str(exc), "account": db.get_account(account_id)}

        # 「凭据失效」先别急着报错：自动续期一次，然后立刻重试签到
        if result.auth_failed:
            recovered = _recover_and_retry(account_id)
            if recovered.get("ok"):
                live = load_account(account_id)
                try:
                    retry = wb.checkin(live)
                except wb.WbAuthError as exc:
                    retry = wb.CheckinResult(False, str(exc), auth_failed=True)
                except wb.WbError as exc:
                    retry = wb.CheckinResult(False, str(exc))
                if retry.ok:
                    retry.message = f"自动续期后{retry.message}"
                result = retry
            else:
                # 续期也失败，这才需要人工重新扫码
                result.message = f"{result.message}；自动续期也失败：{recovered.get('message', '')}"

        # 签成功就立刻记账，避免下一次登录/重扫又去领一遍
        if result.ok:
            won = result.credit if (result.claimed and isinstance(result.credit, int)) else None
            db.mark_checkin(uid, credit=won)

    # 附带刷新一下余额 / 昵称，失败不影响签到结论
    credits = db.get_account(account_id).get("credits") if db.get_account(account_id) else None
    status: dict[str, Any] = {}
    try:
        status = wb.query_status(live) or {}
        if status.get("ok"):
            credits = status.get("credits")
            fields: dict[str, Any] = {"status": "ok", "last_error": ""}
            if credits is not None:
                fields["credits"] = credits
                fields["credits_total"] = status.get("credits_total")
            if status.get("nickname"):
                fields["nickname"] = status["nickname"]
            if status.get("avatar_url"):
                fields["avatar_url"] = status["avatar_url"]
            db.update_account(account_id, **fields)
    except wb.WbError:
        pass

    fields = {}
    if result.ok:
        fields["status"] = "ok"
        fields["last_error"] = ""
        if result.claimed:
            fields["last_checkin_date"] = db.today_str()
            fields["last_checkin_at"] = db.now_ts()
        else:
            # 今天早就签过了（别人 / 官方客户端 / 本工具更早的一次登录），同样算今天完成
            fields["last_checkin_date"] = db.today_str()
    else:
        fields["last_error"] = result.message
        if result.auth_failed:
            fields["status"] = "expired"
    db.update_account(account_id, **fields)

    # 只有「本次真的到账」才把积分记进日志。
    # 否则「今日已签到」那条日志也会带上每日额度（100），
    # 页面上「今日获得」就会每登录一次涨 100，跟账户真实积分对不上。
    gained = result.credit if (result.claimed and isinstance(result.credit, int)) else None
    # 今天早就签过（本地有标记）的重复登录：不再写签到日志，免得「累计签到次数」被灌水
    if not already_marked:
        db.add_log(
            "checkin",
            result.ok,
            f"[{trigger}] {result.message}",
            account_id=account_id,
            uid=account.get("uid", ""),
            nickname=account.get("nickname", ""),
            claimed=result.claimed,
            credit=gained,
        )
    # 把这个结果推给账号本人（如果他自己开了微信提醒）
    # 登录触发的签到，发的是「登录完成 + 积分明细」的完整通知，不再重复发签到通知
    if trigger in ("login", "new-account") and not result.auth_failed:
        notify_login_success(
            db.get_account(account_id, with_secrets=True) or live,
            result,
            reason="电脑端登录 / 上传令牌",
            status=status,
        )
    else:
        notify_account_result(db.get_account(account_id, with_secrets=True) or live, result, status)

    return {
        "ok": result.ok,
        "claimed": result.claimed,
        "message": result.message,
        "credit": result.credit,
        "account": db.get_account(account_id),
    }


def checkin_async(account_id: int, trigger: str = "new-account") -> None:
    """后台补一次签到，不阻塞接口响应。

    新账号通常是「当天才加进来」的，此时当天的定时任务早就跑完了。
    如果不主动补一次，这个账号要等到明天才会被签到——多账号场景下这很致命。
    """

    def worker() -> None:
        try:
            checkin_account(account_id, trigger=trigger)
        except Exception:
            logger.exception("新账号自动签到失败：account_id=%s", account_id)

    threading.Thread(target=worker, name=f"wb-checkin-{account_id}", daemon=True).start()


def checkin_all(trigger: str = "manual") -> dict[str, Any]:
    """批量签到所有启用中的账号。"""
    accounts = [a for a in db.list_accounts() if a.get("enabled")]
    if not accounts:
        return {"total": 0, "ok": 0, "failed": 0, "results": []}

    results: list[dict[str, Any]] = []

    def run(account: dict[str, Any]) -> dict[str, Any]:
        try:
            item = checkin_account(int(account["id"]), trigger=trigger)
        except Exception as exc:  # 单个账号异常不能拖垮整批
            logger.exception("账号 %s 签到异常", account.get("uid"))
            item = {"ok": False, "message": f"内部错误：{exc}", "account": account}
        item["uid"] = account.get("uid")
        item["nickname"] = account.get("nickname")
        return item

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = list(pool.map(run, accounts))

    ok_count = sum(1 for r in results if r.get("ok"))
    failed = [r for r in results if not r.get("ok")]
    summary = {
        "total": len(results),
        "ok": ok_count,
        "failed": len(failed),
        "results": results,
    }
    db.add_log(
        "system",
        not failed,
        f"[{trigger}] 批量签到完成：成功 {ok_count}/{len(results)}"
        + (f"，失败：{'、'.join(str(r.get('nickname') or r.get('uid')) for r in failed)}" if failed else ""),
    )
    _maybe_notify_batch(trigger, summary)
    return summary


def sync_status(account_id: int) -> dict[str, Any]:
    """账号自检：实时查上游的登录态 / 签到状态 / 积分。"""
    account = ensure_live_account(account_id)
    try:
        info = wb.query_status(account)
    except wb.WbError as exc:
        info = {"ok": False, "message": str(exc)}

    # 自检时发现凭据失效，同样先尝试自动续期再查一次
    if info.get("auth_failed"):
        recovered = _recover_and_retry(account_id)
        if recovered.get("ok"):
            account = load_account(account_id)
            try:
                again = wb.query_status(account)
            except wb.WbError:
                again = {}
            if again.get("ok"):
                again["message"] = "自动续期后恢复正常"
                info = again

    fields: dict[str, Any] = {}
    if info.get("ok"):
        fields["status"] = "ok"
        fields["last_error"] = ""
        if info.get("credits") is not None:
            fields["credits"] = info["credits"]
            fields["credits_total"] = info.get("credits_total")
        if info.get("nickname"):
            fields["nickname"] = info["nickname"]
        if info.get("avatar_url"):
            fields["avatar_url"] = info["avatar_url"]
        if info.get("checked_in"):
            fields["last_checkin_date"] = db.today_str()
    else:
        message = str(info.get("message") or "自检失败")
        if info.get("auth_failed"):
            fields["status"] = "expired"
        fields["last_error"] = message
    if fields:
        db.update_account(account_id, **fields)
    return {"ok": bool(info.get("ok")), "info": info, "account": db.get_account(account_id)}


# --------------------------------------------------------------------------- #
# 令牌保活 / 自动复活
# --------------------------------------------------------------------------- #

def keepalive_all(force: bool = False) -> dict[str, Any]:
    """后台保活：把快到期的令牌提前续掉，让续期链永远不断。

    refreshToken 是会「滚」的（每次续期可能换一个新的），只要一直按节奏换，
    就能无限期免维护；一旦超过有效期没动过，就只能重新登录一次。
    v1.0 只在签到那一刻才续期，签到失败又不重试，很容易一停就是几天。
    """
    if not db.get_bool_setting("auto_refresh", True):
        return {"total": 0, "ok": 0, "failed": 0, "skipped": True}

    lead = db.get_int_setting("keepalive_lead_seconds", 6 * 3600)
    targets = []
    for account in db.list_accounts(with_secrets=True):
        if not account.get("enabled") or not account.get("refresh_token"):
            continue
        if force or account.get("status") == "expired" or token_expiring(account, lead=lead):
            targets.append(account)
    if not targets:
        return {"total": 0, "ok": 0, "failed": 0}

    ok, failed = 0, []
    for account in targets:
        try:
            result = refresh_account(int(account["id"]), force=True)
        except Exception as exc:  # 单个账号异常不能拖垮整批
            logger.exception("保活续期异常：%s", account.get("uid"))
            result = {"ok": False, "message": str(exc)}
        if result.get("ok"):
            ok += 1
        else:
            failed.append({
                "uid": account.get("uid"),
                "nickname": account.get("nickname"),
                "message": result.get("message", ""),
            })
    summary = {
        "total": len(targets),
        "ok": ok,
        "failed": len(failed),
        "details": failed,
    }
    db.add_log(
        "system",
        not failed,
        f"[keepalive] 令牌保活：成功 {ok}/{len(targets)}"
        + (f"，失败：{'、'.join(str(f.get('nickname') or f.get('uid')) for f in failed)}" if failed else ""),
    )
    return summary


# --------------------------------------------------------------------------- #
# 通知
# --------------------------------------------------------------------------- #

def _maybe_notify_batch(trigger: str, summary: dict[str, Any]) -> None:
    mode = db.get_setting("notify_on", "failure")
    if mode == "never":
        return
    if mode == "failure" and not summary.get("failed"):
        return
    lines = [f"成功 {summary['ok']}/{summary['total']}"]
    for item in summary["results"]:
        name = item.get("nickname") or item.get("uid") or "?"
        flag = "✅" if item.get("ok") else "❌"
        lines.append(f"{flag} {name}：{item.get('message', '')}")
    _notify(f"WorkBuddy 签到结果（{trigger}）", "\n".join(lines))


def _notify_ex(title: str, content: str) -> tuple[bool, str]:
    """站长级通知（Webhook / 企业微信 / 钉钉 / 飞书 / Server酱）。返回 (是否成功, 原因)。

    以前这里 `requests.post(...)` 连返回值都不看，异常也只在服务器日志里 warning，
    所以「测试通知」按钮**永远提示发送成功**，哪怕对方一个字都没收到。
    现在把 HTTP 状态码和各家的错误码都读出来。
    """
    webhook = db.get_setting("notify_webhook", "").strip()
    if not webhook:
        return False, "还没有配置 Webhook 地址 / SendKey"
    kind = db.get_setting("notify_type", "custom")
    if kind == "none":
        return False, "通知方式还是「不通知」"
    try:
        if kind == "serverchan":
            key = webhook.rstrip("/").split("/")[-1]
            resp = requests.post(
                f"https://sctapi.ftqq.com/{key}.send",
                data={"title": title, "desp": content},
                timeout=config.HTTP_TIMEOUT, proxies=wb._proxies(),
            )
        elif kind == "feishu":
            resp = requests.post(
                webhook, json={"msg_type": "text", "content": {"text": f"{title}\n{content}"}},
                timeout=config.HTTP_TIMEOUT, proxies=wb._proxies(),
            )
        else:  # 企业微信 / 钉钉 / 自定义：都是 {msgtype:text,text:{content}}
            resp = requests.post(
                webhook, json={"msgtype": "text", "text": {"content": f"{title}\n{content}"}},
                timeout=config.HTTP_TIMEOUT, proxies=wb._proxies(),
            )
    except requests.RequestException as exc:
        logger.warning("通知推送失败：%s", exc)
        return False, f"网络错误：{exc}"

    # 先看业务错误码：Server酱/企业微信 出错时也常返 200 或 400，但真正的
    # 原因在响应体里（比如「[AUTH]错误的Key」），比裸的 HTTP 码有用得多。
    try:
        payload = resp.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        # Server酱/飞书用 code，企业微信/钉钉用 errcode，飞书新版用 StatusCode
        code = payload.get("errcode", payload.get("code", payload.get("StatusCode")))
        if code not in (0, None):
            detail = payload.get("errmsg") or payload.get("message") or payload.get("msg") or f"code={code}"
            logger.warning("通知接口返回：%s", detail)
            return False, f"接口返回：{detail}"
    if resp.status_code >= 400:
        return False, f"接口返回 HTTP {resp.status_code}：{(resp.text or '')[:120]}"
    return True, ""


def _notify(title: str, content: str) -> None:
    """发一条站长级通知（不关心结果的老调用方用这个）。"""
    ok, reason = _notify_ex(title, content)
    if not ok:
        db.add_log("system", False, f"站长通知没发出去：{reason}")


def send_test_notification() -> dict[str, Any]:
    """给控制台一个「测试通知」按钮，确认 webhook 真的通。

    注意：这里必须把真实结果返回给前端 —— 以前不管成不成都回「已发送」，
    站长看到绿色提示、群里却啥也没有，基本没法排查。
    """
    webhook = db.get_setting("notify_webhook", "").strip()
    if not webhook:
        raise ValueError("还没有配置 Webhook 地址 / SendKey")
    kind = db.get_setting("notify_type", "custom")
    if kind == "none":
        raise ValueError("通知方式还是「不通知」，请先选择一种方式")
    ok, reason = _notify_ex("WorkBuddy 签到测试通知", "如果你看到这条消息，说明通知渠道配置成功。")
    if ok:
        return {"ok": True, "sent": True, "reason": "",
                "message": "测试通知已发送，请到对应的群里确认"}
    return {"ok": True, "sent": False, "reason": reason,
            "message": f"发送失败：{reason}"}


# --------------------------------------------------------------------------- #
# 每个账号自己的提醒（Server 酱 → 用户本人微信）
# --------------------------------------------------------------------------- #

def site_url() -> str:
    return db.get_setting("site_url", "").strip().rstrip("/")


def remember_site_url(scheme: str, host: str) -> None:
    """第一次被访问时把站点地址记下来，推送里好带上「查看积分」链接。"""
    if db.get_setting("site_url", "").strip() or not host:
        return
    scheme = (scheme or "http").split(",")[0].strip()
    db.set_setting("site_url", f"{scheme}://{host}")


def portal_link() -> str:
    base = site_url()
    return f"{base}/me" if base else "（在浏览器打开自助页 /me）"


# 站点归属方（可选）：设置了 WB_SITE_OWNER，账号彻底失效、用户自己搞不定时，
# 提示里会引导他来这里找站长；留空就只说「联系站点管理员」，不出现任何外部地址。
SITE_OWNER = os.environ.get("WB_SITE_OWNER", "").strip()

# 登录通知的进程内去重：同账号 90 秒内只发一条，避免登录轮询/重试造成连发
_login_notice_lock = threading.Lock()
_login_notice_at: dict[int, float] = {}
LOGIN_NOTICE_GAP = 90


def _fmt_num(value: Any) -> str:
    """积分数格式化：2865.53 → 2,865.53；1000 → 1,000。拿不到就返回「—」。

    这里**不能四舍五入成整数**：官方余额本身就是带小数的（2865.53），
    以前 `int(round())` 会变成 2,866，跟官网对不上，用户会以为工具算错了。
    """
    if value is None or value == "":
        return "—"
    try:
        num = float(value)
    except (TypeError, ValueError):
        return str(value)
    if abs(num - round(num)) < 1e-6:      # 整数就显示整数，别硬加 .00
        return f"{int(round(num)):,}"
    return f"{num:,.2f}"


def _login_help_lines() -> list[str]:
    """「账号失效了去哪儿重新登录」的统一话术。"""
    base = site_url()
    lines: list[str] = []
    if base:
        lines.append(f"1. 打开签到面板：{base}")
        lines.append("   用自己的管理员密码登录 → 点右上角「+ 添加账号」重新登录一次")
        lines.append(f"2. 查看自己的积分：{base}/me")
    else:
        lines.append("1. 打开你的签到面板 → 点右上角「+ 添加账号」重新登录一次")
        lines.append("2. 自助页 /me 可以查看自己的积分和签到记录")
    if SITE_OWNER:
        lines.append(f"3. 不会操作 / 需要帮处理：访问 {SITE_OWNER} 联系站长")
    else:
        lines.append("3. 不会操作 / 需要帮处理：联系站点管理员")
    return lines


def _credit_blocks(status: dict[str, Any], result: Optional["wb.CheckinResult"] = None) -> list[str]:
    """把「今日积分 / 签到所得 / 明日预计」拼成三行，缺数据就如实写未知。"""
    status = status or {}
    today = status.get("credits")
    daily = status.get("daily_credit")
    today_credit = status.get("today_credit")

    gained: Optional[float] = None
    gained_note = ""
    if result is not None:
        if result.claimed and result.credit is not None:
            gained = result.credit
            gained_note = "（本次已到账）"
        elif result.claimed:
            gained_note = "（本次已到账，额度未取到）"
        elif result.ok:
            # 今天早就签过了：不能把「每日额度」写成「今天又赚了 100」
            gained_note = "（今日已签到，本次未新增）"
        else:
            gained_note = "（本次未签到成功）"
    elif today_credit is not None:
        gained = today_credit
        gained_note = "（今日已到账）"
    elif status.get("checked_in"):
        gained_note = "（今日已签到）"
    else:
        gained_note = "（今日还没签到）"

    # 明日预计 = 今日余额 + 明天签到还能拿到的额度（官方额度以实际为准）
    step = daily if daily is not None else gained
    tomorrow: Optional[float] = None
    if today is not None and step is not None:
        tomorrow = float(today) + float(step)
    elif today is not None:
        tomorrow = float(today)

    lines = [f"· 今日积分：{_fmt_num(today)}"]
    if gained is not None:
        lines.append(f"· 今日签到：+{_fmt_num(gained)} 积分{gained_note}")
    else:
        lines.append(f"· 今日签到：{gained_note.strip('（）') or '未签到'}")
    if tomorrow is not None:
        extra = f"（其中明日签到约 +{_fmt_num(daily if daily is not None else step)}）" if step else ""
        lines.append(f"· 明日预计：{_fmt_num(tomorrow)}{extra}")
    else:
        lines.append("· 明日预计：积分数据暂未取到")
    return lines


def notify_login_success(
    account: dict[str, Any],
    result: Optional["wb.CheckinResult"] = None,
    reason: str = "电脑端登录成功",
    status: Optional[dict[str, Any]] = None,
) -> None:
    """登录完成后给账号本人推一条微信通知：已登录 + 今日积分 + 签到所得 + 明日预计。"""
    account_id = int(account["id"])
    key = account.get("notify_serverchan") or ""
    if not key:
        _log_notify_skip(account, "登录完成，但账号还没配微信提醒（SendKey），登录通知没发")
        return

    now = time.time()
    with _login_notice_lock:
        last = _login_notice_at.get(account_id, 0.0)
        if now - last < LOGIN_NOTICE_GAP:
            return
        _login_notice_at[account_id] = now

    nickname = account.get("nickname") or account.get("uid") or "你的账号"

    # 拉一次实时状态，保证「今日积分」是登录这一刻的真实余额
    if not status:
        status = {}
        try:
            live = db.get_account(account_id, with_secrets=True) or account
            if live.get("access_token"):
                status = wb.query_status(live)
        except wb.WbError as exc:
            logger.warning("登录通知查积分失败：%s", exc)

    lines = [
        "✅ 登录已完成，签到服务已经自动接管，你不用再做任何操作。",
        "",
        f"账号：{nickname}",
        f"方式：{reason}",
        f"时间：{time.strftime('%Y-%m-%d %H:%M', time.localtime(now))}",
        "",
        "📊 积分情况",
    ]
    lines += _credit_blocks(status, result)

    lines += [
        "",
        f"🔗 查看明细：{portal_link()}",
        "",
        "────────────",
        "❗账号哪天失效了，在哪儿重新登录？",
    ]
    lines += _login_help_lines()
    lines += ["", "（本条消息由 WorkBuddy 自动签到机器人发送，无需回复）"]

    title = f"✅ 登录完成｜今日 {_fmt_num(status.get('credits'))} 积分"
    ok, reason = push_serverchan_ex(key, title, "\n".join(lines))
    if ok:
        db.add_log("notify", True, "login", account_id=account_id,
                   uid=account.get("uid", ""), nickname=account.get("nickname", ""))
    else:
        logger.warning("登录通知推送失败（%s）：%s", nickname, reason)
        db.add_log("notify", False, f"login|推送失败：{reason}", account_id=account_id,
                   uid=account.get("uid", ""), nickname=account.get("nickname", ""))


def push_serverchan_ex(sendkey: str, title: str, content: str) -> tuple[bool, str]:
    """往 Server 酱推一条消息。返回 ``(是否成功, 失败原因)``。

    为什么要有「失败原因」：以前推送失败只在服务器日志里 warning 一句，
    用户在微信里什么也收不到、站长在控制台也看不出为什么 —— 于是就成了
    「以前能收到，这两天收不到」这种查不动的悬案。现在把 Server 酱 的原始
    返回（比如「[AUTH]错误的Key」）带出来，写进控制台日志，一眼能定位。
    """
    key = (sendkey or "").strip().rstrip("/").split("/")[-1]
    if not key:
        return False, "没有 SendKey"
    try:
        resp = requests.post(
            f"https://sctapi.ftqq.com/{key}.send",
            data={"title": title, "desp": content},
            timeout=config.HTTP_TIMEOUT,
            proxies=wb._proxies(),
        )
    except requests.RequestException as exc:
        logger.warning("Server 酱推送失败：%s", exc)
        return False, f"网络错误：{exc}"
    if resp.status_code != 200:
        logger.warning("Server 酱返回 HTTP %s", resp.status_code)
        return False, f"Server 酱返回 HTTP {resp.status_code}"
    try:
        payload = resp.json()
    except ValueError:
        return True, ""
    if isinstance(payload, dict) and payload.get("code") not in (0, None):
        detail = payload.get("message") or payload.get("info") or f"code={payload.get('code')}"
        logger.warning("Server 酱返回：%s", detail)
        return False, f"Server 酱：{detail}"
    return True, ""


def push_serverchan(sendkey: str, title: str, content: str) -> bool:
    """往 Server 酱推一条消息。返回是否成功（兼容老调用方）。"""
    return push_serverchan_ex(sendkey, title, content)[0]



def save_account_notify(account_id: int, sendkey: str) -> dict[str, Any]:
    """用户自己配置微信提醒：保存 SendKey 并发一条确认消息。"""
    raw = (sendkey or "").strip()
    if not raw:
        raise ValueError("请填写 Server 酱的 SendKey")
    key = raw.rstrip("/").split("/")[-1]
    if len(key) < 8:
        raise ValueError("SendKey 看起来不完整，请重新复制")
    account = db.get_account(account_id)
    if account is None:
        raise ValueError("账号不存在")

    db.set_notify_serverchan(account_id, key)
    nickname = account.get("nickname") or account.get("uid") or "你的账号"
    content = (
        f"账号「{nickname}」的每日提醒已经开启。\n\n"
        "以后你会收到：\n"
        "· 登录完成的通知（含今日积分、签到所得、明日预计）\n"
        "· 每天签到后的结果和积分\n"
        "· 登录凭据失效时的提醒，以及去哪儿重新登录\n\n"
        f"查看积分：{portal_link()}\n"
        + (f"遇到搞不定的问题，访问 {SITE_OWNER} 联系站长。"
           if SITE_OWNER else "遇到搞不定的问题，联系站点管理员。")
    )
    sent, reason = push_serverchan_ex(key, "WorkBuddy 签到提醒已开启", content)
    db.add_log("notify", sent, "用户开启微信提醒" + ("" if sent else f"（失败：{reason}）"),
               account_id=account_id, uid=account.get("uid", ""), nickname=account.get("nickname", ""))
    if sent:
        return {"ok": True, "sent": True, "message": "已开启！给你发了一条测试消息，去微信看看"}
    return {
        "ok": True,
        "sent": False,
        "message": (
            f"SendKey 已保存，但测试消息没发出去（{reason}）。"
            "请确认 SendKey 复制完整、已关注「Server酱」公众号。"
        ),
    }


def clear_account_notify(account_id: int) -> dict[str, Any]:
    if db.get_account(account_id) is None:
        raise ValueError("账号不存在")
    db.set_notify_serverchan(account_id, "")
    db.add_log("notify", True, "用户关闭微信提醒", account_id=account_id)
    return {"ok": True, "message": "已关闭微信提醒"}


def test_account_notify(account_id: int) -> dict[str, Any]:
    """用已保存的 SendKey 再发一条测试消息。"""
    account = db.get_account(account_id, with_secrets=True)
    if account is None:
        raise ValueError("账号不存在")
    key = account.get("notify_serverchan") or ""
    if not key:
        raise ValueError("还没有开启微信提醒")
    nickname = account.get("nickname") or account.get("uid") or "你的账号"
    sent, reason = push_serverchan_ex(
        key,
        "WorkBuddy 测试消息",
        f"账号「{nickname}」的提醒一切正常，收到这条说明配置没问题。\n\n查看积分：{portal_link()}",
    )
    return {
        "ok": True,
        "sent": sent,
        "reason": reason,
        "message": "已发送，去微信看看" if sent else f"发送失败：{reason}",
    }


def resend_notice(account_id: int) -> dict[str, Any]:
    """立刻给某个账号补发一条「今天的签到情况」。

    站长发现用户没收到消息时，点一下就能补一条过去 —— 不用等明天，
    也顺便验证了这个用户的 SendKey 还好不好使。
    """
    account = db.get_account(account_id, with_secrets=True)
    if account is None:
        raise ValueError("账号不存在")
    key = account.get("notify_serverchan") or ""
    nickname = account.get("nickname") or account.get("uid") or "你的账号"
    if not key:
        return {"ok": False, "sent": False,
                "reason": "这个账号还没配微信提醒（SendKey），发不了",
                "message": "这个账号还没配微信提醒（SendKey），发不了 —— 让用户去 /me 开一下"}

    row = db.query_one(
        "SELECT ok, message, credit FROM logs WHERE account_id = ? AND kind = 'checkin' "
        "ORDER BY id DESC LIMIT 1",
        (account_id,),
    )
    if row is None:
        today_line = "今天还没有签到记录，稍后再试，或点「签到」手动跑一次。"
    elif row["ok"]:
        extra = f"，本次 +{row['credit']} 积分" if row["credit"] else ""
        today_line = f"今天的签到已经完成{extra}。"
    else:
        today_line = f"今天的签到失败了：{row['message']}"

    content = "\n".join([
        f"账号「{nickname}」的签到情况（站长手动补发）：",
        "",
        today_line,
        f"当前积分：{_fmt_num(account.get('credits'))}",
        f"查看明细：{portal_link()}",
        "",
        "（如果这条你收到了，说明微信提醒是正常的；收不到就说明 SendKey 需要重新配置。）",
    ])
    ok, reason = push_serverchan_ex(key, "✅ WorkBuddy 今日签到（补发）", content)
    db.add_log("notify", ok, "手动补发|" + ("成功" if ok else f"失败：{reason}"),
               account_id=account_id, uid=account.get("uid", ""), nickname=account.get("nickname", ""))
    return {"ok": ok, "sent": ok, "reason": reason,
            "message": "已补发，让用户看微信" if ok else f"补发失败：{reason}"}


def notify_selftest() -> dict[str, Any]:
    """给每个账号试推一条测试消息，用来定位「为什么用户收不到」。

    一次跑完就能看出：哪些账号压根没配 SendKey（永远收不到），
    哪些配了但 Push 被拒（Key 失效 / 取关 / 超额 / 网络），失败原因一并带出。
    """
    items: list[dict[str, Any]] = []
    for account in db.list_accounts(with_secrets=True):
        nickname = account.get("nickname") or account.get("uid") or "(未命名)"
        key = account.get("notify_serverchan") or ""
        if not key:
            items.append({
                "id": account["id"], "nickname": nickname, "configured": False,
                "ok": None, "reason": "没配 SendKey —— 这类账号永远收不到微信消息",
            })
            continue
        ok, reason = push_serverchan_ex(
            key,
            "WorkBuddy 提醒自检",
            f"账号「{nickname}」的提醒通道正常，收到这条说明没问题。\n\n查看积分：{portal_link()}",
        )
        items.append({
            "id": account["id"], "nickname": nickname, "configured": True,
            "ok": ok, "reason": reason or "正常",
        })
    failed = sum(1 for x in items if x["ok"] is False)
    no_key = sum(1 for x in items if x["ok"] is None)
    return {
        "total": len(items),
        "ok": len(items) - failed - no_key,
        "failed": failed,
        "no_key": no_key,
        "items": items,
    }


def _log_notify_skip(account: dict[str, Any], reason: str) -> None:
    """通知没发出去时，在控制台日志里留一条「为什么没发」。

    以前是直接 return，什么都不记 —— 站长在控制台上看不出任何异常，
    只能听用户说「我没收到」。现在每天每个账号最多留一条，不刷屏。
    """
    message = f"跳过|{reason}"
    account_id = int(account["id"])
    if db.notified_today(account_id, message):
        return
    db.add_log("notify", False, message, account_id=account_id,
               uid=account.get("uid", ""), nickname=account.get("nickname", ""))


def notify_account_result(
    account: dict[str, Any],
    result: "wb.CheckinResult",
    status: Optional[dict[str, Any]] = None,
) -> None:
    """把签到结果推给账号本人。同一个话题每天最多推一条，避免重试时反复轰炸。

    ``status`` 传签到那一刻刚查到的实时数据（wb.query_status 的返回），
    这样消息里的「当前积分」和官方页面是同一秒的数字，不会拿旧值凑。
    """
    account_id = int(account["id"])
    key = account.get("notify_serverchan") or ""
    if not key:
        # 没配 SendKey 的账号天然收不到——但这必须能查到，不能静默
        _log_notify_skip(account, "账号没配微信提醒（SendKey），这条消息没发")
        return
    nickname = account.get("nickname") or account.get("uid") or "你的账号"
    link = portal_link()

    if result.auth_failed:
        topic, title = "expired", "⚠️ WorkBuddy 登录已失效"
        lines = [
            f"账号「{nickname}」的登录凭据已失效，今天的签到已经停下来了。",
            "",
            "别担心，积分和账号数据都还在，重新登录一次就能继续自动签到。",
            "",
            "🔑 重新登录的位置：",
        ]
        lines += _login_help_lines()
        lines += [
            "",
            f"📊 当前积分：{_fmt_num(account.get('credits'))}",
            f"🔗 自助页：{link}",
        ]
        content = "\n".join(lines)
    elif result.ok:
        # 余额优先用「刚刚查到的实时值」，查不到才退回数据库里的上次值
        balance = _fmt_num((status or {}).get("credits") if status else account.get("credits"))
        title = f"✅ 今日已签到｜余额 {balance}"
        topic = "checkin"
        credit = f"本次获得 {_fmt_num(result.credit)} 积分" if result.credit else "今天没有新的积分到账"
        content = (
            f"账号「{nickname}」{result.message}\n"
            f"{credit}\n\n"
            f"📊 当前积分余额：{balance}（官方实时值）\n"
            f"查看积分：{link}"
        )
    else:
        topic, title = "failed", "❌ WorkBuddy 签到失败"
        content = (
            f"账号「{nickname}」签到失败：\n{result.message}\n\n"
            f"查看详情：{link}\n"
            + (f"如果连续几天都失败，可以访问 {SITE_OWNER} 联系站长处理。"
               if SITE_OWNER else "如果连续几天都失败，可以联系站点管理员处理。")
        )

    if db.notified_today(account_id, topic):
        return
    ok, reason = push_serverchan_ex(key, title, content)
    if ok:
        db.add_log("notify", True, topic, account_id=account_id,
                   uid=account.get("uid", ""), nickname=account.get("nickname", ""))
    else:
        logger.warning("给账号 %s 推送提醒失败（topic=%s）：%s", nickname, topic, reason)
        # 注意 message 不能等于 topic，否则会被 notified_today 当成「今天已发过」而挡掉重试
        db.add_log("notify", False, f"{topic}|推送失败：{reason}", account_id=account_id,
                   uid=account.get("uid", ""), nickname=account.get("nickname", ""))


# --------------------------------------------------------------------------- #
# 手动导入
# --------------------------------------------------------------------------- #

def import_manual(
    access_token: str = "",
    uid: str = "",
    domain: str = "",
    nickname: str = "",
    enterprise_id: str = "",
    refresh_token: str = "",
) -> dict[str, Any]:
    """手动导入凭据（不依赖官方登录页的保底方案）。

    两种用法：
    * 只给 ``access_token``：旧的用法，能签到，但令牌过期后要重新导入。
    * 给 ``refresh_token``（access_token 可留空）：导入后由服务器自动续期，
      **导入一次长期免维护** —— 想彻底免人工，优先用这个。
    """
    access_token = (access_token or "").strip()
    refresh_token = (refresh_token or "").strip()
    if not access_token and not refresh_token:
        raise ValueError("accessToken 和 refreshToken 至少要给一个")

    refresh_expires_in = 0
    if not access_token:
        # 只有 refreshToken：先换一次 accessToken，顺手验证它还有效
        try:
            token = wb.refresh_tokens(
                access_token="",
                refresh_token=refresh_token,
                enterprise_id=enterprise_id,
                domain=domain,
            )
        except wb.WbError as exc:
            raise ValueError(f"用 refreshToken 换令牌失败：{exc}") from exc
        access_token = token["accessToken"]
        refresh_token = token["refreshToken"] or refresh_token
        refresh_expires_in = int(token["refreshExpiresIn"] or 0)
        domain = domain or token["domain"]

    claims = wb.decode_jwt_payload(access_token)
    uid = (uid or "").strip() or str(claims.get("uid") or claims.get("sub") or "")
    if not uid:
        raise ValueError("无法从令牌中解析 uid，请手动填写 uid")
    domain = (domain or "").strip() or str(claims.get("domain") or "")
    expires_at = 0
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and exp > 0:
        expires_at = int(exp)

    now = db.now_ts()
    probe = {
        "access_token": access_token,
        "uid": uid,
        "domain": domain,
        "nickname": nickname,
    }
    try:
        info = wb.query_status(probe)
    except wb.WbError as exc:
        info = {"ok": False, "message": str(exc)}

    account_id = db.upsert_account(
        uid=uid,
        access_token=access_token,
        refresh_token=refresh_token,
        domain=domain,
        nickname=nickname or info.get("nickname") or "",
        enterprise_id=enterprise_id,
        expires_at=expires_at,
        refresh_expires_at=now + refresh_expires_in if refresh_expires_in else 0,
        avatar_url=info.get("avatar_url") or "",
        source="manual",
    )
    fields = {"status": "ok" if info.get("ok") else "unknown"}
    if info.get("ok"):
        fields["last_error"] = ""
        fields["credits"] = info.get("credits")
        fields["credits_total"] = info.get("credits_total")
        if info.get("checked_in"):
            fields["last_checkin_date"] = db.today_str()
    else:
        fields["last_error"] = str(info.get("message") or "自检失败")
        if info.get("auth_failed"):
            fields["status"] = "expired"
    db.update_account(account_id, **fields)

    db.add_log("login", bool(info.get("ok")),
               f"手动导入账号{'（自检通过）' if info.get('ok') else '（自检未通过：%s）' % info.get('message', '')}"
               + ("，已保存 refreshToken（自动续期）" if refresh_token else "，未提供 refreshToken（过期后需重新导入）"),
               account_id=account_id, uid=uid, nickname=nickname)
    checkin_async(account_id, trigger="login")

    # 同时生成一套前端（自助页）登录凭据，明文只在这里返回一次
    credential: dict[str, Any] = {}
    try:
        credential = portal.ensure_credentials(account_id)
    except Exception:
        logger.exception("生成前端登录凭据失败：account_id=%s", account_id)

    return {
        "ok": True,
        "account": db.get_account(account_id),
        "probe": info,
        "portal": credential,
    }


def import_batch(text: str) -> dict[str, Any]:
    """导入凭据。**整份文件内容直接丢进来就行**，解析交给这里。

    支持三种输入，自动识别：
    1. 官方客户端的凭据文件整段内容（JSON，单个对象 / 数组 / 多层嵌套都行）
    2. 每行 ``token`` / ``token,uid,domain,昵称``（逗号、竖线、制表符分隔）
    3. ``rt:refreshToken`` 形式（只给 refreshToken，服务器自己换令牌，长期免维护）
    """
    items = parse_credentials_text(text)

    ok, failed = 0, []
    credentials: list[dict[str, Any]] = []
    account_ids: list[int] = []
    for item in items:
        try:
            result = import_manual(**item)
            ok += 1
            account = result.get("account") or {}
            if account.get("id"):
                account_ids.append(int(account["id"]))
            info = result.get("portal") or {}
            if info.get("username"):
                credentials.append({
                    "nickname": account.get("nickname", ""),
                    "username": info.get("username", ""),
                    "password": info.get("password") or "",
                })
        except (ValueError, wb.WbError) as exc:
            head = item.get("access_token") or ("rt:" + str(item.get("refresh_token") or ""))
            failed.append(f"{head[:10]}…：{exc}")
    return {
        "ok": True,
        "total": len(items),
        "imported": ok,
        "failed": failed,
        "credentials": credentials,
        "account_ids": account_ids,
    }


# --------------------------------------------------------------------------- #
# 「原始内容」解析：用户上传什么都能认出来
# --------------------------------------------------------------------------- #

_ACCESS_KEYS = ("accesstoken", "access_token", "accesstokenvalue", "token")
_REFRESH_KEYS = ("refreshtoken", "refresh_token", "refreshtokenvalue")
_UID_KEYS = ("uid", "userid", "user_id", "sub", "accountid")
_DOMAIN_KEYS = ("domain", "host", "iss")
_NICK_KEYS = ("nickname", "name", "username", "displayname")
_ENT_KEYS = ("enterpriseid", "enterprise_id", "entid")


def _pick(source: Any, keys: tuple[str, ...]) -> Any:
    """不区分大小写、忽略下划线和横线地取第一个命中的字段。

    官方凭据文件的字段名在不同版本里变过好几次（``accessToken`` / ``access_token`` /
    ``token``…），所以这里做归一化，用户不用关心自己那份文件长什么样。
    """
    if not isinstance(source, dict):
        return None
    flat: dict[str, Any] = {}
    for key, value in source.items():
        if isinstance(key, str):
            flat[key.replace("_", "").replace("-", "").lower()] = value
    for key in keys:
        if key in flat:
            return flat[key]
    return None


def _pick_deep(node: Any, keys: tuple[str, ...], depth: int = 2) -> Any:
    """先在本层找，找不到再往子对象里找两层。

    官方凭据文件常把用户信息放在 ``credential.user.uid`` 这种位置，
    所以 uid / 昵称要能往下挖。
    """
    got = _pick(node, keys)
    if got not in (None, ""):
        return got
    if depth <= 0 or not isinstance(node, dict):
        return None
    for value in node.values():
        if isinstance(value, dict):
            got = _pick_deep(value, keys, depth - 1)
            if got not in (None, ""):
                return got
    return None


def _as_token(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("value", "token", "accesstoken", "access_token", "refreshtoken"):
            got = _pick(value, (key,))
            if isinstance(got, str) and got.strip():
                return got.strip()
    return ""


def _looks_like_token(value: str) -> bool:
    if not value or len(value) < 20:
        return False
    return " " not in value and "\n" not in value and "\t" not in value


def _walk_credentials(node: Any, out: list[dict[str, Any]], depth: int = 0) -> None:
    """在任意 JSON 结构里找「带令牌的对象」，不管它被包了几层。"""
    if depth > 12:
        return
    if isinstance(node, dict):
        access = _as_token(_pick(node, _ACCESS_KEYS))
        refresh = _as_token(_pick(node, _REFRESH_KEYS))
        if _looks_like_token(access) or _looks_like_token(refresh):
            out.append({
                "access_token": access if _looks_like_token(access) else "",
                "refresh_token": refresh if _looks_like_token(refresh) else "",
                "uid": str(_pick_deep(node, _UID_KEYS) or "").strip(),
                "domain": str(_pick(node, _DOMAIN_KEYS) or "").strip(),
                "nickname": str(_pick_deep(node, _NICK_KEYS) or "").strip(),
                "enterprise_id": str(_pick(node, _ENT_KEYS) or "").strip(),
            })
            return  # 命中就不往下钻，免得同一个账号被拆成好几条
        for value in node.values():
            _walk_credentials(value, out, depth + 1)
    elif isinstance(node, list):
        for value in node:
            _walk_credentials(value, out, depth + 1)


def _loads_forgiving(raw: str) -> Any:
    try:
        return json.loads(raw)
    except ValueError:
        pass
    # 用户可能连文件名、说明文字一起复制了，截取最外层 {...} / [...] 再试一次
    starts = [i for i in (raw.find("{"), raw.find("[")) if i >= 0]
    start = min(starts) if starts else -1
    end = max(raw.rfind("}"), raw.rfind("]"))
    if start >= 0 and end > start:
        try:
            return json.loads(raw[start:end + 1])
        except ValueError:
            pass
    raise ValueError("内容看起来是 JSON，但格式不完整（多半是没复制全）。请重新复制整个文件内容")


def parse_credentials_text(text: str) -> list[dict[str, Any]]:
    """把用户上传的原始内容解析成一条条待导入的凭据。"""
    raw = (text or "").strip()
    if not raw:
        raise ValueError("内容是空的：请把文件内容整段粘贴进来，或者直接选择文件")

    items: list[dict[str, Any]] = []
    looks_json = raw.startswith(("{", "[")) or any(
        f'"{key}"' in raw for key in ("refreshToken", "accessToken", "refresh_token", "access_token")
    )
    if looks_json:
        found: list[dict[str, Any]] = []
        _walk_credentials(_loads_forgiving(raw), found)
        items = found

    if not items:
        items = _parse_token_lines(raw)

    # 去重：同一份文件里同一个令牌只导一次
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for item in items:
        key = (item.get("access_token") or "", item.get("refresh_token") or "", item.get("uid") or "")
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    if not unique:
        raise ValueError(
            "没能从内容里找到 accessToken / refreshToken。"
            "请确认上传的是官方客户端的凭据文件（credentials*.json）"
        )
    return unique


def _parse_token_lines(raw: str) -> list[dict[str, Any]]:
    """按行解析：``token`` / ``token,uid,domain,昵称`` / ``rt:refreshToken``。"""
    items: list[dict[str, Any]] = []
    for raw_line in raw.splitlines():
        line = raw_line.strip().strip(",").strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip().strip('"').strip() for p in _split_fields(line)]
        token = parts[0] if parts else ""
        if not _looks_like_token(token):
            continue
        refresh_token = ""
        lowered = token.lower()
        if lowered.startswith("rt:"):
            refresh_token = token[3:].strip()
            token = ""
        elif lowered.startswith("refresh_token=") or lowered.startswith("refreshtoken="):
            refresh_token = token.split("=", 1)[1].strip()
            token = ""
        items.append({
            "access_token": token,
            "refresh_token": refresh_token,
            "uid": parts[1] if len(parts) > 1 else "",
            "domain": parts[2] if len(parts) > 2 else "",
            "nickname": parts[3] if len(parts) > 3 else "",
            "enterprise_id": "",
        })
    return items


def _split_fields(line: str) -> list[str]:
    for sep in (",", "|", "\t", " "):
        if sep in line:
            return line.split(sep)
    return [line]


def settings_payload() -> dict[str, str]:
    data = db.all_settings()
    data["allow_manual_import"] = "1" if config.ALLOW_MANUAL_IMPORT else "0"
    data["version"] = config.VERSION
    data["tz_offset"] = str(config.TZ_OFFSET_HOURS)
    data["join_token"] = ensure_join_token()
    data["api_base_current"] = wb.current_base()
    data["api_base_default"] = wb.DEFAULT_BASE
    data.pop("secret", None)
    return data


# --------------------------------------------------------------------------- #
# 公开自助入口的令牌
# --------------------------------------------------------------------------- #

def ensure_join_token() -> str:
    """拿到（必要时生成）自助链接里的令牌。

    有了它，别人只能加自己的账号，进不了管理控制台。
    """
    token = db.get_setting("join_token", "").strip()
    if not token:
        token = secrets.token_urlsafe(18)
        db.set_setting("join_token", token)
    return token


def regenerate_join_token() -> str:
    """换一个新令牌，旧链接立刻失效。"""
    token = secrets.token_urlsafe(18)
    db.set_setting("join_token", token)
    db.add_log("system", True, "重新生成自助链接（旧链接已失效）")
    return token


def save_settings(payload: dict[str, Any]) -> dict[str, str]:
    allowed = {
        "checkin_time": str,
        "startup_checkin": str,
        "auto_refresh": str,
        "refresh_lead_seconds": int,
        "keepalive_seconds": int,
        "keepalive_lead_seconds": int,
        "retry_interval_seconds": int,
        "max_retries_per_day": int,
        "notify_webhook": str,
        "notify_type": str,
        "notify_on": str,
        "proxy": str,
        "api_base": str,
        "join_enabled": str,
        "join_max_per_hour": int,
        "auto_cleanup_days": int,
    }
    for key, caster in allowed.items():
        if key not in payload:
            continue
        value = payload[key]
        if caster is int:
            try:
                value = int(value)
            except (TypeError, ValueError):
                continue
            value = max(0, value)
        elif caster is str:
            if isinstance(value, bool):
                value = "1" if value else "0"
            value = str(value).strip()
        if key == "checkin_time" and not _valid_time(str(value)):
            continue
        if key == "api_base" and value:
            value = str(value).rstrip("/")
            if not str(value).startswith("http"):
                value = "https://" + str(value)
            db.set_setting(key, str(value))
            # 立刻生效：清掉域名缓存，下一次请求就走新域名
            wb.reset_base()
            continue
        db.set_setting(key, str(value))
    return settings_payload()


def _valid_time(value: str) -> bool:
    try:
        hour, minute = value.split(":")
        return 0 <= int(hour) <= 23 and 0 <= int(minute) <= 59
    except (ValueError, AttributeError):
        return False


def overview() -> dict[str, Any]:
    accounts = db.list_accounts()
    today = db.count_logs_today("checkin")
    credits = db.credits_total()
    return {
        "accounts": len(accounts),
        "enabled": sum(1 for a in accounts if a.get("enabled")),
        "checked_in_today": sum(1 for a in accounts if a.get("checked_in_today")),
        "ok_today": today["ok"],
        "failed_today": today["fail"],
        "expired": sum(1 for a in accounts if a.get("status") == "expired"),
        "credits": credits["credits"],
        "credits_total": credits["total"],
        # 积分是「签到/自检」那一刻从官方查到的真实余额，不是实时轮询的。
        # 这里把最近一次刷新的时间带出去，界面上标清楚「截至什么时候」，
        # 免得用户拿后台的旧数字和官网比，以为工具算错了。
        "credits_updated_at": max((a.get("updated_at") or 0) for a in accounts) if accounts else 0,
        "settings": db.all_settings(),
        "version": config.VERSION,
        "tz_offset": config.TZ_OFFSET_HOURS,
        "now": db.now_ts(),
        "today": db.today_str(),
    }


def logout_all() -> dict[str, Any]:
    """一键退出全部账号：立即清除本机保存的所有凭据。"""
    count = db.delete_all_accounts()
    db.add_log("system", True, f"一键退出全部账号（{count} 个），本地凭据已全部清除")
    return {"ok": True, "count": count, "message": f"已退出 {count} 个账号，本服务器不再保存任何凭据"}


# --------------------------------------------------------------------------- #
# 清理失效账号
# --------------------------------------------------------------------------- #

def expired_summary(days: int = 0) -> dict[str, Any]:
    """先看一眼会清掉谁（不删除，供前端弹确认框）。"""
    days = max(0, int(days or 0))
    cutoff = int(time.time()) - days * 86400 if days else 0
    accounts = db.expired_accounts(cutoff)
    return {
        "days": days,
        "count": len(accounts),
        "accounts": [
            {
                "id": a.get("id"),
                "nickname": a.get("nickname") or a.get("uid") or "",
                "uid": a.get("uid") or "",
                "updated_at": a.get("updated_at"),
                "last_error": (a.get("last_error") or "")[:80],
            }
            for a in accounts
        ],
    }


def cleanup_expired(days: int = 0) -> dict[str, Any]:
    """删除「需重新登录」的账号。

    days=0 清掉全部失效账号；days=N 只清「失效状态已经持续 N 天以上」的，
    给用户留出重新扫码的缓冲期。只删本地凭据，WorkBuddy 账号本身不受影响。
    """
    days = max(0, int(days or 0))
    targets = expired_summary(days)["accounts"]
    removed: list[str] = []
    for item in targets:
        # 再确认一次：用户点确认到后端执行之间，账号可能刚被「自动修复」救活了
        current = db.get_account(int(item["id"]))
        if not current or current.get("status") != "expired":
            continue
        db.delete_account(int(item["id"]))
        removed.append(str(item.get("nickname") or item.get("uid") or item["id"]))
    if removed:
        suffix = f"（失效超过 {days} 天）" if days else "（全部失效账号）"
        db.add_log("system", True, f"[cleanup] 清理失效账号 {len(removed)} 个{suffix}：{'、'.join(removed[:10])}")
        logger.info("清理失效账号 %s 个：%s", len(removed), "、".join(removed[:10]))
    return {
        "ok": True,
        "removed": len(removed),
        "names": removed,
        "message": f"已清理 {len(removed)} 个失效账号" if removed else "没有需要清理的失效账号",
    }
