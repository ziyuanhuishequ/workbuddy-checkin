"""登录会话管理（电脑端登录）。

每次「添加账号」在服务端开一个独立的登录会话：
用专属的 requests.Session 申请 state 和登录链接，前端把链接给你，你在电脑浏览器里打开，
页面会显示一个二维码，用手机微信扫电脑屏幕上那个码，前端轮询这个会话，拿到令牌就落库。

⚠️ 不再生成二维码图片：把登录链接渲染成二维码让手机扫是走不通的（微信内置浏览器会被官方
的「内网员工探测」挡下来）。所以这里只发链接，扫的必须是电脑屏幕上官方页面的二维码。

会话只存在于内存里（5 分钟就过期），不落盘。
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from . import config, db, portal, service, wb

logger = logging.getLogger("workbuddy.qrlogin")


@dataclass
class LoginSession:
    sid: str
    state: str
    auth_url: str
    session: Any
    created_at: float
    expires_at: float
    status: str = "pending"  # pending / success / failed / expired
    message: str = ""
    finished_at: float = 0.0
    account_id: Optional[int] = None
    account: dict[str, Any] = field(default_factory=dict)


class LoginManager:
    # 登录成功后会话保留多久。前端要在这段时间内把「前端账号密码」取走，
    # 过了就只能用管理员控制台里的「重置密码」再拿一份新的。
    KEEP_FINISHED_SECONDS = 600

    def __init__(self) -> None:
        self._sessions: dict[str, LoginSession] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ #

    def _gc(self) -> None:
        now = time.time()
        for sid, item in list(self._sessions.items()):
            if item.status == "pending":
                if item.expires_at < now:
                    self._sessions.pop(sid, None)
                continue
            finished = item.finished_at or item.created_at
            if now - finished > self.KEEP_FINISHED_SECONDS:
                self._sessions.pop(sid, None)

    def _finish(self, item: LoginSession, status: str, message: str) -> None:
        item.status = status
        item.message = message
        item.finished_at = time.time()

    def start(self) -> dict[str, Any]:
        with self._lock:
            self._gc()
            if len(self._sessions) >= config.QR_MAX_SESSIONS:
                # 清掉最老的一个，避免有人一直点「添加账号」把内存占满
                oldest = min(self._sessions.values(), key=lambda s: s.created_at)
                self._sessions.pop(oldest.sid, None)

            session = wb.new_login_session()
            state, auth_url = wb.start_login(session)
            sid = uuid.uuid4().hex
            now = time.time()
            item = LoginSession(
                sid=sid,
                state=state,
                auth_url=auth_url,
                session=session,
                created_at=now,
                expires_at=now + config.QR_TTL,
            )
            self._sessions[sid] = item
            return {
                "sid": sid,
                "state": state,
                "auth_url": auth_url,
                "expires_in": config.QR_TTL,
            }

    def poll(self, sid: str) -> dict[str, Any]:
        with self._lock:
            item = self._sessions.get(sid)
            if item is None:
                return {"status": "expired", "message": "会话不存在或已过期，请重新发起登录"}

            if item.status in ("success", "failed"):
                return self._snapshot(item)

            if time.time() > item.expires_at:
                self._finish(item, "expired", "登录链接已过期，请重新发起登录")
                return self._snapshot(item)

            try:
                result = wb.poll_login(item.session, item.state)
            except wb.WbError as exc:
                # 单次网络抖动不要让整个扫码流程失败，下一轮继续轮询
                item.message = str(exc)
                return self._snapshot(item)

            if result is None:
                return self._snapshot(item)

            try:
                account_id = self._save(item, result)
            except wb.WbError as exc:
                self._finish(item, "failed", str(exc))
                return self._snapshot(item)

            # 顺手给这个账号生成一套前端（自助页）登录凭据，明文只在这里出现一次
            credential: dict[str, Any] = {}
            try:
                credential = portal.ensure_credentials(account_id)
            except Exception:
                logger.exception("生成前端登录凭据失败：account_id=%s", account_id)

            # 同一个账号同一天重复扫码：凭据照常刷新，但不再重复记账、不再重复触发签到
            uid = str(result.get("uid") or "")
            already_today = db.login_today(uid)

            item.account_id = account_id
            saved = db.get_account(account_id) or {}
            item.account = {
                "id": account_id,
                "uid": uid,
                "nickname": result.get("nickname", ""),
                "domain": result.get("domain", ""),
                "source": "qr",
                "credits": saved.get("credits"),
                "notify_configured": bool(saved.get("notify_configured")),
                "portal_username": credential.get("username", ""),
                "portal_password": credential.get("password") or "",
                "portal_created": bool(credential.get("created")),
                "already_today": already_today,
            }
            self._finish(
                item, "success",
                "这个账号今天已经添加过了" if already_today else "登录成功",
            )

            if not already_today:
                db.add_log(
                    "login",
                    True,
                    f"电脑端登录成功（{item.account['nickname'] or item.account['uid']}）",
                    account_id=account_id,
                    uid=uid,
                    nickname=item.account["nickname"],
                )
            else:
                logger.info("账号 %s 今天已登录过，本次仅刷新凭据", uid)
            # 跑一次「签到判断 + 登录完成通知」。
            # 注意：daily-checkin 并不可靠地幂等 —— 同一个账号重扫后上游还会返回成功
            # 并再发一次积分，所以真正的去重靠 db.checkin_marks（一天一个 uid 只领一次），
            # 已经签过时这里只会得到「今日已签到」，不会再打领取接口。
            service.checkin_async(account_id, trigger="login")
            return self._snapshot(item)

    def cancel(self, sid: str) -> None:
        with self._lock:
            self._sessions.pop(sid, None)

    def _snapshot(self, item: LoginSession) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": item.status,
            "message": item.message,
            "remaining": max(0, int(item.expires_at - time.time())),
        }
        if item.status == "success":
            payload["account"] = item.account
        return payload

    def _save(self, item: LoginSession, result: dict[str, Any]) -> int:
        uid = str(result.get("uid") or "")
        if not uid:
            # login/account 挂了就退回 JWT 声明里找 uid
            claims = wb.decode_jwt_payload(str(result.get("access_token") or ""))
            uid = str(claims.get("uid") or claims.get("sub") or claims.get("userId") or "")
        if not uid:
            raise wb.WbError("登录成功但拿不到账号 uid，请重试")

        expires_in = int(result.get("expires_in") or 0)
        refresh_expires_in = int(result.get("refresh_expires_in") or 0)
        now = int(time.time())
        if not expires_in:
            claims = wb.decode_jwt_payload(str(result.get("access_token") or ""))
            exp = claims.get("exp")
            if isinstance(exp, (int, float)) and exp > 0:
                expires_in = int(exp) - now

        domain = str(result.get("domain") or "")
        if not domain:
            claims = wb.decode_jwt_payload(str(result.get("access_token") or ""))
            domain = str(claims.get("domain") or claims.get("iss") or "")

        return db.upsert_account(
            uid=uid,
            access_token=str(result.get("access_token") or ""),
            refresh_token=str(result.get("refresh_token") or ""),
            domain=domain,
            nickname=str(result.get("nickname") or ""),
            enterprise_id=str(result.get("enterprise_id") or ""),
            expires_at=now + expires_in if expires_in else 0,
            refresh_expires_at=now + refresh_expires_in if refresh_expires_in else 0,
            source="qr",
        )


manager = LoginManager()
