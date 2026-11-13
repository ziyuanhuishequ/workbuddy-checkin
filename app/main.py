"""FastAPI 应用：网页控制台 + 管理接口。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import logging.handlers
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from . import config, db, portal, qrlogin, scheduler as scheduler_mod, service, wb

# --------------------------------------------------------------------------- #
# 日志
# --------------------------------------------------------------------------- #

def setup_logging() -> None:
    root = logging.getLogger()
    if root.handlers:
        return
    root.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")

    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    root.addHandler(stream)

    file_handler = logging.handlers.RotatingFileHandler(
        config.LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)


logger = logging.getLogger("workbuddy")

STATIC_DIR = Path(__file__).resolve().parent / "static"


# --------------------------------------------------------------------------- #
# 控制台登录态
# --------------------------------------------------------------------------- #

SESSION_COOKIE = "wb_session"   # 管理员控制台
PORTAL_COOKIE = "wb_portal"     # 用户自助页（一个 WorkBuddy 账号一套）
SESSION_TTL = 7 * 86400


def _sign(payload: bytes) -> str:
    signature = hmac.new(config.SECRET_KEY.encode("utf-8"), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def _make_token(payload: dict[str, Any]) -> str:
    body_data = dict(payload)
    body_data["exp"] = int(time.time()) + SESSION_TTL
    raw = json.dumps(body_data).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{body}.{_sign(raw)}"


def _read_token(token: str, role: str) -> Optional[dict[str, Any]]:
    """校验签名与有效期，并确认角色。

    管理员和用户用的是两个独立 Cookie，角色写进 payload，
    这样用户拿着自己的令牌也调不动管理接口。
    """
    if not token or "." not in token:
        return None
    body, _, signature = token.partition(".")
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except Exception:
        return None
    if not hmac.compare_digest(_sign(raw), signature):
        return None
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if int(data.get("exp", 0)) <= time.time():
        return None
    # 老版本管理员 Cookie 没有 role 字段，按管理员放行
    if data.get("role", "admin") != role:
        return None
    return data


def verify_session_token(token: str) -> bool:
    return _read_token(token, "admin") is not None


_login_failures: dict[str, list[float]] = {}
_join_hits: dict[str, list[float]] = {}


def _throttle_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _check_throttle(key: str) -> None:
    attempts = [ts for ts in _login_failures.get(key, []) if time.time() - ts < 300]
    _login_failures[key] = attempts
    if len(attempts) >= 10:
        raise HTTPException(status_code=429, detail="尝试次数过多，请 5 分钟后再试")


def require_auth(request: Request) -> None:
    if not verify_session_token(request.cookies.get(SESSION_COOKIE, "")):
        raise HTTPException(status_code=401, detail="未登录")


def require_portal(request: Request) -> dict[str, Any]:
    """用户自助页的鉴权依赖，返回 {role, aid, u}。"""
    data = _read_token(request.cookies.get(PORTAL_COOKIE, ""), "portal")
    if data is None:
        raise HTTPException(status_code=401, detail="未登录")
    return data


def _hostname(value: str) -> str:
    """从 URL / Host 头里只取主机名（去掉协议、端口、路径），比较时才不会误判。"""
    raw = (value or "").strip()
    if not raw:
        return ""
    try:
        if "://" not in raw:
            raw = "http://" + raw
        return (urlsplit(raw).hostname or "").lower()
    except ValueError:
        return ""


def require_same_origin(request: Request) -> None:
    """CSRF 兜底：写操作拒绝跨站来源。

    ⚠️ 走 Nginx 反代时，上游收到的 Host 常常是 127.0.0.1:8848，
    而浏览器发来的 Origin 是 https://你的域名 —— 直接拿 Host 和 Origin 比
    会把所有正常请求都判成跨站（表现就是「点确认就报错」）。
    所以这里只比主机名，并且把 X-Forwarded-Host / 请求自带的 base_url 都算作合法来源。
    """
    origin = request.headers.get("origin") or request.headers.get("referer") or ""
    if not origin:
        return  # 同源导航 / 老浏览器不带 Origin：放行，靠 SameSite Cookie 兜底
    origin_host = _hostname(origin)
    if not origin_host:
        return
    allowed = {
        _hostname(request.headers.get("host", "")),
        _hostname(request.headers.get("x-forwarded-host", "")),
        _hostname(str(request.base_url)),
    }
    allowed.discard("")
    loopback = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}
    if allowed and allowed <= loopback:
        # 反代只把 127.0.0.1 传过来，压根没法比对域名。
        # 这种情况放行，CSRF 由 SameSite=Lax 的会话 Cookie 兜底。
        return
    if allowed and origin_host not in allowed:
        raise HTTPException(status_code=403, detail="跨站请求被拒绝")


# --------------------------------------------------------------------------- #
# 生命周期
# --------------------------------------------------------------------------- #

@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    db.init()
    logger.info("数据目录：%s", config.DATA_DIR)
    if config.PASSWORD_AUTOGENERATED:
        logger.warning("=" * 62)
        logger.warning("已自动生成控制台密码：%s", config.PASSWORD)
        logger.warning("（保存在 %s，请登录后妥善保存）", config.PASSWORD_PATH)
        logger.warning("=" * 62)
    else:
        logger.info("控制台密码：来自环境变量或 %s", config.PASSWORD_PATH)
    scheduler_mod.scheduler.start()
    yield
    scheduler_mod.scheduler.stop()


app = FastAPI(title=config.APP_NAME, version=config.VERSION, lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"ok": False, "error": exc.detail})


# --------------------------------------------------------------------------- #
# 请求体
# --------------------------------------------------------------------------- #

class LoginBody(BaseModel):
    password: str = ""


class ManualImportBody(BaseModel):
    access_token: str = ""
    refresh_token: str = ""
    uid: str = ""
    domain: str = ""
    nickname: str = ""
    enterprise_id: str = ""


class BatchImportBody(BaseModel):
    text: str = ""


class AccountPatchBody(BaseModel):
    nickname: Optional[str] = None
    enabled: Optional[bool] = None


class SettingsBody(BaseModel):
    checkin_time: Optional[str] = None
    startup_checkin: Optional[Any] = None
    auto_refresh: Optional[Any] = None
    refresh_lead_seconds: Optional[Any] = None
    retry_interval_seconds: Optional[Any] = None
    max_retries_per_day: Optional[Any] = None
    notify_webhook: Optional[str] = None
    notify_type: Optional[str] = None
    notify_on: Optional[str] = None
    proxy: Optional[str] = None
    api_base: Optional[str] = None
    keepalive_seconds: Optional[Any] = None
    keepalive_lead_seconds: Optional[Any] = None
    auto_cleanup_days: Optional[Any] = None


class CleanupBody(BaseModel):
    days: int = 0


# --------------------------------------------------------------------------- #
# 页面与登录
# --------------------------------------------------------------------------- #

@app.get("/")
def index() -> FileResponse:
    # 不要让浏览器缓存控制台页面：改完前端刷新就能看到，不用 Ctrl+F5
    return FileResponse(
        STATIC_DIR / "index.html",
        media_type="text/html; charset=utf-8",
        headers={"Cache-Control": "no-cache, must-revalidate"},
    )


@app.get("/favicon.ico")
def favicon() -> Response:
    return Response(status_code=204)


# 静态资源（登录页的广告图等）。
# 这里用「后缀白名单」而不是 app.mount("/static", StaticFiles(...))：
#   1) 挂载整个目录会把 index.html / join.html 在 /static/ 下再暴露一份，没必要；
#   2) 白名单能顺手挡掉 ../ 之类的路径穿越。
STATIC_MEDIA_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
}


@app.get("/static/{name}")
def static_asset(name: str) -> FileResponse:
    if not name or "/" in name or "\\" in name or ".." in name:
        raise HTTPException(status_code=404)
    media_type = STATIC_MEDIA_TYPES.get(Path(name).suffix.lower())
    if not media_type:
        raise HTTPException(status_code=404)
    path = STATIC_DIR / name
    if not path.is_file():
        raise HTTPException(status_code=404)
    return FileResponse(
        path,
        media_type=media_type,
        headers={"Cache-Control": "public, max-age=86400"},
    )


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "version": config.VERSION, "name": config.APP_NAME}


@app.get("/api/me")
def me(request: Request) -> dict[str, Any]:
    return {
        "authed": verify_session_token(request.cookies.get(SESSION_COOKIE, "")),
        "version": config.VERSION,
        "name": config.APP_NAME,
        "tz_offset": config.TZ_OFFSET_HOURS,
    }


@app.post("/api/login")
def login(body: LoginBody, request: Request, response: Response) -> dict[str, Any]:
    key = _throttle_key(request)
    _check_throttle(key)
    if not hmac.compare_digest(body.password or "", config.PASSWORD):
        _login_failures.setdefault(key, []).append(time.time())
        raise HTTPException(status_code=401, detail="密码错误")
    _login_failures.pop(key, None)
    response.set_cookie(
        SESSION_COOKIE,
        _make_token({"role": "admin"}),
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return {"ok": True}


@app.post("/api/logout")
def logout(response: Response) -> dict[str, Any]:
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


# --------------------------------------------------------------------------- #
# 概览
# --------------------------------------------------------------------------- #

@app.get("/api/overview", dependencies=[Depends(require_auth)])
def api_overview() -> dict[str, Any]:
    data = service.overview()
    data["next_run_at"] = scheduler_mod.scheduler.next_run_at()
    return {"ok": True, "data": data}


# --------------------------------------------------------------------------- #
# 电脑端登录 / 登录会话
# --------------------------------------------------------------------------- #

@app.post("/api/qr/start", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def qr_start() -> dict[str, Any]:
    """开一个登录会话，拿一条「在电脑浏览器打开」的登录链接（不再生成二维码图片）。"""
    try:
        return {"ok": True, "data": qrlogin.manager.start()}
    except Exception as exc:  # 网络不通 / 上游改协议
        logger.warning("申请登录链接失败：%s", exc)
        raise HTTPException(status_code=502, detail=f"申请登录链接失败：{exc}") from exc


@app.get("/api/qr/poll/{sid}", dependencies=[Depends(require_auth)])
def qr_poll(sid: str) -> dict[str, Any]:
    return {"ok": True, "data": qrlogin.manager.poll(sid)}


@app.post("/api/qr/cancel/{sid}", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def qr_cancel(sid: str) -> dict[str, Any]:
    qrlogin.manager.cancel(sid)
    return {"ok": True}


# --------------------------------------------------------------------------- #
# 账号
# --------------------------------------------------------------------------- #

@app.get("/api/accounts", dependencies=[Depends(require_auth)])
def api_accounts() -> dict[str, Any]:
    accounts = db.list_accounts()
    for account in accounts:
        account_id = int(account["id"])
        account["last_log"] = db.last_checkin_log(account_id)
        account["today_credit"] = db.today_credit(account_id)
        account["total_success"] = db.total_success(account_id)
    return {"ok": True, "data": accounts}


@app.get("/api/accounts/expired", dependencies=[Depends(require_auth)])
def api_expired_accounts(days: int = 0) -> dict[str, Any]:
    """清理前的预览：有哪些失效账号会被删（不删）。"""
    return {"ok": True, "data": service.expired_summary(days)}


@app.post("/api/accounts/cleanup", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_cleanup_accounts(body: CleanupBody) -> dict[str, Any]:
    # 后端出错时也回一份结构化的 JSON，前端才能把原因（而不是裸 500）显示出来
    try:
        return {"ok": True, "data": service.cleanup_expired(body.days)}
    except Exception as exc:  # noqa: BLE001
        logger.exception("清理失效账号失败")
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@app.delete("/api/accounts/{account_id}", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_delete_account(account_id: int) -> dict[str, Any]:
    account = db.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="账号不存在")
    db.add_log("system", True, "退出登录，已清除该账号凭据", account_id=account_id,
               uid=account.get("uid", ""), nickname=account.get("nickname", ""))
    db.delete_account(account_id)
    return {"ok": True, "message": "已退出登录，本服务器不再保存该账号的任何凭据"}


@app.post("/api/accounts/logout-all", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_logout_all() -> dict[str, Any]:
    return service.logout_all()


@app.patch("/api/accounts/{account_id}", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_patch_account(account_id: int, body: AccountPatchBody) -> dict[str, Any]:
    account = db.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="账号不存在")
    fields: dict[str, Any] = {}
    if body.nickname is not None:
        fields["nickname"] = body.nickname.strip()
    if body.enabled is not None:
        fields["enabled"] = body.enabled
    if fields:
        db.update_account(account_id, **fields)
    return {"ok": True, "data": db.get_account(account_id)}


@app.post("/api/accounts/{account_id}/checkin", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_checkin(account_id: int) -> dict[str, Any]:
    try:
        return {"ok": True, "data": service.checkin_account(account_id, trigger="manual")}
    except service.AccountNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/accounts/{account_id}/refresh", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_refresh(account_id: int) -> dict[str, Any]:
    try:
        return {"ok": True, "data": service.refresh_account(account_id, force=True)}
    except service.AccountNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/accounts/{account_id}/recover", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_recover(account_id: int) -> dict[str, Any]:
    """「登录失效」账号的一键复活：自动续期 + 立刻补签一次。"""
    try:
        refreshed = service.refresh_account(account_id, force=True)
        if not refreshed.get("ok"):
            return {"ok": True, "data": {"refreshed": False, "message": refreshed.get("message", "")}}
        result = service.checkin_account(account_id, trigger="recover")
        return {"ok": True, "data": {"refreshed": True, "checkin": result}}
    except service.AccountNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/keepalive", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_keepalive() -> dict[str, Any]:
    """手动触发一次令牌保活（提前续期 + 复活失效账号）。"""
    return {"ok": True, "data": service.keepalive_all(force=True)}


@app.get("/api/diagnose", dependencies=[Depends(require_auth)])
def api_diagnose() -> dict[str, Any]:
    """上游连通性自检：哪个域名能用、二维码能不能申请到。"""
    return {"ok": True, "data": wb.diagnose()}


@app.post("/api/accounts/{account_id}/status", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_status(account_id: int) -> dict[str, Any]:
    try:
        return {"ok": True, "data": service.sync_status(account_id)}
    except service.AccountNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/accounts/checkin-all", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_checkin_all() -> dict[str, Any]:
    return {"ok": True, "data": service.checkin_all(trigger="manual")}


@app.post("/api/accounts/import", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_import(body: ManualImportBody) -> dict[str, Any]:
    if not config.ALLOW_MANUAL_IMPORT:
        raise HTTPException(status_code=403, detail="手动导入已在服务端关闭")
    try:
        return {"ok": True, "data": service.import_manual(**body.model_dump())}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/accounts/import-batch", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_import_batch(body: BatchImportBody) -> dict[str, Any]:
    if not config.ALLOW_MANUAL_IMPORT:
        raise HTTPException(status_code=403, detail="手动导入已在服务端关闭")
    try:
        return {"ok": True, "data": service.import_batch(body.text)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# --------------------------------------------------------------------------- #
# 日志与设置
# --------------------------------------------------------------------------- #

@app.get("/api/logs", dependencies=[Depends(require_auth)])
def api_logs(limit: int = 100, account_id: Optional[int] = None, kind: str = "") -> dict[str, Any]:
    return {"ok": True, "data": db.list_logs(limit=limit, account_id=account_id, kind=kind)}


@app.get("/api/settings", dependencies=[Depends(require_auth)])
def api_settings() -> dict[str, Any]:
    return {"ok": True, "data": service.settings_payload()}


@app.post("/api/settings", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_save_settings(body: SettingsBody) -> dict[str, Any]:
    payload = {key: value for key, value in body.model_dump().items() if value is not None}
    return {"ok": True, "data": service.save_settings(payload)}


@app.post("/api/notify/test", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_notify_test() -> dict[str, Any]:
    try:
        return service.send_test_notification()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/notify/selftest", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_notify_selftest() -> dict[str, Any]:
    """逐个账号试推一条，定位「用户为什么收不到微信消息」。"""
    return {"ok": True, "data": service.notify_selftest()}


@app.post("/api/accounts/{account_id}/notice", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_account_notice(account_id: int) -> dict[str, Any]:
    """立刻给某个账号补发一条今天的签到消息。"""
    try:
        return {"ok": True, "data": service.resend_notice(account_id)}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/accounts/{account_id}/portal", dependencies=[Depends(require_auth)])
def api_portal_reveal(account_id: int) -> dict[str, Any]:
    """管理员查看某账号的前端登录账号密码 —— 随时可查，不再是一次性。"""
    try:
        return {"ok": True, "data": portal.reveal(account_id)}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/accounts/{account_id}/portal/reset", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_portal_reset(account_id: int) -> dict[str, Any]:
    """管理员重置某账号的前端登录密码（明文只返回这一次）。"""
    try:
        result = portal.reset_password(account_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    db.add_log("system", True, f"重置前端登录密码（{result['username']}）", account_id=account_id)
    return {"ok": True, "data": result}


# --------------------------------------------------------------------------- #
# 用户自助页 /me：一个 WorkBuddy 账号一套账号密码，只能看到自己那一个号
# --------------------------------------------------------------------------- #

class PortalLoginBody(BaseModel):
    username: str = ""
    password: str = ""


class PortalPauseBody(BaseModel):
    enabled: bool = True


class PortalPasswordBody(BaseModel):
    old_password: str = ""
    new_password: str = ""


class PortalNotifyBody(BaseModel):
    sendkey: str = ""


@app.get("/me")
def portal_page() -> FileResponse:
    return FileResponse(
        STATIC_DIR / "portal.html",
        media_type="text/html; charset=utf-8",
        headers={"Cache-Control": "no-cache, must-revalidate"},
    )


@app.get("/api/portal/me")
def portal_me(request: Request) -> dict[str, Any]:
    session = _read_token(request.cookies.get(PORTAL_COOKIE, ""), "portal")
    return {
        "ok": True,
        "authed": session is not None,
        "username": (session or {}).get("u", ""),
    }


@app.post("/api/portal/login")
def portal_login(body: PortalLoginBody, request: Request, response: Response) -> dict[str, Any]:
    key = "portal:" + _throttle_key(request)
    _check_throttle(key)
    identity = portal.authenticate(body.username, body.password)
    if identity is None:
        _login_failures.setdefault(key, []).append(time.time())
        raise HTTPException(status_code=401, detail="账号或密码不正确")
    _login_failures.pop(key, None)
    response.set_cookie(
        PORTAL_COOKIE,
        _make_token({"role": "portal", "aid": identity["account_id"], "u": identity["username"]}),
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        path="/",
    )
    db.add_log("portal", True, "用户登录自助页", account_id=int(identity["account_id"]))
    service.remember_site_url(
        request.headers.get("x-forwarded-proto") or request.url.scheme,
        request.headers.get("host", ""),
    )
    return {"ok": True, "username": identity["username"]}


@app.post("/api/portal/logout")
def portal_logout(response: Response) -> dict[str, Any]:
    response.delete_cookie(PORTAL_COOKIE, path="/")
    return {"ok": True}


@app.get("/api/portal/overview")
def portal_overview(session: dict = Depends(require_portal)) -> dict[str, Any]:
    account_id = int(session["aid"])
    account = db.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="账号不存在或已被移除")
    return {
        "ok": True,
        "data": {
            "username": session["u"],
            "nickname": account.get("nickname") or "",
            "uid": account.get("uid") or "",
            "enabled": account.get("enabled"),
            "status": account.get("status"),
            "checked_in_today": account.get("checked_in_today"),
            "today_credit": db.today_credit(account_id),
            "credits": account.get("credits"),
            "credits_total": account.get("credits_total"),
            "total_success": db.total_success(account_id),
            "last_checkin_at": account.get("last_checkin_at"),
            "token_expires_at": account.get("expires_at"),
            "auto_refresh": db.get_bool_setting("auto_refresh", True),
            "checkin_time": db.get_setting("checkin_time", "09:00"),
            "next_run_at": scheduler_mod.scheduler.next_run_at(),
            "portal_last_login": account.get("portal_last_login"),
            "pw_changed": account.get("portal_pw_changed"),
            "notify_configured": account.get("notify_configured"),
        },
    }


@app.post("/api/portal/notify", dependencies=[Depends(require_same_origin)])
def portal_notify(body: PortalNotifyBody, session: dict = Depends(require_portal)) -> dict[str, Any]:
    """用户配置自己的微信提醒（Server 酱）。会立刻发一条确认消息。"""
    try:
        return service.save_account_notify(int(session["aid"]), body.sendkey)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/portal/notify/off", dependencies=[Depends(require_same_origin)])
def portal_notify_off(session: dict = Depends(require_portal)) -> dict[str, Any]:
    try:
        return service.clear_account_notify(int(session["aid"]))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/portal/notify/test", dependencies=[Depends(require_same_origin)])
def portal_notify_test(session: dict = Depends(require_portal)) -> dict[str, Any]:
    try:
        return service.test_account_notify(int(session["aid"]))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/portal/history")
def portal_history(limit: int = 30, session: dict = Depends(require_portal)) -> dict[str, Any]:
    return {"ok": True, "data": db.list_logs(limit=limit, account_id=int(session["aid"]), kind="checkin")}


@app.post("/api/portal/pause", dependencies=[Depends(require_same_origin)])
def portal_pause(body: PortalPauseBody, session: dict = Depends(require_portal)) -> dict[str, Any]:
    account_id = int(session["aid"])
    if db.get_account(account_id) is None:
        raise HTTPException(status_code=404, detail="账号不存在")
    db.update_account(account_id, enabled=body.enabled)
    db.add_log("portal", True,
               "用户恢复了自动签到" if body.enabled else "用户暂停了自动签到",
               account_id=account_id)
    return {
        "ok": True,
        "enabled": body.enabled,
        "message": "已恢复自动签到" if body.enabled else "已暂停自动签到",
    }


@app.post("/api/portal/password", dependencies=[Depends(require_same_origin)])
def portal_password(body: PortalPasswordBody, session: dict = Depends(require_portal)) -> dict[str, Any]:
    account_id = int(session["aid"])
    try:
        portal.change_password(account_id, body.old_password, body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.add_log("portal", True, "用户修改了自助页密码", account_id=account_id)
    return {"ok": True, "message": "密码已修改，下次请用新密码登录"}


@app.post("/api/portal/unbind", dependencies=[Depends(require_same_origin)])
def portal_unbind(response: Response, session: dict = Depends(require_portal)) -> dict[str, Any]:
    account_id = int(session["aid"])
    account = db.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="账号不存在")
    db.add_log("portal", True, "用户自助退出登录，凭据已清除", account_id=account_id,
               uid=account.get("uid", ""), nickname=account.get("nickname", ""))
    db.delete_account(account_id)
    response.delete_cookie(PORTAL_COOKIE, path="/")
    return {"ok": True, "message": "已退出登录。本服务器已删除你的全部凭据，不再为你签到。"}


# --------------------------------------------------------------------------- #
# 公开自助入口 /join
# 拿着带令牌链接的人可以自己加自己的账号、拿到自己的查看凭据，
# 但完全碰不到管理控制台，也看不到任何别人的数据。
# --------------------------------------------------------------------------- #

def _require_join(token: str) -> None:
    if not db.get_bool_setting("join_enabled", True):
        raise HTTPException(status_code=403, detail="管理员已关闭自助入口")
    if not hmac.compare_digest((token or "").strip(), service.ensure_join_token()):
        raise HTTPException(status_code=403, detail="链接无效或已失效，请向管理员索取最新链接")


def _check_join_rate(request: Request) -> None:
    limit = max(1, db.get_int_setting("join_max_per_hour", 20))
    key = _throttle_key(request)
    now = time.time()
    hits = [ts for ts in _join_hits.get(key, []) if now - ts < 3600]
    if len(hits) >= limit:
        raise HTTPException(status_code=429, detail="操作过于频繁，请过一会儿再试")
    hits.append(now)
    _join_hits[key] = hits


@app.get("/join")
def join_page() -> FileResponse:
    return FileResponse(
        STATIC_DIR / "join.html",
        media_type="text/html; charset=utf-8",
        headers={"Cache-Control": "no-cache, must-revalidate"},
    )


@app.post("/api/join/qr")
def api_join_qr(request: Request, t: str = "") -> dict[str, Any]:
    _require_join(t)
    _check_join_rate(request)
    service.remember_site_url(
        request.headers.get("x-forwarded-proto") or request.url.scheme,
        request.headers.get("host", ""),
    )
    try:
        data = qrlogin.manager.start()
    except Exception as exc:
        logger.warning("自助登录：申请登录链接失败：%s", exc)
        raise HTTPException(status_code=502, detail=f"登录链接申请失败：{exc}") from exc
    # 只发链接，不发二维码图片。
    # 把登录链接渲染成二维码让手机扫是走不通的（微信内置浏览器会被官方「内网员工探测」挡下），
    # 唯一可行的是：用户在**电脑浏览器**里打开这条链接，页面自己显示二维码，再用手机微信扫电脑屏幕。
    return {
        "ok": True,
        "data": {
            "sid": data["sid"],
            "auth_url": data.get("auth_url", ""),
            "expires_in": data["expires_in"],
        },
    }


@app.get("/api/join/poll/{sid}")
def api_join_poll(sid: str, t: str = "") -> dict[str, Any]:
    _require_join(t)
    data = qrlogin.manager.poll(sid)
    result: dict[str, Any] = {"status": data.get("status"), "message": data.get("message", "")}
    if data.get("status") == "success":
        account = data.get("account") or {}
        # 只返回「刚扫的这个账号」的凭据，不带任何别人的信息
        result["nickname"] = account.get("nickname", "")
        result["credentials"] = {
            "username": account.get("portal_username", ""),
            "password": account.get("portal_password", ""),
        }
        result["login_path"] = "/me"
        result["already_today"] = bool(account.get("already_today"))
    return {"ok": True, "data": result}


@app.post("/api/join/regenerate", dependencies=[Depends(require_auth), Depends(require_same_origin)])
def api_join_regenerate() -> dict[str, Any]:
    return {"ok": True, "data": {"join_token": service.regenerate_join_token()}}


MAX_RAW_IMPORT_BYTES = 256 * 1024


@app.post("/api/join/import")
def api_join_import(request: Request, body: BatchImportBody, t: str = "") -> dict[str, Any]:
    """自助页的「上传令牌文件」：整份文件内容丢进来，服务器自己解析。

    和电脑端登录是同一条信任边界 —— 谁能拿到带令牌的 /join 链接，谁就能加自己的账号，
    但拿不到任何别人的数据。所以这里只返回**刚导入的这个账号**的查看凭据。
    """
    _require_join(t)
    _check_join_rate(request)
    if not config.ALLOW_MANUAL_IMPORT:
        raise HTTPException(status_code=403, detail="管理员已关闭自助导入，请改用电脑端登录")

    text = (body.text or "").strip()
    if len(text.encode("utf-8")) > MAX_RAW_IMPORT_BYTES:
        raise HTTPException(status_code=413, detail="内容太大了，请只粘贴凭据文件本身的内容")

    try:
        data = service.import_batch(text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    first = (data.get("credentials") or [{}])[0]
    result: dict[str, Any] = {
        "imported": data["imported"],
        "total": data["total"],
        "failed": data["failed"],
        "nickname": first.get("nickname", ""),
        "credentials": {
            "username": first.get("username", ""),
            "password": first.get("password", ""),
        },
        "login_path": "/me",
    }
    if not data["imported"]:
        raise HTTPException(
            status_code=400,
            detail="导入失败：" + ("；".join(data["failed"]) or "没有可用的令牌"),
        )
    return {"ok": True, "data": result}

