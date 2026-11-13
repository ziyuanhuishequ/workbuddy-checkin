"""WorkBuddy（腾讯 CodeBuddy 国内站）接口客户端。

纯 HTTP 实现，不需要浏览器。三类接口：

* **插件接口** ``/v2/plugin/*`` —— 走的是官方 CLI / 插件通道，
  扫码登录、令牌刷新都在这里。请求头必须伪装成官方 CLI，否则会被拒。
* **登录态对齐** —— 扫码二维码里的 authUrl 可能与接口域名不同，
  必须改写成接口域名，否则手机上完成登录的域和轮询的域不是一个，
  轮询会一直停在「等待扫码」。
* **计费接口** ``/v2/billing/meter/*`` —— 签到与积分，走的是客户端通道，
  网关会拦截默认的 python-requests UA，所以必须带官方 UA。

v1.1.0 主要变更（对齐官方 CLI 2.177.x）：
1. 接口主域名改为 ``www.workbuddy.cn``，并保留 ``copilot.tencent.com`` /
   ``wb.tencentbuddy.com`` 两个备用域名，失败自动切换。
2. 续期请求补上 ``X-Auth-Refresh-Source: plugin``、``X-Domain``、
   ``X-Enterprise-Id``，这三项缺一个都可能被判定为「非官方客户端」。
3. 登录/轮询补上 ``X-No-Authorization`` 等一组头（官方 CLI 一直带）。
4. 令牌响应兼容 camelCase / snake_case，缺 ``expiresIn`` 时用 JWT 的 exp 兜底。

协议细节来自对官方客户端的逆向实现（clean-room），上游随时可能改版。
"""

from __future__ import annotations

import base64
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

import requests

from . import config

# --------------------------------------------------------------------------- #
# 上游域名
# --------------------------------------------------------------------------- #

# 只认官方主站。旧域名 copilot.tencent.com / wb.tencentbuddy.com 的 PC 扫码登录页
# 已经被上游下线：在那两个域名上打开 authUrl，/auth/realms/copilot 直接返回
# 「登录失败 · 账号不存在，请联系企业管理员」。所以它们绝不能再当备用域名。
DEFAULT_BASE = "https://www.workbuddy.cn"
KNOWN_BASES = [
    "https://www.workbuddy.cn",
]

ORIGIN = "https://www.codebuddy.cn"

# 插件通道 UA：必须像官方 CLI
PLUGIN_UA = "CLI/2.63.2 CodeBuddy/2.63.2"
# 计费通道 UA：官方网关会拒绝 python-requests/*
BILLING_UA = "WorkBuddy/1.0"

# 业务码
CODE_OK = 0
CODE_ALREADY_CHECKED_IN = 10001
CODE_LOGIN_PENDING = 11217          # 登录还没完成
CODE_ACCOUNT_PENDING = 12151        # 登录已完成但账号信息还没就绪
CODE_REFRESH_FAILED = 12153         # 续期失败

PENDING_CODES = {CODE_LOGIN_PENDING}
ACCOUNT_PENDING_CODES = {CODE_ACCOUNT_PENDING}

# 续期接口：官方 CLI 两种前缀都用过，按顺序兜底
REFRESH_PATHS = ("/v2/plugin/auth/token/refresh", "/v2/auth/token/refresh")


class WbError(Exception):
    """接口调用失败。"""


class WbAuthError(WbError):
    """凭据失效，需要重新登录。"""


AUTH_HINT = "凭据已失效，请在控制台重新添加该账号"


def _auth_message(status: int) -> str:
    return f"{AUTH_HINT}（HTTP {status}）"


@dataclass
class Envelope:
    code: int = 0
    msg: str = ""
    data: Any = None
    http_status: int = 0
    raw: dict = field(default_factory=dict)
    base: str = ""

    @property
    def ok(self) -> bool:
        return self.code == CODE_OK

    def message(self) -> str:
        if self.code == 0:
            return "ok"
        return self.msg or self.raw.get("message") or f"code={self.code}"


@dataclass
class CheckinResult:
    ok: bool
    message: str
    credit: Optional[int] = None
    claimed: bool = False       # 本次是否真的领取了积分（False = 今天早就签过了）
    auth_failed: bool = False   # 凭据失效，调用方应把账号标记为「需重新登录」
    activity_open: bool = True  # 官方签到活动是否开放（False = 还没开始/已结束，不是错误）


class _NoBody:
    """哨兵：表示这个 POST 要发空 body（跟官方 CLI 的行为一致）。"""


NO_BODY = _NoBody()


# --------------------------------------------------------------------------- #
# 域名选择与故障切换
# --------------------------------------------------------------------------- #

_base_lock = threading.Lock()
_active_base: str = ""
_active_since: float = 0.0

# failover 的保质期：切到备用域名后最多用这么久，然后自动回到主站。
# 没有这个兜底，进程一旦因为一次网络抖动切走，就会永远停在备用域名上。
FAILOVER_TTL = 600


def configured_base() -> str:
    """控制台设置的接口域名；留空用默认主站。"""
    try:
        from . import db

        raw = (db.get_setting("api_base", "") or "").strip()
    except Exception:
        raw = ""
    if not raw:
        raw = config.API_BASE
    raw = raw.strip().rstrip("/")
    if not raw:
        return DEFAULT_BASE
    if not raw.startswith("http"):
        raw = "https://" + raw
    return raw


def candidate_bases() -> list[str]:
    primary = configured_base()
    out = [primary]
    for item in KNOWN_BASES:
        if item not in out:
            out.append(item)
    return out


def current_base() -> str:
    global _active_base
    if _active_base:
        # failover 只是临时救急：超过保质期就尝试回到控制台配置的主站，
        # 否则登录链接会一直签发在备用域名上（旧域名的登录页已经打不开了）。
        if _active_base != configured_base() and time.time() - _active_since > FAILOVER_TTL:
            _active_base = ""
        else:
            return _active_base
    return configured_base()


def reset_base() -> None:
    """设置改了以后清掉缓存，下一次请求用新域名。"""
    global _active_base
    with _base_lock:
        _active_base = ""


def _failover(failed_base: str) -> str:
    """当前域名不通时切到下一个候选域名。"""
    global _active_base, _active_since
    with _base_lock:
        bases = candidate_bases()
        try:
            index = bases.index(failed_base)
        except ValueError:
            index = 0
        _active_base = bases[(index + 1) % len(bases)]
        _active_since = time.time()
        return _active_base


def align_url(url: str) -> str:
    """把链接的域名改写成当前接口域名。

    上游把「登录会话」和「签发 state 的域名」绑定住了：如果二维码里是
    copilot.tencent.com，而手机打开后跳到 www.codebuddy.cn 完成登录，
    那这个 state 的登录结果和我们在 copilot.tencent.com 的轮询就不在同一个域，
    轮询永远停在「等待扫码」。官方 CLI 也是这么做的（alignAuthUrlToApiOrigin）。
    """
    try:
        parsed = urlsplit(url)
        base = urlsplit(current_base())
        if not parsed.netloc or not base.netloc:
            return url
        if parsed.netloc.lower() == base.netloc.lower():
            return url
        return urlunsplit((base.scheme or "https", base.netloc, parsed.path, parsed.query, parsed.fragment))
    except Exception:
        return url


def _abs(path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return current_base() + path


def _proxies() -> Optional[dict[str, str]]:
    """上游代理，取自控制台设置（留空表示直连）。"""
    try:
        from . import db

        proxy = db.get_setting("proxy", "").strip()
    except Exception:
        proxy = ""
    return {"http": proxy, "https": proxy} if proxy else None


# --------------------------------------------------------------------------- #
# 请求头
# --------------------------------------------------------------------------- #

def plugin_headers(ua: str = PLUGIN_UA, token: str = "") -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": ORIGIN,
        "Referer": ORIGIN + "/",
        "User-Agent": ua,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def login_headers(token: str = "") -> dict[str, str]:
    """扫码登录用的头：官方 CLI 会显式声明「本次请求别带鉴权」。"""
    headers = plugin_headers(token=token)
    headers.update({
        "X-No-Authorization": "true",
        "X-No-User-Id": "true",
        "X-No-Enterprise-Id": "true",
        "X-No-Department-Info": "true",
    })
    return headers


def billing_headers(
    access_token: str, uid: str = "", domain: str = "", enterprise_id: str = ""
) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": BILLING_UA,
    }
    if uid:
        headers["X-User-Id"] = uid
    if domain:
        headers["X-Domain"] = domain
    if enterprise_id:
        headers["X-Enterprise-Id"] = enterprise_id
        headers["X-Tenant-Id"] = enterprise_id
    return headers


# --------------------------------------------------------------------------- #
# 底层请求
# --------------------------------------------------------------------------- #

def _parse(raw: bytes, status: int, base: str = "") -> Envelope:
    """解析 {code,msg,data} 信封。

    注意：上游网关在未鉴权时返回的是 **HTML** 错误页而不是 JSON。
    这里绝不能直接抛异常，否则 401 会被报成「响应不是 JSON」，
    调用方就没法判断「凭据失效」了。统一降级成 code=-1 + http_status。
    """
    text = raw.decode("utf-8", errors="replace").strip()
    payload: Any = None
    try:
        payload = json.loads(text or "{}")
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        snippet = " ".join(text[:100].split())
        return Envelope(
            code=-1,
            msg=f"HTTP {status}：响应不是 JSON（{snippet or '空响应'}）",
            data=None,
            http_status=status,
            raw={},
            base=base,
        )
    code = payload.get("code")
    try:
        code = int(code) if code is not None else 0
    except (TypeError, ValueError):
        code = -1
    return Envelope(
        code=code,
        msg=str(payload.get("msg") or payload.get("message") or ""),
        data=payload.get("data"),
        http_status=status,
        raw=payload,
        base=base,
    )


def _do(
    method: str,
    path: str,
    headers: dict[str, str],
    session: Optional[requests.Session] = None,
    body: Any = NO_BODY,
    timeout: Optional[int] = None,
    retry: bool = True,
) -> Envelope:
    """发请求；5xx / 网络异常时自动切备用域名重试一次。"""
    client = session or requests
    attempts = 2 if retry else 1
    last_error: Optional[str] = None

    for attempt in range(attempts):
        url = _abs(path)
        base = current_base()
        kwargs: dict[str, Any] = {
            "headers": headers,
            "timeout": timeout or config.HTTP_TIMEOUT,
        }
        proxy = _proxies()
        if proxy:
            kwargs["proxies"] = proxy
        if method == "POST":
            kwargs["data"] = b"" if body is NO_BODY else json.dumps(body)
        try:
            resp = client.request(method, url, **kwargs)  # type: ignore[union-attr]
        except requests.RequestException as exc:
            last_error = f"网络请求失败：{exc}"
            if attempt + 1 < attempts:
                _failover(base)
                continue
            raise WbError(last_error) from exc

        env = _parse(resp.content, resp.status_code, base)
        if env.http_status >= 500 and attempt + 1 < attempts:
            last_error = f"HTTP {env.http_status}"
            _failover(base)
            continue
        return env

    raise WbError(last_error or "请求失败")


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _clean(value: float) -> int | float:
    return int(value) if abs(value - round(value)) <= 1e-6 else round(value, 2)


def _flag(payload: Any, *names: str) -> Optional[bool]:
    """在响应里找一个布尔标记，兼容 snake_case / camelCase / 嵌套。

    上游同一份数据在不同接口里字段名并不统一（`today_checked_in`、
    `todayCheckedIn`、`checked_in`…），甚至套在 `data` / `result` 里。
    只认一个名字的写法一旦对不上，就会被误判成「今天还没签」→ 重复调签到接口
    → 重复领积分。所以这里宁可多试几个名字。
    """
    if not isinstance(payload, dict):
        return None

    def norm(key: str) -> str:
        return str(key).replace("_", "").lower()

    wanted = {norm(n) for n in names}
    # 先看本层，再看一层嵌套（上游常把结果包一层）
    levels = [payload]
    for key in ("data", "result", "payload", "activity", "checkin"):
        inner = payload.get(key)
        if isinstance(inner, dict):
            levels.append(inner)

    for level in levels:
        for key, value in level.items():
            if norm(key) not in wanted:
                continue
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return bool(value)
            if isinstance(value, str):
                low = value.strip().lower()
                if low in ("1", "true", "yes", "y", "checked", "checked_in", "done", "signed", "已签到"):
                    return True
                if low in ("0", "false", "no", "n", "", "none", "null", "未签到", "unchecked"):
                    return False
    return None


CHECKED_IN_KEYS = (
    "today_checked_in",
    "todayCheckedIn",
    "checked_in",
    "checkedIn",
    "today_signed",
    "todaySigned",
    "signed_today",
    "signedToday",
    "has_checked_in",
    "hasCheckedIn",
    "is_checked_in",
    "isCheckedIn",
    "checkin_done",
    "checkinDone",
)

ACTIVE_KEYS = ("active", "is_active", "isActive", "enabled", "is_open", "isOpen")


# --------------------------------------------------------------------------- #
# 电脑端登录
# --------------------------------------------------------------------------- #

def new_login_session() -> requests.Session:
    """每次扫码登录用独立的 Session。

    上游把浏览器会话和 auth/state 签发的 state 绑定（靠 Cookie），
    所以同一个 state 的所有请求必须共用一套 Cookie，多个账号之间不能串。
    """
    session = requests.Session()
    session.headers.update(login_headers())
    return session


def start_login(session: requests.Session) -> tuple[str, str]:
    """申请登录二维码。返回 (state, auth_url)。auth_url 就是要转成二维码的内容。"""
    env = _do("POST", "/v2/plugin/auth/state?platform=CLI", login_headers(), session=session, body={})
    if not env.ok:
        raise WbError(f"申请二维码失败：{env.message()}")
    data = env.data if isinstance(env.data, dict) else {}
    state = str(data.get("state") or "")
    auth_url = str(data.get("authUrl") or data.get("auth_url") or "")
    if not state or not auth_url:
        raise WbError("申请二维码失败：接口未返回 state / authUrl")
    # 二维码里的域名必须和轮询域名一致，否则扫码后永远等不到结果
    return state, align_url(auth_url)


def poll_login(session: requests.Session, state: str) -> Optional[dict[str, Any]]:
    """轮询扫码结果。

    返回 None 表示还在等待扫码；返回 dict 表示登录成功，包含令牌与账号信息。
    """
    env = _do("GET", f"/v2/plugin/auth/token?state={state}", login_headers(), session=session)
    if not env.ok:
        if env.code in PENDING_CODES:
            return None
        if env.http_status and env.http_status >= 400:
            raise WbError(f"轮询失败：HTTP {env.http_status} {env.message()}")
        # 其它业务码也按「等待中」处理（上游改码时不至于直接失败）
        return None

    payload = env.data if isinstance(env.data, dict) else {}
    access_token = str(payload.get("accessToken") or payload.get("access_token") or "")
    if not access_token:
        return None

    account = fetch_login_account(session, state, access_token)
    token = normalize_token(payload)
    return {
        "access_token": access_token,
        "refresh_token": token["refreshToken"],
        "domain": token["domain"],
        "entry_domain": token["domain"],
        "expires_in": token["expiresIn"],
        "refresh_expires_in": token["refreshExpiresIn"],
        "uid": str(account.get("uid") or ""),
        "nickname": str(account.get("nickname") or ""),
        "enterprise_id": str(account.get("enterpriseId") or account.get("enterprise_id") or ""),
    }


def fetch_login_account(
    session: requests.Session, state: str, access_token: str
) -> dict[str, Any]:
    """登录成功后拉账号信息（uid / 昵称 / 企业 ID）。

    ``login/account`` 在登录完成前会被网关挡成 401 或返回 12151，
    所以只在拿到 bearer 之后调，且把 12151 当成「再等等」。
    这一步失败不影响登录结果，uid 还能从 JWT 里兜底解析。
    """
    for _ in range(3):
        try:
            env = _do(
                "GET",
                f"/v2/plugin/login/account?state={state}",
                login_headers(token=access_token),
                session=session,
            )
        except WbError:
            return {}
        if env.code in ACCOUNT_PENDING_CODES:
            time.sleep(1.0)
            continue
        if not env.ok or not isinstance(env.data, dict):
            return {}
        return env.data
    return {}


def decode_jwt_payload(token: str) -> dict[str, Any]:
    """从 accessToken（无状态 JWT）里解析声明，用于兜底取 uid / 过期时间。

    纯解码，不校验签名——这里只用它做展示和兜底，不作为安全依据。
    """
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload + padding)
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def normalize_token(payload: Any) -> dict[str, Any]:
    """统一令牌响应的字段名，兼容 camelCase / snake_case。

    上游不同通道返回的字段名不一致（accessToken / access_token），
    早期版本只认 camelCase，遇到 snake_case 会把 refreshToken 存成空字符串，
    之后整条续期链就断了 —— 这是「用着用着就要重新扫码」的经典原因。
    """
    data = payload if isinstance(payload, dict) else {}

    def pick(*keys: str) -> Any:
        for key in keys:
            if key in data and data[key] not in (None, ""):
                return data[key]
        return None

    return {
        "accessToken": str(pick("accessToken", "access_token", "token") or ""),
        "refreshToken": str(pick("refreshToken", "refresh_token") or ""),
        "expiresIn": _as_int(pick("expiresIn", "expires_in", "expireIn")),
        "refreshExpiresIn": _as_int(pick("refreshExpiresIn", "refresh_expires_in")),
        "domain": str(pick("domain", "entryDomain", "entry_domain") or ""),
        "enterpriseId": str(pick("enterpriseId", "enterprise_id") or ""),
    }


# --------------------------------------------------------------------------- #
# 令牌续期（自动登录的核心）
# --------------------------------------------------------------------------- #

def refresh_tokens(
    access_token: str,
    refresh_token: str,
    enterprise_id: str = "",
    domain: str = "",
    timeout: int = 30,
) -> dict[str, Any]:
    """拿 refreshToken 换新令牌。返回归一化后的令牌包。

    官方 CLI 的原始请求（2.177.x）：
        POST /v2/plugin/auth/token/refresh
        X-Refresh-Token: <refreshToken>
        X-Auth-Refresh-Source: plugin
        X-Domain: <auth.domain 或接口域名>
        X-Enterprise-Id: <企业 ID>
    少了 X-Auth-Refresh-Source 或写成别的值，服务端会当成别的客户端签发，
    续期直接被拒（12153）。
    """
    if not refresh_token:
        raise WbAuthError("没有 refreshToken，需要重新登录")

    headers = plugin_headers()
    headers["X-Refresh-Token"] = refresh_token
    headers["X-Auth-Refresh-Source"] = "plugin"
    headers["X-Domain"] = domain or urlsplit(current_base()).netloc
    if enterprise_id:
        headers["X-Enterprise-Id"] = enterprise_id
        headers["X-Tenant-Id"] = enterprise_id
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    last_error = "续期失败"
    for path in REFRESH_PATHS:
        env = _do("POST", path, headers, body=NO_BODY, timeout=timeout)

        if env.http_status == 404:
            # 这个前缀没有这条路由，换下一个
            last_error = f"{path} 不存在（404）"
            continue

        if env.http_status in (401, 403) or env.code in (CODE_REFRESH_FAILED, CODE_ALREADY_CHECKED_IN):
            raise WbAuthError(f"续期被拒绝：{env.message()}（HTTP {env.http_status}）")

        if not env.ok:
            last_error = env.message()
            continue

        token = normalize_token(env.data)
        if not token["accessToken"]:
            last_error = "响应里没有 accessToken"
            continue
        if not token["expiresIn"]:
            claims = decode_jwt_payload(token["accessToken"])
            exp = claims.get("exp")
            if isinstance(exp, (int, float)) and exp > int(time.time()):
                token["expiresIn"] = int(exp) - int(time.time())
        if not token["domain"]:
            token["domain"] = domain
        return token

    raise WbError(f"续期失败：{last_error}")


# --------------------------------------------------------------------------- #
# 签到 / 积分
# --------------------------------------------------------------------------- #

def _billing_call(
    account: dict[str, Any], url: str, method: str = "POST"
) -> Envelope:
    access_token = account.get("access_token") or ""
    if not access_token:
        raise WbAuthError("没有 accessToken，需要重新登录")
    headers = billing_headers(
        access_token,
        str(account.get("uid") or ""),
        str(account.get("domain") or ""),
        str(account.get("enterprise_id") or ""),
    )
    env = _do(method, url, headers, body={} if method == "POST" else NO_BODY)
    if env.http_status in (401, 403):
        raise WbAuthError(_auth_message(env.http_status))
    return env


def activity_status(account: dict[str, Any]) -> Envelope:
    return _billing_call(account, "/v2/billing/meter/checkin-activity-status")


def query_balance(account: dict[str, Any]) -> dict[str, int]:
    """实时积分余额（各资源包剩余额度之和）。"""
    env = _billing_call(account, "/billing/meter/get-user-resource-summary")
    if not env.ok:
        raise WbError(f"查询余额失败：{env.message()}")
    data = env.data if isinstance(env.data, dict) else {}
    packages = data.get("Packages") or data.get("packages") or []
    left = sum(_as_float(p.get("CycleRemainCapacity")) for p in packages if isinstance(p, dict))
    total = sum(_as_float(p.get("CycleTotalCapacity")) for p in packages if isinstance(p, dict))
    return {"credits": _clean(left), "credits_total": _clean(total)}


def query_profile(account: dict[str, Any]) -> dict[str, str]:
    env = _billing_call(account, "/v2/accounts", method="GET")
    if not env.ok:
        raise WbError(f"查询账号信息失败：{env.message()}")
    data = env.data if isinstance(env.data, dict) else {}
    accounts = data.get("accounts") or []
    uid = str(account.get("uid") or "")
    me = next((a for a in accounts if isinstance(a, dict) and str(a.get("uid") or "") == uid), None)
    if me is None:
        me = accounts[0] if accounts and isinstance(accounts[0], dict) else {}
    return {
        "nickname": str(me.get("nickname") or ""),
        "avatar_url": str(me.get("avatarUrl") or me.get("avatar_url") or ""),
        "uin": str(me.get("uin") or ""),
    }


def query_status(account: dict[str, Any]) -> dict[str, Any]:
    """账号自检：登录态、今日签到状态、实时积分、昵称。"""
    info: dict[str, Any] = {
        "ok": False,
        "logged_in": False,
        "checked_in": False,
        "credits": None,
        "credits_total": None,
        "today_credit": None,
        "nickname": account.get("nickname") or "",
        "avatar_url": "",
        "active": None,
        "message": "",
        "auth_failed": False,
    }
    try:
        env = activity_status(account)
    except WbAuthError as exc:
        info["message"] = str(exc)
        info["auth_failed"] = True
        return info
    except WbError as exc:
        info["message"] = str(exc)
        return info

    if not env.ok:
        info["message"] = f"接口返回异常：{env.message()}"
        return info

    data = env.data if isinstance(env.data, dict) else {}
    info["ok"] = True
    info["logged_in"] = True
    info["checked_in"] = bool(data.get("today_checked_in"))
    info["active"] = data.get("active")
    # daily_credit 是「每天签到固定能给多少」，用来估算明天的积分
    daily = _clean(_as_float(data.get("daily_credit"))) if data.get("daily_credit") is not None else None
    if data.get("today_checked_in"):
        credit = data.get("today_credit")
        if credit is None:
            credit = data.get("daily_credit")
        info["today_credit"] = _clean(_as_float(credit)) if credit is not None else None
        if daily is None:
            daily = info["today_credit"]
    info["daily_credit"] = daily
    if data.get("active") is False and not data.get("today_checked_in"):
        info["message"] = "登录有效，但官方签到活动未开放或已结束"

    for probe, key in ((query_balance, "balance"), (query_profile, "profile")):
        try:
            result = probe(account)
        except WbError:
            continue
        if key == "balance":
            info["credits"] = result.get("credits")
            info["credits_total"] = result.get("credits_total")
        else:
            if result.get("nickname"):
                info["nickname"] = result["nickname"]
            info["avatar_url"] = result.get("avatar_url") or ""
    return info


def checkin(account: dict[str, Any]) -> CheckinResult:
    """执行一次签到。接口幂等，重复调用安全。"""
    if not account.get("access_token"):
        return CheckinResult(False, "未配置 accessToken")

    try:
        status = activity_status(account)
    except WbAuthError as exc:
        return CheckinResult(False, str(exc), auth_failed=True)
    except WbError as exc:
        return CheckinResult(False, f"查询签到状态失败：{exc}")

    if not status.ok:
        return CheckinResult(False, f"查询签到状态异常：{status.message()}")

    data = status.data if isinstance(status.data, dict) else {}
    active = _flag(data, *ACTIVE_KEYS)
    checked_in = _flag(data, *CHECKED_IN_KEYS)
    if active is False and not checked_in:
        return CheckinResult(False, "官方签到活动未开放或已结束", activity_open=False)

    if checked_in:
        credit = data.get("today_credit")
        if credit is None:
            credit = data.get("daily_credit")
        return CheckinResult(
            True, "今日已签到", _clean(_as_float(credit)) if credit is not None else None, False
        )

    try:
        claim = _billing_call(account, "/v2/billing/meter/daily-checkin")
    except WbAuthError as exc:
        return CheckinResult(False, str(exc), auth_failed=True)
    except WbError as exc:
        return CheckinResult(False, f"领取积分失败：{exc}")

    if claim.code == CODE_OK:
        payload = claim.data if isinstance(claim.data, dict) else {}
        credit = payload.get("credit")
        if credit is None:
            credit = data.get("today_credit") or data.get("daily_credit")
        result = CheckinResult(
            True, "签到成功", _clean(_as_float(credit)) if credit is not None else None, True
        )
    elif claim.code == CODE_ALREADY_CHECKED_IN:
        return CheckinResult(True, "今日已签到", None, False)
    else:
        return CheckinResult(False, f"签到失败：{claim.message()}")

    # 「今日礼包」是尽力而为的附加奖励，上游已经下线（404）就静默跳过
    try:
        gift = _billing_call(account, "/v2/billing/meter/claim-gift")
        if gift.code == CODE_OK:
            result.message += "；今日礼包已领取"
        elif gift.code == CODE_ALREADY_CHECKED_IN:
            result.message += "；今日礼包已领过"
    except WbError:
        pass
    return result


# --------------------------------------------------------------------------- #
# 诊断
# --------------------------------------------------------------------------- #

def diagnose() -> dict[str, Any]:
    """自检上游连通性：每个域名能不能申请二维码、返回什么。

    部署环境出问题时，先看这个结果，比翻日志快得多。
    """
    results = []
    for base in candidate_bases():
        item: dict[str, Any] = {"base": base, "ok": False, "message": "", "auth_url": ""}
        try:
            started = time.time()
            resp = requests.post(
                f"{base}/v2/plugin/auth/state?platform=CLI",
                headers=login_headers(),
                data=b"",
                timeout=min(config.HTTP_TIMEOUT, 15),
                proxies=_proxies(),
            )
            env = _parse(resp.content, resp.status_code, base)
            item["ms"] = int((time.time() - started) * 1000)
            if env.ok and isinstance(env.data, dict) and env.data.get("authUrl"):
                item["ok"] = True
                item["message"] = "可用"
                item["auth_url"] = str(env.data["authUrl"])
            else:
                item["message"] = f"HTTP {env.http_status} {env.message()}"
        except requests.RequestException as exc:
            item["message"] = f"网络不通：{exc}"
        results.append(item)
    return {
        "current_base": current_base(),
        "configured": configured_base(),
        "origins": results,
        "timestamp": int(time.time()),
    }
