"""SQLite 持久化层。

单文件数据库 + 一把全局锁。这个量级（几十个账号、每天几十条日志）完全够用，
没必要引入 ORM 或独立数据库。
"""

from __future__ import annotations

import sqlite3
import threading
import time
from datetime import datetime
from typing import Any, Iterable, Optional

from . import config
from .crypto import decrypt, encrypt

_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    uid                 TEXT    NOT NULL UNIQUE,
    enterprise_id       TEXT    NOT NULL DEFAULT '',
    nickname            TEXT    NOT NULL DEFAULT '',
    domain              TEXT    NOT NULL DEFAULT '',
    access_token        TEXT    NOT NULL DEFAULT '',
    refresh_token       TEXT    NOT NULL DEFAULT '',
    expires_at          INTEGER NOT NULL DEFAULT 0,
    refresh_expires_at  INTEGER NOT NULL DEFAULT 0,
    enabled             INTEGER NOT NULL DEFAULT 1,
    status              TEXT    NOT NULL DEFAULT 'unknown',
    last_error          TEXT    NOT NULL DEFAULT '',
    last_checkin_date   TEXT    NOT NULL DEFAULT '',
    last_checkin_at     INTEGER NOT NULL DEFAULT 0,
    credits             INTEGER,
    credits_total       INTEGER,
    avatar_url          TEXT    NOT NULL DEFAULT '',
    source              TEXT    NOT NULL DEFAULT 'qr',
    -- 前端（用户自助页）登录凭据：一个 WorkBuddy 账号对应一套
    portal_username     TEXT    NOT NULL DEFAULT '',
    portal_password     TEXT    NOT NULL DEFAULT '',   -- pbkdf2 哈希，登录校验用
    portal_secret       TEXT    NOT NULL DEFAULT '',   -- 加密后的明文，供管理员随时查看/转交
    portal_last_login   INTEGER NOT NULL DEFAULT 0,
    portal_pw_changed   INTEGER NOT NULL DEFAULT 0,
    -- 每个账号自己的 Server 酱 SendKey（加密存），用来给用户本人推提醒
    notify_serverchan    TEXT    NOT NULL DEFAULT '',
    created_at          INTEGER NOT NULL DEFAULT 0,
    updated_at          INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    account_id  INTEGER,
    uid         TEXT    NOT NULL DEFAULT '',
    nickname    TEXT    NOT NULL DEFAULT '',
    kind        TEXT    NOT NULL DEFAULT 'system',
    ok          INTEGER NOT NULL DEFAULT 0,
    claimed     INTEGER NOT NULL DEFAULT 0,
    message     TEXT    NOT NULL DEFAULT '',
    credit      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs (ts DESC);
CREATE INDEX IF NOT EXISTS idx_logs_account ON logs (account_id, ts DESC);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- 每天每个 uid 只允许真正调一次上游签到。
-- 单独建表而不是复用 accounts.last_checkin_date：用户删号重加（很常见）时
-- accounts 行会被重建，但「这个 uid 今天已经签过」这件事不能跟着丢，
-- 否则每重扫一次就会再领一次积分。
CREATE TABLE IF NOT EXISTS checkin_marks (
    uid     TEXT    NOT NULL,
    date    TEXT    NOT NULL,
    credit  INTEGER,
    ts      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (uid, date)
);
"""


def connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(str(config.DB_PATH), check_same_thread=False, timeout=15)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _conn.execute("PRAGMA foreign_keys=ON")
    return _conn


def init() -> None:
    with _lock:
        conn = connect()
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()
        for key, value in config.DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value)
            )
        conn.commit()


# 加过的列都放这里：老库升级时自动补上，不用手工改表
_ACCOUNT_MIGRATIONS: dict[str, str] = {
    "portal_username": "TEXT NOT NULL DEFAULT ''",
    "portal_password": "TEXT NOT NULL DEFAULT ''",
    "portal_secret": "TEXT NOT NULL DEFAULT ''",
    "portal_last_login": "INTEGER NOT NULL DEFAULT 0",
    "portal_pw_changed": "INTEGER NOT NULL DEFAULT 0",
    "notify_serverchan": "TEXT NOT NULL DEFAULT ''",
}


def _migrate(conn: sqlite3.Connection) -> None:
    """轻量迁移：CREATE TABLE IF NOT EXISTS 不会给老表补列，这里手动补。"""
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(accounts)")}
    for column, declaration in _ACCOUNT_MIGRATIONS.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE accounts ADD COLUMN {column} {declaration}")
    # 前端用户名唯一（空值不参与，partial index 需要 SQLite 3.8+）
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_portal_user "
        "ON accounts (portal_username) WHERE portal_username <> ''"
    )


# --------------------------------------------------------------------------- #
# 通用工具
# --------------------------------------------------------------------------- #

def now_ts() -> int:
    return int(time.time())


def today_str(ts: Optional[int] = None) -> str:
    """本地时区（默认东八区）下的 YYYY-MM-DD。"""
    dt = datetime.fromtimestamp(ts if ts is not None else time.time(), config.TZ)
    return dt.strftime("%Y-%m-%d")


def query(sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
    with _lock:
        return list(connect().execute(sql, tuple(params)).fetchall())


def query_one(sql: str, params: Iterable[Any] = ()) -> Optional[sqlite3.Row]:
    rows = query(sql, params)
    return rows[0] if rows else None


def execute(sql: str, params: Iterable[Any] = ()) -> int:
    with _lock:
        conn = connect()
        cur = conn.execute(sql, tuple(params))
        conn.commit()
        return cur.lastrowid or 0


# --------------------------------------------------------------------------- #
# settings
# --------------------------------------------------------------------------- #

def get_setting(key: str, default: str = "") -> str:
    row = query_one("SELECT value FROM settings WHERE key = ?", (key,))
    if row is None:
        return config.DEFAULT_SETTINGS.get(key, default)
    return str(row["value"])


def get_int_setting(key: str, default: int = 0) -> int:
    try:
        return int(get_setting(key, str(default)))
    except (TypeError, ValueError):
        return default


def get_bool_setting(key: str, default: bool = False) -> bool:
    raw = get_setting(key, "1" if default else "0").strip().lower()
    return raw in ("1", "true", "yes", "on", "y")


def set_setting(key: str, value: str) -> None:
    execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def all_settings() -> dict[str, str]:
    result = dict(config.DEFAULT_SETTINGS)
    for row in query("SELECT key, value FROM settings"):
        result[str(row["key"])] = str(row["value"])
    return result


# --------------------------------------------------------------------------- #
# accounts
# --------------------------------------------------------------------------- #

_ACCOUNT_SECRET_FIELDS = ("access_token", "refresh_token")


def row_to_account(row: sqlite3.Row, with_secrets: bool = False) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": row["id"],
        "uid": row["uid"],
        "enterprise_id": row["enterprise_id"],
        "nickname": row["nickname"],
        "domain": row["domain"],
        "expires_at": row["expires_at"],
        "refresh_expires_at": row["refresh_expires_at"],
        "enabled": bool(row["enabled"]),
        "status": row["status"],
        "last_error": row["last_error"],
        "last_checkin_date": row["last_checkin_date"],
        "last_checkin_at": row["last_checkin_at"],
        "credits": row["credits"],
        "credits_total": row["credits_total"],
        "avatar_url": row["avatar_url"],
        "source": row["source"],
        "portal_username": row["portal_username"],
        "portal_last_login": row["portal_last_login"],
        "portal_pw_changed": bool(row["portal_pw_changed"]),
        "notify_configured": bool(row["notify_serverchan"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "checked_in_today": row["last_checkin_date"] == today_str(),
    }
    if with_secrets:
        data["access_token"] = decrypt(row["access_token"])
        data["refresh_token"] = decrypt(row["refresh_token"])
        data["notify_serverchan"] = decrypt(row["notify_serverchan"])
    else:
        data["token_hint"] = ""
        plain = decrypt(row["access_token"])
        data["token_hint"] = f"{plain[:6]}...{plain[-6:]}" if len(plain) > 14 else "*" * len(plain)
    return data


def list_accounts(with_secrets: bool = False) -> list[dict[str, Any]]:
    rows = query("SELECT * FROM accounts ORDER BY id ASC")
    return [row_to_account(row, with_secrets) for row in rows]


def get_account(account_id: int, with_secrets: bool = False) -> Optional[dict[str, Any]]:
    row = query_one("SELECT * FROM accounts WHERE id = ?", (account_id,))
    return row_to_account(row, with_secrets) if row else None


def get_account_by_uid(uid: str) -> Optional[dict[str, Any]]:
    row = query_one("SELECT * FROM accounts WHERE uid = ?", (uid,))
    return row_to_account(row) if row else None


def expired_accounts(older_than_ts: int = 0) -> list[dict[str, Any]]:
    """「需重新登录」的账号。older_than_ts > 0 时只取最后变动早于该时间的。"""
    if older_than_ts > 0:
        rows = query(
            "SELECT * FROM accounts WHERE status = 'expired' AND updated_at <= ? ORDER BY id ASC",
            (older_than_ts,),
        )
    else:
        rows = query("SELECT * FROM accounts WHERE status = 'expired' ORDER BY id ASC")
    return [row_to_account(row) for row in rows]


def upsert_account(
    uid: str,
    access_token: str,
    refresh_token: str = "",
    domain: str = "",
    nickname: str = "",
    enterprise_id: str = "",
    expires_at: int = 0,
    refresh_expires_at: int = 0,
    avatar_url: str = "",
    source: str = "qr",
) -> int:
    """按 uid 新增或更新账号；token 到期时间与昵称会被刷新。"""
    ts = now_ts()
    existing = query_one("SELECT id, refresh_token FROM accounts WHERE uid = ?", (uid,))
    # 上游偶尔不回吐 refreshToken，此时保留旧的，别把可续期的凭据弄丢
    effective_refresh = refresh_token or (decrypt(existing["refresh_token"]) if existing else "")
    if existing:
        execute(
            """UPDATE accounts SET
                   access_token = ?, refresh_token = ?, domain = ?, nickname = ?,
                   enterprise_id = ?, expires_at = ?, refresh_expires_at = ?,
                   avatar_url = ?, status = 'ok', last_error = '', updated_at = ?
               WHERE uid = ?""",
            (
                encrypt(access_token),
                encrypt(effective_refresh),
                domain,
                nickname,
                enterprise_id,
                expires_at,
                refresh_expires_at,
                avatar_url,
                ts,
                uid,
            ),
        )
        return int(existing["id"])
    return execute(
        """INSERT INTO accounts
               (uid, enterprise_id, nickname, domain, access_token, refresh_token,
                expires_at, refresh_expires_at, enabled, status, avatar_url,
                source, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'ok', ?, ?, ?, ?)""",
        (
            uid,
            enterprise_id,
            nickname,
            domain,
            encrypt(access_token),
            encrypt(effective_refresh),
            expires_at,
            refresh_expires_at,
            avatar_url,
            source,
            ts,
            ts,
        ),
    )


def update_account(account_id: int, **fields: Any) -> None:
    if not fields:
        return
    allowed = {
        "nickname", "domain", "enterprise_id", "expires_at", "refresh_expires_at",
        "enabled", "status", "last_error", "last_checkin_date", "last_checkin_at",
        "credits", "credits_total", "avatar_url",
    }
    sets, params = [], []
    for key, value in fields.items():
        if key not in allowed:
            continue
        if key == "enabled":
            value = 1 if value else 0
        sets.append(f"{key} = ?")
        params.append(value)
    if not sets:
        return
    sets.append("updated_at = ?")
    params.append(now_ts())
    params.append(account_id)
    execute(f"UPDATE accounts SET {', '.join(sets)} WHERE id = ?", params)


def update_tokens(
    account_id: int,
    access_token: str,
    refresh_token: str = "",
    expires_at: int = 0,
    refresh_expires_at: int = 0,
    domain: str = "",
) -> None:
    sets = ["access_token = ?", "expires_at = ?", "updated_at = ?"]
    params: list[Any] = [encrypt(access_token), expires_at, now_ts()]
    if refresh_token:
        sets.append("refresh_token = ?")
        params.append(encrypt(refresh_token))
    if refresh_expires_at:
        sets.append("refresh_expires_at = ?")
        params.append(refresh_expires_at)
    if domain:
        sets.append("domain = ?")
        params.append(domain)
    sets.append("status = 'ok'")
    sets.append("last_error = ''")
    params.append(account_id)
    execute(f"UPDATE accounts SET {', '.join(sets)} WHERE id = ?", params)


def set_account_tokens_raw(account_id: int, access_token: str, refresh_token: str) -> None:
    execute(
        "UPDATE accounts SET access_token = ?, refresh_token = ?, updated_at = ? WHERE id = ?",
        (encrypt(access_token), encrypt(refresh_token), now_ts(), account_id),
    )


def delete_account(account_id: int) -> None:
    execute("DELETE FROM accounts WHERE id = ?", (account_id,))


# --------------------------------------------------------------------------- #
# 前端（用户自助页）凭据：一个 WorkBuddy 账号对应一套
# --------------------------------------------------------------------------- #

def set_portal_credentials(
    account_id: int, username: str, password_hash: str, password_plain: str = ""
) -> None:
    execute(
        "UPDATE accounts SET portal_username = ?, portal_password = ?, portal_secret = ?, "
        "portal_pw_changed = 0, updated_at = ? WHERE id = ?",
        (username, password_hash, encrypt(password_plain), now_ts(), account_id),
    )


def set_portal_password(
    account_id: int, password_hash: str, password_plain: str = "", changed: bool = True
) -> None:
    """更新前端密码。password_plain 会加密存一份，方便管理员随时再查/再转交。"""
    execute(
        "UPDATE accounts SET portal_password = ?, portal_secret = ?, portal_pw_changed = ?, "
        "updated_at = ? WHERE id = ?",
        (password_hash, encrypt(password_plain), 1 if changed else 0, now_ts(), account_id),
    )


def get_portal_secret(account_id: int) -> dict[str, str]:
    """取回前端账号明文密码（只有管理员接口会用）。"""
    row = query_one(
        "SELECT portal_username, portal_secret FROM accounts WHERE id = ?", (account_id,)
    )
    if row is None:
        return {"username": "", "password": ""}
    return {
        "username": str(row["portal_username"]),
        "password": decrypt(row["portal_secret"]),
    }


def touch_portal_login(account_id: int) -> None:
    execute("UPDATE accounts SET portal_last_login = ? WHERE id = ?", (now_ts(), account_id))


def get_portal_credential(username: str) -> Optional[dict[str, Any]]:
    """按前端用户名取凭据（含密码哈希），供登录校验用。"""
    row = query_one("SELECT * FROM accounts WHERE portal_username = ?", (username,))
    if row is None:
        return None
    return {
        "account_id": int(row["id"]),
        "username": str(row["portal_username"]),
        "password_hash": str(row["portal_password"]),
        "enabled": bool(row["enabled"]),
        "nickname": str(row["nickname"]),
        "uid": str(row["uid"]),
    }


def portal_usernames() -> list[str]:
    return [
        str(row["portal_username"])
        for row in query("SELECT portal_username FROM accounts WHERE portal_username <> ''")
    ]


def set_notify_serverchan(account_id: int, sendkey: str) -> None:
    """保存/清除某个账号自己的 Server 酱 SendKey（加密存）。"""
    execute(
        "UPDATE accounts SET notify_serverchan = ?, updated_at = ? WHERE id = ?",
        (encrypt(sendkey.strip()), now_ts(), account_id),
    )


def notified_today(account_id: int, topic: str) -> bool:
    """今天是否已经就某个话题推送过了（防止重试时反复轰炸用户）。"""
    row = query_one(
        "SELECT 1 FROM logs WHERE account_id = ? AND kind = 'notify' AND message = ? "
        "AND ts >= ? LIMIT 1",
        (account_id, topic, start_of_today_ts()),
    )
    return row is not None


# --------------------------------------------------------------------------- #
# logs
# --------------------------------------------------------------------------- #

def add_log(
    kind: str,
    ok: bool,
    message: str = "",
    account_id: Optional[int] = None,
    uid: str = "",
    nickname: str = "",
    claimed: bool = False,
    credit: Optional[int] = None,
) -> None:
    execute(
        """INSERT INTO logs (ts, account_id, uid, nickname, kind, ok, claimed, message, credit)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (now_ts(), account_id, uid, nickname, kind, 1 if ok else 0,
         1 if claimed else 0, message, credit),
    )


def list_logs(limit: int = 100, account_id: Optional[int] = None, kind: str = "") -> list[dict[str, Any]]:
    sql = "SELECT * FROM logs WHERE 1=1"
    params: list[Any] = []
    if account_id is not None:
        sql += " AND account_id = ?"
        params.append(account_id)
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    sql += " ORDER BY ts DESC, id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 500)))
    return [dict(row) for row in query(sql, params)]


def prune_logs(keep_days: int = 180) -> None:
    cutoff = now_ts() - keep_days * 86400
    execute("DELETE FROM logs WHERE ts < ?", (cutoff,))


def last_checkin_log(account_id: int) -> Optional[dict[str, Any]]:
    row = query_one(
        "SELECT * FROM logs WHERE account_id = ? AND kind = 'checkin' ORDER BY ts DESC LIMIT 1",
        (account_id,),
    )
    return dict(row) if row else None


def success_today(account_id: int) -> bool:
    row = query_one(
        """SELECT 1 FROM logs
           WHERE account_id = ? AND kind = 'checkin' AND ok = 1 AND ts >= ?
           LIMIT 1""",
        (account_id, start_of_today_ts()),
    )
    return row is not None


def login_today(uid: str) -> bool:
    """这个账号今天是否已经成功扫码登录过。

    同一个账号同一天重复扫码时，账号本身是覆盖更新（uid 唯一），
    但日志不该重复记 —— 否则看起来像「登录了好几次」。
    """
    if not uid:
        return False
    row = query_one(
        "SELECT 1 FROM logs WHERE uid = ? AND kind = 'login' AND ok = 1 AND ts >= ? LIMIT 1",
        (uid, start_of_today_ts()),
    )
    return row is not None


def today_credit(account_id: int) -> Optional[float]:
    """今天签到实际到账的积分。没有记录时返回 None（区别于「拿到了 0 分」）。"""
    row = query_one(
        """SELECT COALESCE(SUM(credit), 0) AS c
           FROM logs
           WHERE account_id = ? AND kind = 'checkin' AND ok = 1
                 AND claimed = 1 AND credit IS NOT NULL AND ts >= ?""",
        (account_id, start_of_today_ts()),
    )
    if row is None or not row["c"]:
        return None
    return round(float(row["c"]), 2)


def mark_checkin(uid: str, date: str = "", credit: Optional[int] = None) -> None:
    """记一笔「uid 在这一天已经真正签过到」。

    只要写了这条，当天对同一个 uid 就再也不会去调上游 daily-checkin，
    避免「删号重扫 → 又领一次积分」。
    """
    uid = str(uid or "").strip()
    if not uid:
        return
    day = date or today_str()
    if credit is None:
        execute(
            "INSERT INTO checkin_marks (uid, date, credit, ts) VALUES (?, ?, NULL, ?) "
            "ON CONFLICT(uid, date) DO NOTHING",
            (uid, day, now_ts()),
        )
    else:
        execute(
            "INSERT INTO checkin_marks (uid, date, credit, ts) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(uid, date) DO UPDATE SET "
            "credit = COALESCE(excluded.credit, checkin_marks.credit)",
            (uid, day, int(credit), now_ts()),
        )


def get_checkin_mark(uid: str, date: str = "") -> Optional[dict[str, Any]]:
    """今天这个 uid 签过了没？签过返回 {date, credit, ts}，没签过返回 None。"""
    uid = str(uid or "").strip()
    if not uid:
        return None
    row = query_one(
        "SELECT date, credit, ts FROM checkin_marks WHERE uid = ? AND date = ?",
        (uid, date or today_str()),
    )
    if row is None:
        return None
    return {"date": row["date"], "credit": row["credit"], "ts": row["ts"]}


def prune_checkin_marks(keep_days: int = 60) -> None:
    """只留最近 N 天的签到标记，别让表无限长。"""
    keep_days = max(1, int(keep_days or 60))
    cut = time.strftime("%Y-%m-%d", time.localtime(now_ts() - keep_days * 86400))
    execute("DELETE FROM checkin_marks WHERE date < ?", (cut,))


def total_success(account_id: int) -> int:
    """该账号累计签到成功次数。"""
    row = query_one(
        "SELECT COUNT(*) AS c FROM logs WHERE account_id = ? AND kind = 'checkin' AND ok = 1",
        (account_id,),
    )
    return int(row["c"]) if row else 0


def credits_total() -> dict[str, float]:
    """所有启用账号的积分合计。

    注意：官方余额是带小数的（比如 2865.53），这里**不能 int() 截断**，
    否则后台「总积分」会和每个账号加起来的对不上。
    """
    row = query_one(
        "SELECT COALESCE(SUM(credits), 0) AS c, COALESCE(SUM(credits_total), 0) AS t "
        "FROM accounts WHERE enabled = 1"
    )
    return {
        "credits": round(float(row["c"]), 2) if row else 0,
        "total": round(float(row["t"]), 2) if row else 0,
    }


def delete_all_accounts() -> int:
    """一键退出全部账号：删掉所有凭据。"""
    row = query_one("SELECT COUNT(*) AS c FROM accounts")
    execute("DELETE FROM accounts")
    return int(row["c"]) if row else 0


def attempts_today(account_id: int) -> int:
    row = query_one(
        "SELECT COUNT(*) AS c FROM logs WHERE account_id = ? AND kind = 'checkin' AND ts >= ?",
        (account_id, start_of_today_ts()),
    )
    return int(row["c"]) if row else 0


def start_of_today_ts() -> int:
    now = datetime.fromtimestamp(time.time(), config.TZ)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return int(midnight.timestamp())


def count_logs_today(kind: str = "checkin") -> dict[str, int]:
    rows = query(
        "SELECT ok, COUNT(*) AS c FROM logs WHERE kind = ? AND ts >= ? GROUP BY ok",
        (kind, start_of_today_ts()),
    )
    result = {"ok": 0, "fail": 0}
    for row in rows:
        result["ok" if row["ok"] else "fail"] = int(row["c"])
    return result
