#!/usr/bin/env bash
#
# WorkBuddy 自动签到 —— 宝塔面板一键部署脚本
#
#   cd /www/wwwroot/workbuddy-checkin
#   bash deploy/install-bt.sh
#
# 可选（直接写在命令前面）：
#   APP_DIR=/www/wwwroot/workbuddy-checkin   安装目录
#   PORT=8848                                监听端口（默认 8848）
#   PY=/usr/bin/python3                      手动指定 Python 解释器
#
# 脚本可以重复执行：已经做过的步骤会跳过或覆盖，不会弄坏现有数据。
#
set -euo pipefail

APP_DIR="${APP_DIR:-/www/wwwroot/workbuddy-checkin}"
PORT="${PORT:-8848}"
SERVICE_NAME="workbuddy-checkin"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIP_LOG="/tmp/wb-pip.log"
SELFTEST_LOG="/tmp/wb-selftest.log"

log()  { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# 出错时把行号和退出码打出来，方便把日志原样发给别人排查
trap 'printf "\033[31m[x]\033[0m 脚本在第 %s 行中断（退出码 %s），请把完整输出保留下来用于排查。\n" "${LINENO}" "$?" >&2' ERR

[ "$(id -u)" = "0" ] || die "请用 root 运行（宝塔「终端」默认就是 root）"
command -v systemctl >/dev/null 2>&1 || die "这台机器没有 systemd，无法用本脚本。请改用宝塔「Python项目管理器」部署（见 部署文档.md 方式二）"

# ---------------------------------------------------------------- 1. 找 Python
# 宝塔各个版本的「Python项目管理器」安装路径完全不同，靠枚举总会漏，
# 所以这里：先列常见路径，再兜底扫目录，最后把「扫到了什么、版本是多少」全打出来。
collect_python_candidates() {
    local candidate
    local candidates=(
        "${PY:-}"
        /www/server/pyporject_evn/versions/*/bin/python3
        /www/server/pyporject_evn/versions/*/bin/python
        /www/server/pyporject_evn/*/bin/python3
        /www/server/pyporject_evn/*/bin/python
        /www/server/python_manager/versions/*/bin/python3
        /www/server/python_manager/versions/*/bin/python
        /www/server/panel/pyenv/bin/python3
        /usr/local/python3/bin/python3
        /usr/local/python3/bin/python
        /usr/local/bin/python3.13 /usr/local/bin/python3.12 /usr/local/bin/python3.11
        /usr/local/bin/python3.10 /usr/local/bin/python3.9  /usr/local/bin/python3.8
        /usr/local/bin/python3 /usr/bin/python3
        python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3
    )
    for candidate in "${candidates[@]}"; do
        [ -n "$candidate" ] || continue
        [ -x "$candidate" ] && printf '%s\n' "$candidate"
    done
    # 兜底扫一遍常见目录（限制深度 + 超时，别拖垮机器）
    timeout 20 find /www/server /usr/local /opt /root -maxdepth 7 -type f \
        \( -name 'python3' -o -name 'python3.[0-9]*' \) ! -name '*-config' \
        -perm -u+x 2>/dev/null | head -n 60 || true
}

PYBIN=""
PY_REPORT=""
while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    version="$("$candidate" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo '?')"
    if [ "$version" = "?" ]; then
        printf -v PY_REPORT '%s    %s  →  无法执行\n' "$PY_REPORT" "$candidate"
        continue
    fi
    printf -v PY_REPORT '%s    %s  →  Python %s\n' "$PY_REPORT" "$candidate" "$version"
    if [[ "$version" =~ ^3\.([89]|[1-9][0-9])$ ]]; then
        PYBIN="$candidate"
        break
    fi
done < <(collect_python_candidates)

if [ -z "$PYBIN" ]; then
    printf '\033[31m[x]\033[0m 没找到 Python 3.8 及以上版本。\n\n' >&2
    if [ -n "$PY_REPORT" ]; then
        printf '脚本在这台机器上扫到这些 Python：\n%s\n' "$PY_REPORT" >&2
        printf '如果上面有 3.8+ 的解释器却没被选上，手动指定它再跑一次即可：\n' >&2
        printf '    PY=/上面那个路径 bash deploy/install-bt.sh\n\n' >&2
    else
        printf '这台机器上连 python3 都没扫到。\n\n' >&2
    fi
    die "装一个 3.8+ 的办法（任选其一）：
      1) 宝塔「软件商店」→ 安装「Python项目管理器」→ 在里面装 3.10+ → 重跑本脚本
      2) yum install -y python3 python3-pip          # CentOS
         apt update && apt install -y python3 python3-venv python3-pip   # Ubuntu/Debian
      3) 装完后如果脚本还是找不到，用 PY= 手动指路（见上）"
fi
log "使用 Python：$PYBIN（$("$PYBIN" -V 2>&1)）"

# ---------------------------------------------------------------- 2. 放代码
log "安装目录：$APP_DIR"
mkdir -p "$APP_DIR"
if [ "$SRC_DIR" != "$APP_DIR" ]; then
    if command -v rsync >/dev/null 2>&1; then
        rsync -a \
            --exclude '.venv' --exclude 'venv' --exclude 'data' \
            --exclude '.testdata' --exclude 'research' --exclude '__pycache__' \
            "$SRC_DIR"/ "$APP_DIR"/
    else
        # 没有 rsync 就用 tar 过滤复制，别把开发机的 .venv / 测试数据搬过去
        (
            cd "$SRC_DIR" && tar cf - \
                --exclude='./.venv' --exclude='./venv' --exclude='./data' \
                --exclude='./.testdata' --exclude='./research' --exclude='__pycache__' .
        ) | (
            cd "$APP_DIR" && tar xf -
        )
    fi
fi
[ -f "$APP_DIR/requirements.txt" ] || die "$APP_DIR 里没有 requirements.txt，代码没放对位置"

# ---------------------------------------------------------------- 3. 依赖
if [ ! -x "$APP_DIR/venv/bin/python" ]; then
    log "创建虚拟环境…"
    "$PYBIN" -m venv "$APP_DIR/venv" \
        || die "创建虚拟环境失败。Debian/Ubuntu 请先执行：apt install -y python3-venv"
fi
VPY="$APP_DIR/venv/bin/python"

# 国内服务器拉 PyPI 经常超时，官方源失败就自动切清华镜像
pip_install() {
    if "$VPY" -m pip install --timeout 30 --retries 2 "$@" >"$PIP_LOG" 2>&1; then
        return 0
    fi
    warn "官方 PyPI 装不上，改用清华镜像重试…"
    if "$VPY" -m pip install --timeout 30 --retries 2 \
        -i https://pypi.tuna.tsinghua.edu.cn/simple "$@" >>"$PIP_LOG" 2>&1; then
        return 0
    fi
    warn "依赖安装失败，最后 25 行日志："
    tail -n 25 "$PIP_LOG" || true
    return 1
}

log "安装依赖（首次大约 1-2 分钟，请稍等）…"
pip_install --upgrade pip >/dev/null 2>&1 || warn "升级 pip 失败，继续用现有版本"
pip_install -q -r "$APP_DIR/requirements.txt" \
    || die "依赖安装失败。可手动执行：$VPY -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r $APP_DIR/requirements.txt"
"$VPY" -c 'import fastapi, uvicorn, requests, cryptography, qrcode' \
    || die "依赖装上了但导入失败，请把上面日志发出来"
log "依赖就绪"

# ---------------------------------------------------------------- 4. 配置
ENV_FILE="$APP_DIR/.env"
mkdir -p "$APP_DIR/data"
if [ ! -f "$ENV_FILE" ]; then
    GENERATED_PASSWORD="$("$VPY" -c 'import secrets;print(secrets.token_urlsafe(12))')"
    cat > "$ENV_FILE" <<EOF
# 由 deploy/install-bt.sh 生成；改完执行 systemctl restart $SERVICE_NAME 生效
WB_HOST=127.0.0.1
WB_PORT=$PORT
WB_PASSWORD=$GENERATED_PASSWORD
WB_DATA_DIR=$APP_DIR/data
WB_TZ_OFFSET=8
WB_ALLOW_MANUAL_IMPORT=1
EOF
    chmod 600 "$ENV_FILE"
    log "已生成配置文件 $ENV_FILE"
else
    GENERATED_PASSWORD="$(grep -E '^WB_PASSWORD=' "$ENV_FILE" | head -n1 | cut -d= -f2- || true)"
    warn "配置文件已存在，沿用其中的密码（如需换密码请改 $ENV_FILE）"
fi

# ---------------------------------------------------------------- 5. 服务
log "写入 systemd 服务…"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=WorkBuddy 自动签到（多账号扫码登录 + 定时签到）
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/run.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
systemctl restart "$SERVICE_NAME" || true
sleep 4

if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    warn "服务没起来，最近 40 行日志："
    journalctl -u "$SERVICE_NAME" -n 40 --no-pager || true
    die "服务启动失败。常见原因：端口被占用（换 PORT=其他端口 重跑）、依赖没装全"
fi
log "服务已启动"

# ---------------------------------------------------------------- 6. 自检
log "运行接口自检…"
if "$VPY" "$APP_DIR/tools/selftest_api.py" "http://127.0.0.1:$PORT" "$GENERATED_PASSWORD" >"$SELFTEST_LOG" 2>&1; then
    log "自检全部通过"
else
    warn "自检未全部通过，详情：$SELFTEST_LOG"
    tail -n 20 "$SELFTEST_LOG" || true
fi

cat <<EOF

════════════════════════════════════════════════════════════
 ✅ 部署完成
════════════════════════════════════════════════════════════
 服务名    ：$SERVICE_NAME
 本机地址  ：http://127.0.0.1:$PORT
 控制台密码：${GENERATED_PASSWORD:-（见 $ENV_FILE）}
 数据目录  ：$APP_DIR/data    ← 备份这个目录 = 备份全部账号
 配置文件  ：$ENV_FILE

 常用命令：
   systemctl status  $SERVICE_NAME
   systemctl restart $SERVICE_NAME
   journalctl -u $SERVICE_NAME -f

 下一步（在宝塔面板里点几下就能用上 HTTPS）：
   1. 「网站」→ 添加站点，填你的域名，不要建数据库和 PHP
   2. 点该站点 →「设置」→「反向代理」→ 添加：
        代理名称  workbuddy
        目标 URL  http://127.0.0.1:$PORT
        发送域名  \$host
   3. 同一个「设置」窗口 →「SSL」→ Let's Encrypt → 申请证书 → 打开「强制 HTTPS」

 ⚠ 不要把 $PORT 端口开放到公网，走 Nginx 的 80/443 就够了。

 第一次使用：打开 https://你的域名 → 输入上面的控制台密码
 → 「+ 添加账号」→ 手机微信扫码 → 完成后点「复制账号密码和地址」
 → 对方用 https://你的域名/me 登录，就能看到自己的积分和签到情况。
════════════════════════════════════════════════════════════
EOF
