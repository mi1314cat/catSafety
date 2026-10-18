#!/bin/bash
# =============================================================
# catSafety 安装 / 更新入口
#   bash install.sh            安装或更新到 /opt/catSafety
#   bash install.sh --status   查看安装状态
#   bash install.sh --uninstall 卸载（不删 /etc/catSafety 账本）
# 支持: 本地目录运行 / bash <(curl -Ls .../install.sh)
# =============================================================
set -uo pipefail

APP="catSafety"
INSTALL_DIR="${INSTALL_DIR:-/opt/catSafety}"
BIN="/usr/local/bin/catSafety"
REPO="${REPO:-https://github.com/mi1314cat/catSafety}"

R='\033[0m'; G='\033[32m'; Y='\033[33m'; RD='\033[31m'; B='\033[1m'; D='\033[2m'
ok(){ printf "  ${G}[OK]${R} %s\n" "$*"; }
warn(){ printf "  ${Y}[WARN]${R} %s\n" "$*"; }
err(){ printf "  ${RD}[ERR]${R} %s\n" "$*" >&2; }
info(){ printf "  ${D}[--]${R} %s\n" "$*"; }
die(){ err "$*"; exit 1; }

need_root(){ [[ ${EUID:-$(id -u)} -eq 0 ]] || die "需要 root 运行"; }

status(){
    if [[ -x "$INSTALL_DIR/catSafety.sh" ]]; then
        ok "已安装: $INSTALL_DIR/catSafety.sh"
        [[ -L "$BIN" || -x "$BIN" ]] && ok "命令: $BIN" || warn "命令链接缺失"
        [[ -d /etc/catSafety ]] && printf "  账本: %s 条\n" "$(wc -l </etc/catSafety/ledger.tsv 2>/dev/null || echo 0)"
        systemctl is-active catSafety-guard.timer >/dev/null 2>&1 && ok "SSH 守护: 运行中" || warn "SSH 守护: 未运行"
        systemctl is-active catSafety-restore.service >/dev/null 2>&1 && ok "开机恢复: 已启用" || warn "开机恢复: 未启用"
    else
        warn "未安装"
    fi
}

uninstall(){
    need_root
    if command -v catSafety >/dev/null 2>&1; then
        catSafety disable >/dev/null 2>&1 || true
    fi
    systemctl disable --now catSafety-guard.timer >/dev/null 2>&1 || true
    systemctl disable --now catSafety-restore.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/catSafety-guard.service /etc/systemd/system/catSafety-guard.timer \
          /etc/systemd/system/catSafety-restore.service
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -f "$BIN"
    rm -rf "$INSTALL_DIR"
    ok "已卸载程序；账本保留在 /etc/catSafety（要彻底删: rm -rf /etc/catSafety）"
}

install_all(){
    need_root
    local src="" tmp=""
    if [[ -f "$(dirname "${BASH_SOURCE[0]:-$0}")/catSafety.sh" ]]; then
        src="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
        ok "使用本地目录: $src"
    else
        tmp=$(mktemp -d)
        info "下载 $REPO ..."
        for u in \
            "$REPO/archive/refs/heads/main.tar.gz" \
            "https://ghproxy.net/$REPO/archive/refs/heads/main.tar.gz" \
            "https://gh-proxy.com/$REPO/archive/refs/heads/main.tar.gz"; do
            if curl -fsSL --connect-timeout 8 -m 120 "$u" -o "$tmp/repo.tgz" 2>/dev/null \
               && tar -tzf "$tmp/repo.tgz" >/dev/null 2>&1; then
                tar -xzf "$tmp/repo.tgz" -C "$tmp" && src=$(find "$tmp" -maxdepth 1 -mindepth 1 -type d | head -1)
                [[ -n "$src" ]] && break
            fi
        done
        [[ -n "$src" && -f "$src/catSafety.sh" ]] || die "下载失败"
    fi

    mkdir -p "$INSTALL_DIR" /etc/catSafety || die "创建目录失败"
    install -m 0755 "$src/catSafety.sh" "$INSTALL_DIR/catSafety.sh" || die "复制主程序失败"
    [[ -f "$src/api.sh" ]] && install -m 0644 "$src/api.sh" "$INSTALL_DIR/api.sh" || true
    [[ -d "$src/docs" ]] && cp -rf "$src/docs" "$INSTALL_DIR/" 2>/dev/null || true
    [[ -f "$src/README.md" ]] && cp -f "$src/README.md" "$INSTALL_DIR/" 2>/dev/null || true
    ln -sfn "$INSTALL_DIR/catSafety.sh" "$BIN"
    chmod 0700 /etc/catSafety 2>/dev/null || true
    [[ -n "$tmp" ]] && rm -rf "$tmp"
    ok "已安装: $INSTALL_DIR/catSafety.sh"
    ok "命令: catSafety"
    echo
    printf "  ${B}下一步${R}（不会自动改防火墙）：\n"
    echo "    1) 先看状态:        catSafety status"
    echo "    2) SSH 检查:        catSafety ssh status"
    echo "    3) 接管/初始化:     catSafety takeover --dry-run"
    echo "    4) 正式接管:        catSafety takeover"
    echo
    printf "  ${D}安全兜底：任何启用动作都先放行 SSH，并带 180 秒自动回滚；\n  失联时用服务商控制台执行: catSafety panic${R}\n"
}

case "${1:-install}" in
    install|"") install_all ;;
    --status|status) status ;;
    --uninstall|uninstall) uninstall ;;
    *) echo "用法: bash install.sh [install|--status|--uninstall]"; exit 2 ;;
esac
