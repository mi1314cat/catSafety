#!/bin/bash
# =============================================================
#  catSafety · 防火墙 / 安全工具（统一入口）
#
#  设计目标（按优先级）:
#    1) SSH 永远不会被自己的规则封死；即使被第三方规则封了, guard 也会自动救回来
#    2) 接管第三方防火墙脚本（ufw / nftables.sh / iptables / fail2ban 混装）
#    3) 与三个内核共用一套端口账本: xray / mihomo / sing-box（+ share）
#    4) 规则可归属、可对账、可回滚、可离线自检
#
#  原则:
#    · 任何"改策略/启防火墙"的动作，前面一定先放行 SSH，并且带 deadman 自动回滚
#    · 只关自己账本里、且 owner 匹配的端口；SSH / 80 / 443 / 分享端口永不动
#    · 规则一律带 catSafety-<owner> 标记（后端支持就带）
#    · 不把别人的规则抄成自己的：接管时明确标 legacy，并允许一键回滚
#
#  CLI:
#    catSafety menu | status | takeover [--dry-run] [--yes] | sync [--prune]
#    catSafety guard | ssh {status|protect|unlock} | backend {ufw|nft|iptables|status}
#    catSafety open <owner> <port[/proto]> | close <owner> <port[/proto]> | list | check
#    catSafety f2b {install|status|unban <ip>|unban-all|whitelist <ip>}
#    catSafety backup | restore <dir> | panic | install-guard | uninstall
# =============================================================

set -u

CS_VERSION="1.0.0"
CS_ROOT="${CS_ROOT:-/etc/catSafety}"
CS_LEDGER="${CS_LEDGER:-$CS_ROOT/ledger.tsv}"
CS_STATE="${CS_STATE:-$CS_ROOT/backend}"
CS_LOG="${CS_LOG:-/var/log/catSafety.log}"
CS_BACKUP="${CS_BACKUP:-$CS_ROOT/backup}"
CS_INSTALL_DIR="${CS_INSTALL_DIR:-/opt/catSafety}"
CS_UNIT_DIR="${CS_UNIT_DIR:-/etc/systemd/system}"
CS_NFT_TABLE="${CS_NFT_TABLE:-catSafety}"

# 可选配置覆盖（root 600）: AUTO_GRACE=900 / AUTOSCAN=0/1
CS_CONFIG_FILE="${CS_CONFIG_FILE:-$CS_ROOT/config}"
if [[ -r "$CS_CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    . "$CS_CONFIG_FILE" 2>/dev/null || true
fi
CS_AUTO_GRACE="${CS_AUTO_GRACE:-900}"

# 永不自动关闭的端口（SSH 端口会被动态加进来）
CS_NEVER_TOUCH="80 443 8443"

# 颜色
if [[ -t 1 ]]; then
    R=$'\033[0m'; B=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'
    YEL=$'\033[33m'; BLU=$'\033[36m'; MAG=$'\033[35m'; DIM=$'\033[2m'; CYN=$'\033[36m'
else
    R=""; B=""; RED=""; GRN=""; YEL=""; BLU=""; MAG=""; DIM=""; CYN=""
fi

# ---------------------------- 基础工具 ----------------------------
cs_root_check() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || { echo -e "${RED}需要 root 运行${R}" >&2; exit 1; }
}
cs_log() {
    mkdir -p "$CS_ROOT" 2>/dev/null
    printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$CS_LOG" 2>/dev/null || true
}
ok()   { printf '  %b[OK]%b %s\n' "$GRN" "$R" "$*"; }
warn() { printf '  %b[WARN]%b %s\n' "$YEL" "$R" "$*"; }
err()  { printf '  %b[ERR]%b %s\n' "$RED" "$R" "$*" >&2; }
info() { printf '  %b[--]%b %s\n' "$DIM" "$R" "$*"; }
die()  { err "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
hr()   { printf '%s\n' "──────────────────────────────────────────────────────────────"; }
pause_() {
    printf '\n  按回车继续...'; read -r _ || true
}
confirm_() { # <提示> [默认 y/N]
    local p="$1" d="${2:-n}" a
    printf '  %s ' "$p"
    read -r a || return 1
    a="${a:-$d}"
    [[ "$a" == [yY]* ]]
}

# ---------------------------- 端口/协议解析 ----------------------------
cs_norm_port() { # <port[/proto]> → "port proto"
    local s="${1:-}" p pr="both"
    [[ "$s" == */* ]] && { p="${s%%/*}"; pr="${s##*/}"; } || p="$s"
    [[ "$p" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 )) || return 1
    case "$pr" in
        tcp|udp) ;;
        both|"") pr="both" ;;
        *) return 1 ;;
    esac
    printf '%s %s' "$p" "$pr"
}

# ---------------------------- 账本 ----------------------------
cs_ledger_init() {
    mkdir -p "$CS_ROOT" 2>/dev/null
    [[ -f "$CS_LEDGER" ]] || : >"$CS_LEDGER"
    chmod 600 "$CS_LEDGER" 2>/dev/null || true
}

cs_ledger_add() { # <owner> <proto> <port> [tag]
    local owner="${1:?}" proto="${2:?}" port="${3:?}" tag="${4:-}" ts
    cs_ledger_init
    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    [[ "$proto" == "both" || "$proto" == "tcp" || "$proto" == "udp" ]] || return 1
    if cs_ledger_has "$owner" "$proto" "$port"; then
        return 0
    fi
    ts=$(date +%s)
    printf '%s\t%s\t%s\t%s\t%s\n' "$owner" "$proto" "$port" "${tag//$'\t'/ }" "$ts" >>"$CS_LEDGER"
}

cs_ledger_del() { # <owner> <proto> <port>
    local owner="${1:?}" proto="${2:?}" port="${3:?}" tmp
    [[ -f "$CS_LEDGER" ]] || return 0
    tmp=$(mktemp) || return 1
    awk -F'\t' -v o="$owner" -v p="$proto" -v n="$port" \
        '!($1==o && $2==p && $3==n)' "$CS_LEDGER" >"$tmp" && mv -f "$tmp" "$CS_LEDGER"
}

cs_ledger_has() { # <owner> <proto> <port>
    [[ -f "$CS_LEDGER" ]] || return 1
    awk -F'\t' -v o="$1" -v p="$2" -v n="$3" '
        $1==o && $2==p && $3==n { found=1; exit }
        END { exit(found?0:1) }' "$CS_LEDGER" 2>/dev/null
}

cs_ledger_ports() { # 所有端口(去重)
    [[ -f "$CS_LEDGER" ]] || return 0
    cut -f3 "$CS_LEDGER" | grep -E '^[0-9]+$' | sort -nu
}

cs_ledger_rows() { [[ -f "$CS_LEDGER" ]] && cat "$CS_LEDGER"; }

cs_ledger_owner_of() { # <port> → owner(s)
    [[ -f "$CS_LEDGER" ]] || return 0
    awk -F'\t' -v n="$1" '$3==n {print $1}' "$CS_LEDGER" | sort -u | paste -sd, -
}

# ---------------------------- SSH 检测 ----------------------------
cs_ssh_ports() {
    local out=""
    # 1) 正在监听的 sshd（最真实）
    if have ss; then
        out+=$'\n'$(ss -Hltnp 2>/dev/null | grep -i sshd \
            | sed -n 's/.*[[:space:]]\{1,\}[^ ]*:\([0-9]\{1,5\}\)[[:space:]].*/\1/p')
    fi
    # 2) sshd -T（会把 Include 也算进去）
    if have sshd; then
        out+=$'\n'$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}')
    fi
    # 3) 配置文件
    local f
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [[ -r "$f" ]] || continue
        out+=$'\n'$(grep -hiE '^[[:space:]]*Port[[:space:]]+' "$f" 2>/dev/null | awk '{print $2}')
    done
    # 4) 兜底：只有完全探测不到时才假设 22（否则会误报）
    local got
    got=$(printf '%s\n' "$out" | tr -d '\r' | grep -E '^[0-9]+$' | sort -nu)
    if [[ -z "$got" ]]; then echo 22; else printf '%s\n' "$got"; fi
}

cs_ssh_listening() { # 返回 0=至少一个 SSH 端口在监听
    local p
    while read -r p; do
        [[ -n "$p" ]] || continue
        local addrs a
        addrs=$(ss -Hltn 2>/dev/null | awk '{print $4}')
        while IFS= read -r a; do
            [[ "$a" == *":${p}" ]] && return 0
        done <<<"$addrs"
    done < <(cs_ssh_ports)
    return 1
}

cs_is_ssh_port() {
    local p="$1" s
    for s in $(cs_ssh_ports); do [[ "$s" == "$p" ]] && return 0; done
    return 1
}
cs_is_protected() { # <port>
    local p="$1" w
    cs_is_ssh_port "$p" && return 0
    for w in $CS_NEVER_TOUCH; do [[ "$w" == "$p" ]] && return 0; done
    return 1
}

# ---------------------------- 后端探测/选择 ----------------------------
cs_backend_get() {
    [[ -s "$CS_STATE" ]] && { tr -d '[:space:]' <"$CS_STATE"; return 0; }
    # 自动探测：先看谁在管，再看有什么
    if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then echo ufw; return 0; fi
    if have nft && nft list table inet "$CS_NFT_TABLE" >/dev/null 2>&1; then echo nft; return 0; fi
    if have firewall-cmd && firewall-cmd --state 2>/dev/null | grep -q running; then echo firewalld; return 0; fi
    if have ufw; then echo ufw; return 0; fi
    if have nft; then echo nft; return 0; fi
    if have iptables; then echo iptables; return 0; fi
    echo none
}

cs_backend_set() {
    case "${1:-}" in ufw|nft|firewalld|iptables) ;; *) return 1 ;; esac
    mkdir -p "$CS_ROOT" 2>/dev/null
    printf '%s\n' "$1" >"$CS_STATE"
    cs_log "backend -> $1"
}

cs_backend_active() {
    case "$(cs_backend_get)" in
        ufw)        have ufw && ufw status 2>/dev/null | grep -q '^Status: active' ;;
        nft)        have nft && nft list table inet "$CS_NFT_TABLE" >/dev/null 2>&1 ;;
        firewalld)  have firewall-cmd && firewall-cmd --state 2>/dev/null | grep -q running ;;
        iptables)   have iptables && iptables -S INPUT 2>/dev/null | grep -q -- '--dport' ;;
        *) return 1 ;;
    esac
}

# ---------------------------- 外部防火墙探测 ----------------------------
cs_foreign_list() {
    local out=""
    if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then out+="ufw(active) "; fi
    if systemctl is-active --quiet nftables 2>/dev/null; then out+="nftables.service "; fi
    if systemctl is-active --quiet nftables-ufw-panel 2>/dev/null; then out+="nftables-ufw-panel.service "; fi
    if systemctl is-active --quiet sb-panel-nft 2>/dev/null; then out+="sb-panel-nft.service "; fi
    if have firewall-cmd && firewall-cmd --state 2>/dev/null | grep -q running; then out+="firewalld "; fi
    if have fail2ban-client && fail2ban-client status 2>/dev/null | grep -q 'Jail list'; then out+="fail2ban "; fi
    if crontab -l 2>/dev/null | grep -qE '@reboot .*iptables-restore'; then out+="cron:iptables-restore "; fi
    if [[ -f /etc/iptables/rules.v4 ]]; then out+="iptables-persistent "; fi
    printf '%s' "$out"
}

# ---------------------------- 后端：规则是否存在 ----------------------------
cs_rule_exists() { # <proto: tcp|udp> <port>
    local proto="$1" port="$2"
    case "$(cs_backend_get)" in
        ufw) ufw status 2>/dev/null | grep -qE "^${port}/${proto} +ALLOW" ;;
        nft)
            # 不用 `nft | grep -q`: grep 提前退出会让 nft 收到 SIGPIPE，
            # 加上 pipefail 时整条管道被判失败 —— 实测同样的规则查询会
            # 间歇性返回"不存在"（20 次里错 8 次，guard 会被误导）。
            local out
            out=$(nft -a list chain inet "$CS_NFT_TABLE" input 2>/dev/null)
            [[ "$out" == *"${proto} dport ${port} accept"* ]] ;;
        iptables) iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null ;;
        firewalld) firewall-cmd --query-port="${port}/${proto}" 2>/dev/null ;;
        *) return 1 ;;
    esac
}

# ---------------------------- 放行/关闭（后端分发） ----------------------------
# 统一入口：先记账，再改规则；失败回滚账本
cs_open() { # <owner> <proto> <port> [tag]
    local owner="$1" proto="$2" port="$3" tag="${4:-}"
    local before; before=$(mktemp)
    cp -f "$CS_LEDGER" "$before" 2>/dev/null || true
    cs_ledger_add "$owner" "$proto" "$port" "$tag" || { rm -f "$before"; return 1; }
    if ! cs_backend_open "$owner" "$proto" "$port"; then
        cp -f "$before" "$CS_LEDGER" 2>/dev/null || true
        rm -f "$before"; return 1
    fi
    rm -f "$before"
    cs_log "open $owner $proto/$port ${tag:+tag=$tag}"
    return 0
}

cs_backend_open() { # <owner> <proto> <port>
    local owner="$1" proto="$2" port="$3" p
    for p in tcp udp; do
        [[ "$proto" == "both" || "$proto" == "$p" ]] || continue
        case "$(cs_backend_get)" in
            ufw)
                ufw allow "${port}/${p}" comment "catSafety-${owner}" >/dev/null 2>&1 \
                    || return 1 ;;
            nft)
                # 未启用时只记账；否则 open 一个端口会顺手建出 policy drop 表
                [[ "$(cs_enabled_get)" == "1" ]] && { cs_nft_rebuild || return 1; } ;;
            iptables)
                cs_ipt_allow "$owner" "$p" "$port" || return 1 ;;
            firewalld)
                firewall-cmd --zone=public --add-port="${port}/${p}" --permanent >/dev/null 2>&1 || return 1
                firewall-cmd --reload >/dev/null 2>&1 || true ;;
            *) return 1 ;;
        esac
    done
    return 0
}

cs_close() { # <owner> <proto> <port>
    local owner="$1" proto="$2" port="$3"
    cs_is_protected "$port" && { warn "端口 $port 受保护（SSH/系统端口），拒绝关闭"; return 1; }
    if ! cs_ledger_has "$owner" "$proto" "$port" && ! cs_ledger_has "$owner" both "$port"; then
        warn "账本里没有 $owner $proto/$port —— 不归本工具管，拒绝关闭"
        return 1
    fi
    cs_backend_close "$owner" "$proto" "$port" || return 1
    cs_purge_kernel_rules "$port"
    cs_ledger_del "$owner" "$proto" "$port"
    cs_ledger_del "$owner" both "$port"
    cs_log "close $owner $proto/$port"
}

cs_backend_close() {
    local owner="$1" proto="$2" port="$3" p
    for p in tcp udp; do
        [[ "$proto" == "both" || "$proto" == "$p" ]] || continue
        case "$(cs_backend_get)" in
            ufw)
                ufw delete allow "${port}/${p}" >/dev/null 2>&1 || true ;;
            nft)
                cs_nft_rebuild || return 1 ;;
            iptables)
                cs_ipt_del "$owner" "$p" "$port" ;;
            firewalld)
                firewall-cmd --zone=public --remove-port="${port}/${p}" --permanent >/dev/null 2>&1 || true
                firewall-cmd --reload >/dev/null 2>&1 || true ;;
            *) return 1 ;;
        esac
    done
    return 0
}

# ---------------------------- 后端：nftables（自有表，policy drop） ----------------------------
# 设计: 用独立的 inet catSafety 表，hook priority -10（最先执行），policy drop。
# 好处: 规则归属清晰，不受别的表/脚本影响；接管后本工具就是唯一入口。
# 注意: 建表必须在**同一个事务**里把 SSH 放行规则一起写进去，否则中间会断 SSH。
cs_nft_ruleset() { # 生成完整规则文本（stdout）
    local p s ssh_ports
    ssh_ports=$(cs_ssh_ports | paste -sd' ' -)
    cat <<EOF
flush chain inet ${CS_NFT_TABLE} input
add rule inet ${CS_NFT_TABLE} input ct state established,related accept
add rule inet ${CS_NFT_TABLE} input iif lo accept
add rule inet ${CS_NFT_TABLE} input icmp type echo-request accept
add rule inet ${CS_NFT_TABLE} input icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert } accept
EOF
    for s in $ssh_ports; do
        echo "add rule inet ${CS_NFT_TABLE} input tcp dport ${s} accept comment \"catSafety-ssh\""
    done
    # 系统 Web 端口：监听就放行（保护站点，不让防火墙优化把 80/443 关掉）
    for p in 80 443 8443; do
        if ss -Hltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"; then
            echo "add rule inet ${CS_NFT_TABLE} input tcp dport ${p} accept comment \"catSafety-web\""
        fi
    done
    # 账本里的端口（按 proto+port 去重：同一端口可能既有 xray 又有 legacy）
    if [[ -f "$CS_LEDGER" ]]; then
        awk -F'\t' '
            $3 !~ /^[0-9]+$/ { next }
            $1=="ssh" || $1=="web" { next }
            {
                if ($2=="tcp") { k="tcp:"$3; if (!(k in seen)) { seen[k]=1; print "tcp", $3, $1 } }
                else if ($2=="udp") { k="udp:"$3; if (!(k in seen)) { seen[k]=1; print "udp", $3, $1 } }
                else { k="tcp:"$3; if (!(k in seen)) { seen[k]=1; print "tcp", $3, $1 }
                       k="udp:"$3; if (!(k in seen)) { seen[k]=1; print "udp", $3, $1 } }
            }' "$CS_LEDGER" \
        | while read -r pr pt ow; do
            echo "add rule inet ${CS_NFT_TABLE} input ${pr} dport ${pt} accept comment \"catSafety-${ow}\""
        done
    fi
}

cs_nft_create() { # 首次建表：一个事务里建链 + SSH 放行 + 账本端口
    local body
    body=$(cs_nft_ruleset | sed 's/^flush chain inet .* input$//')
    nft -f - <<EOF
table inet ${CS_NFT_TABLE} {
  chain input {
    type filter hook input priority -10; policy drop;
$(printf '%s\n' "$body" | sed 's/^add rule inet '"${CS_NFT_TABLE}"' input //; s/^/    /')
  }
}
EOF
}

cs_nft_rebuild() { # 已有表：原子 flush + 重建
    have nft || return 1
    mkdir -p "$CS_ROOT" 2>/dev/null
    local f; f=$(mktemp) || return 1
    if ! nft list table inet "$CS_NFT_TABLE" >/dev/null 2>&1; then
        cs_nft_ruleset | sed '1d' >"$f"     # 去掉 flush 行
        if nft -f - <<EOF
table inet ${CS_NFT_TABLE} {
  chain input {
    type filter hook input priority -10; policy drop;
$(sed 's/^add rule inet '"${CS_NFT_TABLE}"' input //; s/^/    /' "$f")
  }
}
EOF
        then rm -f "$f"; return 0; else rm -f "$f"; return 1; fi
    fi
    cs_nft_ruleset >"$f"
    if nft -f "$f" 2>/dev/null; then rm -f "$f"; return 0; fi
    # 退一步：分步执行（极少见）
    local rc=0 line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        nft $line 2>/dev/null || rc=1
    done <"$f"
    rm -f "$f"
    return $rc
}

cs_nft_delete() {
    have nft || return 0
    nft delete table inet "$CS_NFT_TABLE" 2>/dev/null || true
}

# ---------------------------- 后端：iptables ----------------------------
cs_ipt_cmt() { printf '%s' "catSafety-$1"; }

cs_ipt_allow() { # <owner> <proto> <port>
    local owner="$1" proto="$2" port="$3" c; c=$(cs_ipt_cmt "$owner")
    if have iptables; then
        iptables -C INPUT -p "$proto" --dport "$port" -m comment --comment "$c" -j ACCEPT 2>/dev/null \
            || iptables -I INPUT 1 -p "$proto" --dport "$port" -m comment --comment "$c" -j ACCEPT 2>/dev/null \
            || return 1
    fi
    if have ip6tables; then
        ip6tables -C INPUT -p "$proto" --dport "$port" -m comment --comment "$c" -j ACCEPT 2>/dev/null \
            || ip6tables -I INPUT 1 -p "$proto" --dport "$port" -m comment --comment "$c" -j ACCEPT 2>/dev/null || true
    fi
    return 0
}

cs_ipt_del() { # <owner> <proto> <port>
    local owner="$1" proto="$2" port="$3" c line
    c=$(cs_ipt_cmt "$owner")
    for bin in iptables ip6tables; do
        have "$bin" || continue
        while :; do
            # 注意: iptables -S 输出的 comment 不带引号
            line=$("$bin" -S INPUT 2>/dev/null | grep -F -- "--dport ${port} " | grep -F -- "--comment ${c}" | head -1)
            [[ -n "$line" ]] || break
            line="${line/-A INPUT /-D INPUT }"
            "$bin" $line 2>/dev/null || break
        done
    done
}

cs_ipt_base_rules() { # 基础放行：established / lo / icmp / SSH
    local proto p
    have iptables || return 0
    iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
        || iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i lo -j ACCEPT 2>/dev/null || true
    iptables -C INPUT -p icmp -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null || true
    if have ip6tables; then
        ip6tables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
            || ip6tables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
        ip6tables -C INPUT -i lo -j ACCEPT 2>/dev/null || ip6tables -I INPUT 1 -i lo -j ACCEPT 2>/dev/null || true
        ip6tables -C INPUT -p ipv6-icmp -j ACCEPT 2>/dev/null || ip6tables -I INPUT 1 -p ipv6-icmp -j ACCEPT 2>/dev/null || true
    fi
    for p in $(cs_ssh_ports); do
        cs_ipt_allow ssh tcp "$p"
    done
    for p in 80 443 8443; do
        ss -Hltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$" && cs_ipt_allow web tcp "$p"
    done
}

cs_ipt_policy() { # drop|accept
    local act="${1:-drop}"
    have iptables || return 1
    if [[ "$act" == "drop" ]]; then
        cs_ipt_base_rules
        iptables -P INPUT DROP 2>/dev/null || return 1
        have ip6tables && ip6tables -P INPUT DROP 2>/dev/null || true
    else
        iptables -P INPUT ACCEPT 2>/dev/null || true
        have ip6tables && ip6tables -P INPUT ACCEPT 2>/dev/null || true
    fi
}

# ---------------------------- 后端：ufw ----------------------------
cs_ufw_allow() { # <owner> <proto> <port>
    local owner="$1" proto="$2" port="$3"
    have ufw || return 1
    ufw allow "${port}/${proto}" comment "catSafety-${owner}" >/dev/null 2>&1
}

cs_ufw_ensure() { # 只放行，不启停
    local p proto port owner tag ts
    have ufw || return 1
    for p in $(cs_ssh_ports); do ufw allow "${p}/tcp" comment "catSafety-ssh" >/dev/null 2>&1 || true; done
    for p in 80 443 8443; do
        ss -Hltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$" \
            && ufw allow "${p}/tcp" comment "catSafety-web" >/dev/null 2>&1 || true
    done
    [[ -f "$CS_LEDGER" ]] || return 0
    while IFS=$'\t' read -r owner proto port tag ts; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        [[ "$owner" == "ssh" || "$owner" == "web" ]] && continue
        case "$proto" in
            tcp)  ufw allow "${port}/tcp" comment "catSafety-${owner}" >/dev/null 2>&1 || true ;;
            udp)  ufw allow "${port}/udp" comment "catSafety-${owner}" >/dev/null 2>&1 || true ;;
            both|"") ufw allow "${port}/tcp" comment "catSafety-${owner}" >/dev/null 2>&1 || true
                     ufw allow "${port}/udp" comment "catSafety-${owner}" >/dev/null 2>&1 || true ;;
        esac
    done <"$CS_LEDGER"
}

cs_ufw_status() { have ufw && ufw status 2>/dev/null; }

# ---------------------------- 启用状态 / deadman ----------------------------
cs_enabled_get() { [[ -s "$CS_ROOT/enabled" ]] && cat "$CS_ROOT/enabled" || echo 0; }
cs_enabled_set() { mkdir -p "$CS_ROOT"; printf '%s\n' "$1" >"$CS_ROOT/enabled"; }

CS_DEADMAN_PID=""
cs_deadman_start() { # <回滚命令> [秒=180]
    local cmd="$1" secs="${2:-180}" pidf="$CS_ROOT/.deadman.pid"
    mkdir -p "$CS_ROOT"
    nohup sh -c "sleep ${secs}; ${cmd}; echo deadman-fired \$(date +%F_%T) >>'${CS_LOG}'" \
        >/dev/null 2>&1 &
    CS_DEADMAN_PID=$!
    printf '%s\n' "$CS_DEADMAN_PID" >"$pidf" 2>/dev/null
    cs_log "deadman armed: ${secs}s → ${cmd} (pid $CS_DEADMAN_PID)"
}
cs_deadman_cancel() {
    local pidf="$CS_ROOT/.deadman.pid" pid
    [[ -f "$pidf" ]] || return 0
    pid=$(cat "$pidf" 2>/dev/null)
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null
    rm -f "$pidf"
    cs_log "deadman cancelled"
}

# ---------------------------- SSH 保护 ----------------------------
cs_ssh_rule_missing() { # 输出缺失的 SSH 端口
    local p miss=""
    while read -r p; do
        [[ -n "$p" ]] || continue
        cs_rule_exists tcp "$p" || miss+=" $p"
    done < <(cs_ssh_ports)
    printf '%s' "$miss"
}

cs_ssh_protect() { # 确保每个 SSH 端口都有放行规则
    local p n=0
    case "$(cs_backend_get)" in
        ufw)
            while read -r p; do ufw allow "${p}/tcp" comment "catSafety-ssh" >/dev/null 2>&1 && n=$((n+1)); done < <(cs_ssh_ports) ;;
        nft)
            # 表不存在 = 防火墙还没启用：不要为了"放行 SSH"顺手建出 policy drop 表
            if nft list table inet "$CS_NFT_TABLE" >/dev/null 2>&1; then
                cs_nft_rebuild >/dev/null 2>&1 && n=1
            else
                info "nft 防火墙未启用，跳过 SSH 规则重建（启用时会自动带上）"
            fi ;;
        iptables)
            while read -r p; do cs_ipt_allow ssh tcp "$p" && n=$((n+1)); done < <(cs_ssh_ports) ;;
        firewalld)
            while read -r p; do firewall-cmd --zone=public --add-port="${p}/tcp" --permanent >/dev/null 2>&1 && n=$((n+1)); done < <(cs_ssh_ports)
            firewall-cmd --reload >/dev/null 2>&1 || true ;;
    esac
    (( n > 0 )) && ok "SSH 放行已确保（$(cs_ssh_ports | paste -sd, -)）"
    return 0
}

cs_ssh_verify() { # 0=所有 SSH 端口都有规则
    local miss; miss=$(cs_ssh_rule_missing)
    [[ -z "${miss// /}" ]]
}

cs_ssh_status() {
    local p
    hr
    printf '  %bSSH 端口%b: %s\n' "$B" "$R" "$(cs_ssh_ports | paste -sd' ' -)"
    printf '  %b监听状态%b: %s\n' "$B" "$R" "$(cs_ssh_listening && echo 运行中 || echo 未监听)"
    printf '  %b当前后端%b: %s\n' "$B" "$R" "$(cs_backend_get)"
    printf '  %b规则检查%b:\n' "$B" "$R"
    while read -r p; do
        [[ -n "$p" ]] || continue
        if cs_rule_exists tcp "$p"; then
            printf '    %s/tcp  %b已放行%b\n' "$p" "$GRN" "$R"
        else
            printf '    %s/tcp  %b未放行%b  ← 危险\n' "$p" "$RED" "$R"
        fi
    done < <(cs_ssh_ports)
    # 第三方 DROP 规则检查
    if have iptables; then
        while read -r p; do
            [[ -n "$p" ]] || continue
            if iptables -S INPUT 2>/dev/null | grep -E -- "--dport ${p} .* -j (DROP|REJECT)"; then
                printf '    %b发现针对 %s 的 DROP/REJECT 规则（第三方）%b\n' "$YEL" "$p" "$R"
            fi
        done < <(cs_ssh_ports)
    fi
    hr
}

# ---------------------------- 启用 / 停用 ----------------------------
cs_apply() { # 按 enabled 状态重建当前后端（不做启停决策）
    local be; be=$(cs_backend_get)
    case "$be" in
        nft)      cs_nft_rebuild ;;
        ufw)      cs_ufw_ensure; [[ "$(cs_enabled_get)" == "1" ]] && ufw --force enable >/dev/null 2>&1 || true ;;
        iptables)
            cs_ipt_base_rules
            if [[ -f "$CS_LEDGER" ]]; then
                while IFS=$'\t' read -r owner proto port tag ts; do
                    [[ "$port" =~ ^[0-9]+$ ]] || continue
                    [[ "$owner" == "ssh" || "$owner" == "web" ]] && continue
                    case "$proto" in
                        tcp)  cs_ipt_allow "$owner" tcp "$port" ;;
                        udp)  cs_ipt_allow "$owner" udp "$port" ;;
                        both|"") cs_ipt_allow "$owner" tcp "$port"; cs_ipt_allow "$owner" udp "$port" ;;
                    esac
                done <"$CS_LEDGER"
            fi
            [[ "$(cs_enabled_get)" == "1" ]] && cs_ipt_policy drop || cs_ipt_policy accept ;;
        firewalld) : ;;
        *) return 1 ;;
    esac
}

cs_enable() { # 启用防火墙（带 deadman + SSH 校验）
    local be; be=$(cs_backend_get)
    cs_ssh_listening || { err "sshd 没在监听，拒绝启用防火墙（防止把自己关在外面）"; return 1; }
    # ufw 未启用时 status 看不到规则，不能据此判断"缺失"（会误报）
    if [[ "$be" != "ufw" ]] || ufw status 2>/dev/null | grep -q '^Status: active'; then
        local miss; miss=$(cs_ssh_rule_missing)
        if [[ -n "${miss// /}" ]]; then
            warn "SSH 端口规则缺失:$miss —— 先补齐"
            cs_ssh_protect >/dev/null 2>&1
        fi
    fi

    case "$be" in
        ufw)
            have ufw || { err "未安装 ufw"; return 1; }
            cs_ufw_ensure
            # ufw 未启用时 status 不显示规则，必须用 show added 校验
            local missu="" up
            for up in $(cs_ssh_ports); do
                ufw show added 2>/dev/null | grep -qE "allow ${up}/tcp" || missu+=" $up"
            done
            [[ -z "${missu// /}" ]] || { err "SSH 放行规则未进入 ufw 队列:$missu"; return 1; }
            cs_deadman_start "ufw disable >/dev/null 2>&1; echo 'DEADMAN: ufw disabled'" 180
            ufw default deny incoming >/dev/null 2>&1
            ufw default allow outgoing >/dev/null 2>&1
            ufw --force enable >/dev/null 2>&1 || { cs_deadman_cancel; err "ufw 启用失败"; return 1; }
            sleep 1
            if ! cs_ssh_verify; then
                err "启用后 SSH 规则缺失，立即回滚"
                ufw disable >/dev/null 2>&1
                cs_deadman_cancel
                return 1
            fi
            cs_deadman_cancel
            ;;
        nft)
            have nft || { err "未安装 nftables"; return 1; }
            cs_deadman_start "nft delete table inet ${CS_NFT_TABLE} >/dev/null 2>&1; echo 'DEADMAN: nft table dropped'" 180
            cs_nft_rebuild || { cs_deadman_cancel; err "nft 规则加载失败"; return 1; }
            sleep 1
            if ! cs_ssh_verify; then
                err "nft 下 SSH 规则缺失，立即回滚"
                cs_nft_delete
                cs_deadman_cancel
                return 1
            fi
            cs_deadman_cancel
            ;;
        iptables)
            have iptables || { err "未安装 iptables"; return 1; }
            cs_deadman_start "iptables -P INPUT ACCEPT >/dev/null 2>&1; ip6tables -P INPUT ACCEPT >/dev/null 2>&1; echo 'DEADMAN: iptables policy accept'" 180
            cs_ipt_base_rules
            cs_ipt_policy drop || { cs_deadman_cancel; err "iptables 策略设置失败"; return 1; }
            sleep 1
            if ! cs_ssh_verify; then
                err "iptables 下 SSH 规则缺失，立即回滚"
                cs_ipt_policy accept
                cs_deadman_cancel
                return 1
            fi
            cs_deadman_cancel
            ;;
        *) err "未知后端"; return 1 ;;
    esac
    cs_enabled_set 1
    cs_log "firewall enabled backend=$be"
    ok "防火墙已启用（后端: $be）"
    if ! cs_ssh_verify; then
        warn "SSH 规则异常，已启用 guard 兜底；如失联请用服务商控制台执行: catSafety panic"
    fi
    cs_install_guard >/dev/null 2>&1 || true
    return 0
}

cs_disable() {
    local be; be=$(cs_backend_get)
    case "$be" in
        ufw)      have ufw && ufw disable >/dev/null 2>&1 ;;
        nft)      cs_nft_delete ;;
        iptables) cs_ipt_policy accept ;;
        firewalld) have firewall-cmd && firewall-cmd --panic-off >/dev/null 2>&1 ;;
    esac
    cs_enabled_set 0
    cs_log "firewall disabled backend=$be"
    ok "防火墙已停用（规则保留在账本里，随时可恢复）"
}

# 紧急放行：不删规则，只把策略改回 ACCEPT / 停用后端
cs_panic() {
    cs_disable
    # 再兜一层：把常见第三方 DROP 策略也放回
    have iptables && iptables -P INPUT ACCEPT 2>/dev/null || true
    have ip6tables && ip6tables -P INPUT ACCEPT 2>/dev/null || true
    have ufw && ufw disable >/dev/null 2>&1 || true
    cs_nft_delete
    ok "PANIC 完成：所有已知防火墙策略已放行"
}

# ---------------------------- guard（SSH 自动抢救） ----------------------------
cs_guard() {
    local be enabled changed=0 p
    be=$(cs_backend_get)
    enabled=$(cs_enabled_get)
    [[ "$enabled" == "1" ]] || return 0
    mkdir -p "$CS_ROOT" 2>/dev/null
    date +%s >"$CS_ROOT/guard.last" 2>/dev/null
    cs_owners_sync >/dev/null 2>&1 || true
    cs_autosync >/dev/null 2>&1 || true

    # 0) 后端状态丢失（被删/被停）→ 按账本重建
    if ! cs_backend_active; then
        warn "guard: 后端 $be 未生效，按账本重建"
        cs_apply >/dev/null 2>&1 || true
        changed=1
    fi

    # 1) SSH 规则缺失 → 补
    local miss; miss=$(cs_ssh_rule_missing)
    if [[ -n "${miss// /}" ]]; then
        warn "guard: SSH 规则缺失:$miss → 自动补放行"
        cs_ssh_protect >/dev/null 2>&1 || true
        changed=1
    fi

    # 2) sshd 没在监听 → 尝试拉起（只一次）
    if ! cs_ssh_listening; then
        if [[ "$(readlink /proc/self/ns/net 2>/dev/null)" != "$(readlink /proc/1/ns/net 2>/dev/null)" ]]; then
            warn "guard: 非主机命名空间，跳过 sshd 重启"
            return 0
        fi
        warn "guard: sshd 未监听 → 尝试重启"
        systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true
        sleep 1
        changed=1
    fi

    # 1.5) 账本里的其它端口规则缺失 → 按账本整体重放（防火墙自愈）
    local miss_any=0 owner proto port tag ts
    if [[ -f "$CS_LEDGER" ]]; then
        while IFS=$'\t' read -r owner proto port tag ts; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            [[ "$owner" == "ssh" || "$owner" == "web" ]] && continue
            cs_is_protected "$port" && continue
            if ! cs_rule_exists tcp "$port"; then miss_any=1; break; fi
        done <"$CS_LEDGER"
    fi
    if (( miss_any )); then
        warn "guard: 账本端口规则缺失 → 按账本重放"
        cs_apply >/dev/null 2>&1 || true
        changed=1
    fi

    # 2.5) 外来 nft 表里针对 SSH 的 drop：无法安全自动改别人的表，至少告警
    if [[ "$be" == "nft" ]] && have nft; then
        while read -r p; do
            [[ -n "$p" ]] || continue
            if nft list ruleset 2>/dev/null | grep -E "dport ${p}([^0-9]|$)" | grep -qi 'drop'; then
                warn "guard: 检测到外来 nft 规则可能 drop SSH $p（请检查其它 nft 表）"
                cs_log "guard warning: foreign nft drop for ssh $p"
            fi
        done < <(cs_ssh_ports)
    fi

    # 3) 第三方针对 SSH 的 DROP/REJECT → 在 iptables 最前面插 ACCEPT（同表可救）
    if have iptables; then
        while read -r p; do
            [[ -n "$p" ]] || continue
            if iptables -S INPUT 2>/dev/null | grep -E -- "--dport ${p} .* -j (DROP|REJECT)" >/dev/null; then
                warn "guard: 发现第三方 DROP/REJECT 针对 SSH $p，插入救急放行"
                iptables -I INPUT 1 -p tcp --dport "$p" -m comment --comment "catSafety-ssh-rescue" -j ACCEPT 2>/dev/null || true
                have ip6tables && ip6tables -I INPUT 1 -p tcp --dport "$p" -m comment --comment "catSafety-ssh-rescue" -j ACCEPT 2>/dev/null || true
                changed=1
            fi
        done < <(cs_ssh_ports)
    fi

    if (( changed )); then
        cs_log "guard: repaired ssh/firewall state"
        printf 'guard repaired at %s\n' "$(date '+%F %T')" >>"$CS_ROOT/guard.log" 2>/dev/null
    fi
    return 0
}

# ---------------------------- 三内核端口发现 ----------------------------
CS_X_DIR="${CS_X_DIR:-/root/catmi/xray/conf}"
CS_M_DIR="${CS_M_DIR:-/root/catmi/mihomo/conf/config.d}"
CS_SB_DIR="${CS_SB_DIR:-/root/catmi/sing-box/config}"
CS_X_LEDGER="${CS_X_LEDGER:-/root/catmi/xray/.fw-ports}"
CS_M_LEDGER="${CS_M_LEDGER:-/root/catmi/mihomo/.fw-ports}"
CS_SB_LEDGER="${CS_SB_LEDGER:-/root/catmi/sing-box/.fw-ports}"

cs_scan_xray() {
    [[ -d "$CS_X_DIR" ]] || return 0
    python3 - "$CS_X_DIR" <<'PY' 2>/dev/null
import glob, json, os, sys
d = sys.argv[1]
ports = set()
for f in glob.glob(os.path.join(d, "*.json")):
    try:
        j = json.load(open(f, encoding="utf-8"))
    except Exception:
        continue
    for ib in (j.get("inbounds") or []):
        p = ib.get("port")
        if not isinstance(p, int):
            continue
        listen = str(ib.get("listen") or "")
        if listen in ("127.0.0.1", "::1"):
            continue
        ports.add(p)
for p in sorted(ports):
    print(p)
PY
}

cs_scan_mihomo() {
    [[ -d "$CS_M_DIR" ]] || return 0
    awk '
        /^listeners:/ { inl = 1; next }
        /^[a-zA-Z]/  { inl = 0 }
        inl && /^[[:space:]]*-?[[:space:]]*port:[[:space:]]*[0-9]+/ {
            if (match($0, /[0-9]+/)) print substr($0, RSTART, RLENGTH)
        }
    ' "$CS_M_DIR"/*.yaml 2>/dev/null | sort -nu
}

cs_scan_singbox() {
    [[ -d "$CS_SB_DIR" ]] || return 0
    python3 - "$CS_SB_DIR" <<'PY' 2>/dev/null
import glob, json, os, sys
d = sys.argv[1]
ports = set()
for f in glob.glob(os.path.join(d, "*.json")):
    try:
        j = json.load(open(f, encoding="utf-8"))
    except Exception:
        continue
    for ib in (j.get("inbounds") or []):
        p = ib.get("listen_port")
        if isinstance(p, int):
            ports.add(p)
for p in sorted(ports):
    print(p)
PY
}

cs_scan_ledger_file() { # <file>
    [[ -r "$1" ]] || return 0
    grep -E '^[0-9]+$' "$1" 2>/dev/null | sort -nu
}

cs_kernel_ports() { # <xray|mihomo|sing-box>
    # ★ 只认**当前配置里的监听端口**。三家的 .fw-ports 账本在生产上已经证明会漂移
    #   (实测 SB 218 条 / 实际 17 个)，拿它当来源会把早已删掉的端口重新打开。
    #   只有配置目录不存在（换机器/只装了账本）时才回退到账本。
    local ports led
    case "$1" in
        xray)     ports=$(cs_scan_xray);     led="$CS_X_LEDGER" ;;
        mihomo)   ports=$(cs_scan_mihomo);   led="$CS_M_LEDGER" ;;
        sing-box) ports=$(cs_scan_singbox);  led="$CS_SB_LEDGER" ;;
        *) return 0 ;;
    esac
    if [[ -n "$ports" ]]; then
        printf '%s\n' "$ports"
    else
        cs_scan_ledger_file "$led"
    fi
}

cs_kernel_sync() { # [--prune] [--dry-run]
    local prune=0 dry=0 a owner p n=0 added=0
    for a in "$@"; do
        case "$a" in
            --prune) prune=1 ;;
            --dry-run) dry=1 ;;
        esac
    done
    for owner in xray mihomo sing-box; do
        local ports; ports=$(cs_kernel_ports "$owner")
        [[ -n "$ports" ]] || { info "$owner: 未发现端口（未安装或目录不存在）"; continue; }
        info "$owner: $(printf '%s ' $ports)"
        for p in $ports; do
            cs_is_protected "$p" && continue
            if (( dry )); then
                cs_ledger_has "$owner" both "$p" || { echo "    + $owner both/$p"; added=$((added+1)); }
                continue
            fi
            if ! cs_ledger_has "$owner" both "$p"; then
                cs_open "$owner" both "$p" "kernel" >/dev/null 2>&1 && { added=$((added+1)); n=$((n+1)); }
            else
                n=$((n+1))
            fi
        done
        if (( prune )); then
            local cur=" $ports "
            while IFS=$'\t' read -r o proto port tag ts; do
                [[ "$o" == "$owner" ]] || continue
                [[ "$cur" == *" $port "* ]] && continue
                cs_is_protected "$port" && continue
                (( dry )) && { echo "    - $owner $proto/$port"; continue; }
                cs_close "$owner" "$proto" "$port" >/dev/null 2>&1 || true
            done <"$CS_LEDGER"
        fi
    done
    # 分享服务端口（如果存在）
    local sp=""
    [[ -r /run/proxy-share-service/port ]] && sp=$(tr -dc '0-9' </run/proxy-share-service/port)
    if [[ -n "$sp" ]]; then
        if (( dry )); then echo "    + share both/$sp"; else cs_open share both "$sp" "share-service" >/dev/null 2>&1 || true; fi
    fi
    (( dry )) || ok "内核端口同步完成（已处理 $n 个，新增 $added 个）"
}

# ---------------------------- 自动开放监听端口 / 账本对账 ----------------------------
# 用户需求: "找本机对外端口自动开放"，同时不能影响三内核自己开关端口。
# 做法: 以**监听状态**为准每分钟对账：
#   · 新监听的非回环端口 → 自动放行（owner=auto）
#   · 账本里有、但既不监听、也不在对应内核当前配置里的端口 → 宽限期后关闭
#   这样内核无论是用 ufw/iptables/nft 自己开的，还是根本没写防火墙代码（Xray），
#   只要它把端口 listen 起来，catSafety 就会补放行；它关掉监听，宽限期后回收。
CS_AUTOSCAN_FILE="${CS_AUTOSCAN_FILE:-$CS_ROOT/autoscan}"
# 宽限秒数来自上面的配置（默认 900）
CS_STALE_FILE="${CS_STALE_FILE:-$CS_ROOT/stale.tsv}"
CS_LAST_SCAN_FILE="${CS_LAST_SCAN_FILE:-$CS_ROOT/last-scan}"
CS_OWNERS_DIR="${CS_OWNERS_DIR:-$CS_ROOT/owners}"
CS_HOOKS_DIR="${CS_HOOKS_DIR:-$CS_ROOT/hooks}"

cs_autoscan_on()  { [[ "$(cat "$CS_AUTOSCAN_FILE" 2>/dev/null || echo 1)" != "0" ]]; }
cs_autoscan_set() { mkdir -p "$CS_ROOT"; printf '%s\n' "$1" >"$CS_AUTOSCAN_FILE"; }

# 只取**对外**监听：绑 127.0.0.1 / ::1 的不算（自动开放不应该为回环端口放行）
cs_tcp_listen_ports() {
    ss -Hltn 2>/dev/null | awk '{print $4}' \
        | grep -vE '^(127\.|\[::1\]|::1)' | sed 's/.*://' | grep -E '^[0-9]+$' | sort -nu
}
cs_udp_listen_ports() {
    ss -Huln 2>/dev/null | awk '{print $4}' \
        | grep -vE '^(127\.|\[::1\]|::1)' | sed 's/.*://' | grep -E '^[0-9]+$' | sort -nu
}
cs_listen_has() { # <tcp|udp> <port>
    local list
    if [[ "$1" == "tcp" ]]; then list=$(cs_tcp_listen_ports); else list=$(cs_udp_listen_ports); fi
    printf '%s\n' "$list" | grep -qx "$2"
}

cs_stale_get() { # <owner> <proto> <port> → 秒数(相对 now) 或空
    [[ -f "$CS_STALE_FILE" ]] || return 0
    awk -F'\t' -v o="$1" -v p="$2" -v n="$3" '$1==o&&$2==p&&$3==n{print $4}' "$CS_STALE_FILE" 2>/dev/null
}
cs_stale_set() { # <owner> <proto> <port>
    mkdir -p "$CS_ROOT"
    cs_stale_del "$1" "$2" "$3"
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$(date +%s)" >>"$CS_STALE_FILE"
}
cs_stale_del() {
    [[ -f "$CS_STALE_FILE" ]] || return 0
    awk -F'\t' -v o="$1" -v p="$2" -v n="$3" '!($1==o&&$2==p&&$3==n)' "$CS_STALE_FILE" >"$CS_STALE_FILE.tmp.$$" 2>/dev/null \
        && mv -f "$CS_STALE_FILE.tmp.$$" "$CS_STALE_FILE" 2>/dev/null || rm -f "$CS_STALE_FILE.tmp.$$"
}

# 内核配置里的端口（用于判断"服务暂时没起，但配置还在"）
cs_owner_in_config() { # <owner> <port>
    local owner="$1" port="$2"
    case "$owner" in
        xray)     cs_scan_xray | grep -qx "$port" ;;
        mihomo)   cs_scan_mihomo | grep -qx "$port" ;;
        sing-box) cs_scan_singbox | grep -qx "$port" ;;
        share)    [[ -r /run/proxy-share-service/port ]] && tr -dc '0-9' </run/proxy-share-service/port | grep -qx "$port" ;;
        *) return 1 ;;
    esac
}

cs_autosync() {
    local now; now=$(date +%s)
    mkdir -p "$CS_ROOT"
    # 防并发：guard timer 与手动/开机恢复可能同时跑，对账会互相覆盖
    local _lock="$CS_ROOT/.autosync.lock"
    mkdir "$_lock" 2>/dev/null || return 3
    trap "rmdir '${_lock}' 2>/dev/null" RETURN
    date +%s >"$CS_LAST_SCAN_FILE" 2>/dev/null
    [[ "$(cs_enabled_get)" == "1" ]] || return 0
    cs_autoscan_on || return 0

    local tcp udp opened=0 closed=0 kept=0 proto port owner tag ts
    tcp=$(cs_tcp_listen_ports)
    udp=$(cs_udp_listen_ports)

    # --- 1) 新监听端口 → 自动放行 ---
    for proto in tcp udp; do
        local list; [[ "$proto" == "tcp" ]] && list=$tcp || list=$udp
        for port in $list; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            cs_is_protected "$port" && continue
            if ! cs_ledger_has auto "$proto" "$port" \
               && ! cs_ledger_has xray both "$port" && ! cs_ledger_has mihomo both "$port" \
               && ! cs_ledger_has sing-box both "$port" && ! cs_ledger_has share both "$port" \
               && ! cs_ledger_has legacy both "$port"; then
                if cs_open auto "$proto" "$port" "autoscan" >/dev/null 2>&1; then
                    opened=$((opened+1)); cs_log "auto-open $proto/$port"
                fi
            fi
        done
    done

    # --- 2) 账本对账：不监听且配置里也没有 → 宽限期后关闭 ---
    if [[ -f "$CS_LEDGER" ]]; then
        while IFS=$'\t' read -r owner proto port tag ts; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            cs_is_protected "$port" && continue
            [[ "$owner" == "ssh" || "$owner" == "web" ]] && continue
            local alive=0
            case "$proto" in
                tcp)  cs_listen_has tcp "$port" && alive=1 ;;
                udp)  cs_listen_has udp "$port" && alive=1 ;;
                both|"") { cs_listen_has tcp "$port" || cs_listen_has udp "$port"; } && alive=1 ;;
            esac
            if (( ! alive )) && cs_owner_in_config "$owner" "$port"; then alive=1; fi
            if (( ! alive )) && cs_owner_manifest_has "$owner" "$port"; then alive=1; fi
            if (( alive )); then
                cs_stale_del "$owner" "$proto" "$port"; kept=$((kept+1)); continue
            fi
            local since; since=$(cs_stale_get "$owner" "$proto" "$port")
            [[ -n "$since" ]] || { cs_stale_set "$owner" "$proto" "$port"; continue; }
            if (( now - since >= CS_AUTO_GRACE )); then
                if cs_close "$owner" "$proto" "$port" >/dev/null 2>&1; then
                    cs_purge_kernel_rules "$port"
                    closed=$((closed+1)); cs_log "auto-close $owner $proto/$port (stale)"
                    cs_stale_del "$owner" "$proto" "$port"
                fi
            fi
        done <"$CS_LEDGER"
    fi

    cs_sweep_stale_kernel_rules
    (( opened || closed )) && ok "自动端口对账: 新增 $opened, 回收 $closed, 保留 $kept"
    return 0
}

# 全量清扫：iptables 里带内核注释、但端口已不监听、也不在内核配置里的规则。
# 不依赖账本 —— 代理项目不走 catSafety 时，账本里可能没有这条记录。
cs_sweep_stale_kernel_rules() {
    local bin line proto port c owner
    for bin in iptables ip6tables; do
        have "$bin" || continue
        while IFS= read -r line; do
            proto=$(printf '%s' "$line" | grep -oE -- '-p (tcp|udp)' | awk '{print $2}')
            port=$(printf '%s' "$line" | grep -oE -- '--dport [0-9]+' | awk '{print $2}')
            c=$(printf '%s' "$line" | sed -n 's/.*--comment \([^ ]*\).*/\1/p')
            [[ -n "$proto" && -n "$port" ]] || continue
            cs_is_protected "$port" && continue
            cs_listen_has "$proto" "$port" && continue
            case "$c" in
                MIHOMO-Panel*) owner="mihomo" ;;
                SB-Panel*)     owner="sing-box" ;;
                Xray-Panel*)   owner="xray" ;;
                *)             continue ;;
            esac
            cs_owner_in_config "$owner" "$port" && continue
            cs_purge_kernel_rules "$port"
            cs_log "sweep stale kernel rule: $owner $proto/$port"
        done < <("$bin" -S INPUT 2>/dev/null | grep -- '--dport' \
                 | grep -E -- '--comment (MIHOMO-Panel|SB-Panel|Xray-Panel)')
    done
}

# ---------------------------- 外部项目联动（声明式 owner 清单） ----------------------------
# 其他项目**不需要关心**当前是 UFW 还是 nftables，只需要：
#   1) 写一份清单: /etc/catSafety/owners/<项目名>.ports
#         tcp 8080
#         udp 51820
#         both 443
#   2) 或者直接调: catSafety owner-set <项目名> tcp:8080 udp:51820
# catSafety 每分钟按清单放行/回收，切换后端时账本自动迁移。
# 这样"以后的项目"只有一个稳定接口，不依赖防火墙实现。

cs_owner_name_ok() { [[ "$1" =~ ^[A-Za-z0-9._-]{1,40}$ ]]; }
cs_owner_file() { printf '%s/%s.ports' "$CS_OWNERS_DIR" "${1:?}"; }

cs_owner_manifest_has() { # <owner> <port>
    local f; f=$(cs_owner_file "$1" 2>/dev/null) || return 1
    [[ -f "$f" ]] || return 1
    awk -v n="$2" '
        /^[[:space:]]*#/ { next }
        {
            p=""
            if ($1=="tcp"||$1=="udp"||$1=="both") p=$2
            else if ($1 ~ /^[0-9]+\/(tcp|udp|both)$/) { split($1,a,"/"); p=a[1] }
            else if ($1 ~ /^[0-9]+$/) p=$1
            if (p==n) { found=1; exit }
        }
        END { exit(found?0:1) }' "$f"
}

# 清理"内核项目留下、但端口已经不监听"的 iptables 规则。
# 为什么需要: 代理项目没有改动（用户要求），它们删节点时可能不回收 iptables；
# 在 UFW 后端下，这些残留 ACCEPT 会绕过 ufw 的 deny，端口看起来还开着。
# 只删带明确内核注释的规则，且只对"已判定失效"的端口调用。
cs_purge_kernel_rules() { # <port>
    local port="$1" bin line
    [[ "$port" =~ ^[0-9]+$ ]] || return 0
    for bin in iptables ip6tables; do
        have "$bin" || continue
        while :; do
            line=$("$bin" -S INPUT 2>/dev/null \
                | grep -- "--dport ${port} " \
                | grep -E -- '--comment (MIHOMO-Panel|SB-Panel|Xray-Panel|catSafety-)' \
                | head -1)
            [[ -n "$line" ]] || break
            line="${line/-A INPUT /-D INPUT }"
            "$bin" $line 2>/dev/null || break
            cs_log "purge stale kernel iptables rule: $port"
        done
    done
}

cs_owners_sync() {
    [[ -d "$CS_OWNERS_DIR" ]] || return 0
    local f owner proto port tag ts desired opened closed n
    for f in "$CS_OWNERS_DIR"/*.ports; do
        [[ -f "$f" ]] || continue
        owner=$(basename "$f" .ports)
        cs_owner_name_ok "$owner" || { warn "跳过非法 owner 名: $owner"; continue; }
        opened=0; closed=0; n=0
        # 放行清单里新增的
        while read -r proto port _tag; do
            [[ -n "$proto" && -n "$port" ]] || continue
            [[ "$proto" == "tcp" || "$proto" == "udp" || "$proto" == "both" ]] || continue
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            cs_is_protected "$port" && continue
            n=$((n+1))
            if ! cs_ledger_has "$owner" "$proto" "$port"; then
                cs_open "$owner" "$proto" "$port" "manifest" >/dev/null 2>&1 && opened=$((opened+1))
            fi
        done < <(awk '
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*$/ { next }
            $1=="tcp"||$1=="udp"||$1=="both" { print $1, $2; next }
            $1 ~ /^[0-9]+\/(tcp|udp|both)$/ { split($1,a,"/"); print a[2], a[1]; next }
            $1 ~ /^[0-9]+$/ { print "both", $1; next }' "$f")
        # 回收清单里删掉的（只动 owner 自己、tag=manifest 的）
        if [[ -f "$CS_LEDGER" ]]; then
            while IFS=$'\t' read -r o proto port tag ts; do
                [[ "$o" == "$owner" && "$tag" == "manifest" ]] || continue
                cs_owner_manifest_has "$owner" "$port" && continue
                cs_close "$owner" "$proto" "$port" >/dev/null 2>&1 && closed=$((closed+1))
            done <"$CS_LEDGER"
        fi
        (( opened || closed )) && ok "owner [$owner]: 放行 $opened，回收 $closed（清单 $n 条）"
    done
    return 0
}

cs_owner_set() { # <owner> <tcp:8080|udp:51820|8080> ...
    local owner="${1:?owner}"; shift
    cs_owner_name_ok "$owner" || { err "owner 名只能是字母数字._-"; return 1; }
    mkdir -p "$CS_OWNERS_DIR"
    local f; f=$(cs_owner_file "$owner")
    : >"$f.tmp.$$"
    local spec proto port
    for spec in "$@"; do
        case "$spec" in
            *:*) proto="${spec%%:*}"; port="${spec#*:}" ;;
            */*) port="${spec%%/*}"; proto="${spec##*/}" ;;
            *)   proto="both"; port="$spec" ;;
        esac
        [[ "$proto" == "tcp" || "$proto" == "udp" || "$proto" == "both" ]] || { err "协议不对: $spec"; rm -f "$f.tmp.$$"; return 1; }
        [[ "$port" =~ ^[0-9]+$ ]] || { err "端口不对: $spec"; rm -f "$f.tmp.$$"; return 1; }
        printf '%s %s\n' "$proto" "$port" >>"$f.tmp.$$"
    done
    mv -f "$f.tmp.$$" "$f"
    ok "已更新清单 $f"
    cs_owners_sync
}

cs_owner_clear() { # <owner>
    local owner="${1:?owner}" f; f=$(cs_owner_file "$owner")
    rm -f "$f"
    if [[ -f "$CS_LEDGER" ]]; then
        local o proto port tag ts
        while IFS=$'\t' read -r o proto port tag ts; do
            [[ "$o" == "$owner" ]] || continue
            cs_close "$owner" "$proto" "$port" >/dev/null 2>&1 || true
        done <"$CS_LEDGER"
    fi
    ok "已清除 owner [$owner] 的清单和端口"
}

# ---------------------------- 后端切换（保留账本） ----------------------------
cs_run_hook() { # <name> <args...>
    local h="$CS_HOOKS_DIR/$1"; shift
    [[ -x "$h" ]] || return 0
    "$h" "$@" >/dev/null 2>&1 || warn "hook $(basename "$h") 返回非 0"
}

cs_switch() { # <ufw|nft|iptables>
    local new="${1:-}" old; old=$(cs_backend_get)
    case "$new" in ufw|nft|iptables|firewalld) ;; *) err "未知后端: $new"; return 1 ;; esac
    [[ "$new" == "$old" ]] && { info "后端已经是 $new"; return 0; }
    cs_run_hook pre-switch "$old" "$new"
    local was_enabled; was_enabled=$(cs_enabled_get)
    # 先停旧的（账本不动）
    cs_disable >/dev/null 2>&1 || true
    cs_backend_set "$new" || return 1
    if [[ "$was_enabled" == "1" ]]; then
        cs_enabled_set 1
        if ! cs_enable; then
            err "切换到 $new 失败，回退到 $old"
            cs_backend_set "$old"
            cs_enabled_set 1
            cs_enable >/dev/null 2>&1 || cs_panic >/dev/null 2>&1
            return 1
        fi
    else
        info "后端已切换为 $new（当前未启用）"
    fi
    cs_run_hook post-switch "$old" "$new"
    # 让系统里可能存在的开机单元也跟着迁移
    cs_install_restore_unit >/dev/null 2>&1 || true
    ok "后端切换: $old → $new（账本保留，端口已按新后端重放）"
}

# ---------------------------- 给其它项目的稳定接口（JSON） ----------------------------
cs_status_json() {
    local be en ssh ledger owners guard f2b auto
    be=$(cs_backend_get); en=$(cs_enabled_get)
    ssh=$(cs_ssh_ports | paste -sd, -)
    ledger=$([[ -f "$CS_LEDGER" ]] && wc -l <"$CS_LEDGER" || echo 0)
    owners=0; [[ -d "$CS_OWNERS_DIR" ]] && owners=$(ls -1 "$CS_OWNERS_DIR"/*.ports 2>/dev/null | wc -l)
    guard=$(systemctl is-active catSafety-guard.timer 2>/dev/null || echo inactive)
    f2b=$(systemctl is-active fail2ban 2>/dev/null || echo inactive)
    auto=$([[ "$(cs_autoscan_on)" == "0" ]] && echo 0 || echo 1)
    printf '{"version":"%s","backend":"%s","enabled":%s,"ssh_ports":[%s],"ledger":%s,"owners":%s,"guard":"%s","fail2ban":"%s","autoscan":%s}\n' \
        "$CS_VERSION" "$be" "$([[ "$en" == 1 ]] && echo true || echo false)" \
        "$(printf '%s' "$ssh" | sed 's/[^0-9,]/ /g; s/ *, */,/g')" \
        "$ledger" "$owners" "$guard" "$f2b" "$auto"
}

# ---------------------------- 第三方接管 ----------------------------
cs_backup() {
    local ts dir
    ts=$(date +%Y%m%d-%H%M%S)
    dir="$CS_BACKUP/$ts"
    mkdir -p "$dir" || return 1
    {
        have iptables && iptables-save >"$dir/iptables.v4" 2>/dev/null || true
        have ip6tables && ip6tables-save >"$dir/ip6tables.v6" 2>/dev/null || true
        have nft && nft list ruleset >"$dir/nft.ruleset" 2>/dev/null || true
        have ufw && ufw status numbered >"$dir/ufw.status" 2>/dev/null || true
        crontab -l >"$dir/crontab.txt" 2>/dev/null || true
        tar -czf "$dir/etc-fw.tar.gz" /etc/ufw /etc/nftables.conf /etc/nftables.d /etc/iptables /etc/fail2ban 2>/dev/null || true
        cp -a "$CS_LEDGER" "$dir/ledger.tsv" 2>/dev/null || true
        cp -a "$CS_ROOT" "$dir/catSafety-root" 2>/dev/null || true
    } >/dev/null 2>&1
    cs_log "backup -> $dir"
    printf '%s' "$dir"
}

cs_import_existing() { # 把现有放行规则导入账本（owner=legacy）
    local n=0 proto port
    # iptables / ip6tables
    if have iptables; then
        while IFS= read -r line; do
            proto=$(printf '%s' "$line" | grep -oE -- '-p (tcp|udp)' | awk '{print $2}')
            port=$(printf '%s' "$line" | grep -oE -- '--dport [0-9]+' | awk '{print $2}')
            [[ -n "$proto" && -n "$port" ]] || continue
            cs_ledger_add legacy "$proto" "$port" "imported-iptables"
            n=$((n+1))
        done < <(iptables -S INPUT 2>/dev/null | grep -- '-j ACCEPT' | grep -- '--dport' | grep -v 'catSafety-')
    fi
    # ufw
    if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
        while read -r spec; do
            port="${spec%%/*}"; proto="${spec##*/}"
            [[ "$port" =~ ^[0-9]+$ && ( "$proto" == "tcp" || "$proto" == "udp" ) ]] || continue
            cs_ledger_add legacy "$proto" "$port" "imported-ufw"
            n=$((n+1))
        done < <(ufw status 2>/dev/null | awk '$2=="ALLOW"{print $1}' | grep -E '^[0-9]+/(tcp|udp)$')
    fi
    # nft（排除本工具自己的表）
    if have nft; then
        while read -r proto port; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            cs_ledger_add legacy "$proto" "$port" "imported-nft"
            n=$((n+1))
        done < <(nft list ruleset 2>/dev/null | sed -n 's/.*\(tcp\|udp\) dport \([0-9]\+\) accept.*/\1 \2/p' | sort -u)
    fi
    ok "已导入现有放行规则 $n 条（owner=legacy，可追溯）"
}

# 把当前**正在监听**的非回环端口导入账本（owner=legacy）。
# 目的: 接管/启用前先保证"原来能访问的东西不会因为新策略被关掉"。
# 这一步比解析别人规则更可靠 —— 监听才是事实。
# 删除"端口已有明确归属、却还挂着 legacy"的重复账目
cs_ledger_prune_legacy() {
    [[ -f "$CS_LEDGER" ]] || return 0
    local n; n=$(awk -F'\t' '$1=="legacy"{print $3}' "$CS_LEDGER" | sort -u | wc -l)
    awk -F'\t' 'NR==FNR{ if ($1!="legacy") own[$3]=1; next }
        !($1=="legacy" && ($3 in own))' "$CS_LEDGER" "$CS_LEDGER" >"$CS_LEDGER.tmp" \
        && mv -f "$CS_LEDGER.tmp" "$CS_LEDGER"
    ok "已清理 legacy 重复账目（原 legacy 端口 $n 个）"
}

cs_import_listening() {
    local n=0 p addr proto
    while read -r proto addr; do
        [[ -n "$addr" ]] || continue
        p="${addr##*:}"
        [[ "$p" =~ ^[0-9]+$ ]] || continue
        case "$addr" in 127.*|"[::1]"*|::1*) continue ;; esac
        cs_is_protected "$p" && continue
        # 已经有归属的端口不再登记 legacy（否则同一端口两条规则/两份账）
        if cs_ledger_has xray both "$p" || cs_ledger_has mihomo both "$p" \
           || cs_ledger_has sing-box both "$p" || cs_ledger_has share both "$p"; then
            continue
        fi
        cs_ledger_add legacy both "$p" "imported-listening" && n=$((n+1))
    done < <( { ss -Hltn 2>/dev/null | awk '{print "tcp",$4}'; ss -Huln 2>/dev/null | awk '{print "udp",$4}'; } )
    ok "已导入当前监听端口 $n 个（owner=legacy）"
}

cs_disable_foreign() {
    local ts; ts=$(date +%Y%m%d-%H%M%S)
    # 备份 crontab 后移除 @reboot iptables-restore（第三方自恢复）
    if crontab -l 2>/dev/null | grep -qE '@reboot .*iptables-restore'; then
        crontab -l >"$CS_ROOT/crontab.bak.$ts" 2>/dev/null || true
        crontab -l 2>/dev/null | grep -vE '@reboot .*iptables-restore' | crontab - 2>/dev/null || true
        info "已移除 @reboot iptables-restore（原 crontab 见 $CS_ROOT/crontab.bak.$ts）"
    fi
    for u in nftables nftables-ufw-panel sb-panel-nft firewalld; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${u}.service"; then
            systemctl stop "$u" >/dev/null 2>&1 || true
            systemctl disable "$u" >/dev/null 2>&1 || true
            info "已停用 $u.service"
        fi
    done
    # 外来 nft 的 inet filter：如果保留，它的 drop 会先于我们的表生效，
    # 我们的 SSH 放行就形同虚设。接管语义下删掉（备份里已有完整 ruleset）。
    if [[ "$(cs_backend_get)" == "nft" ]] && have nft \
       && nft list table inet filter >/dev/null 2>&1; then
        nft delete table inet filter 2>/dev/null && info "已移除外来 inet filter 表（备份中可恢复）"
    fi
    if systemctl list-unit-files 2>/dev/null | grep -q '^netfilter-persistent.service'; then
        systemctl disable netfilter-persistent >/dev/null 2>&1 || true
        info "已禁用 netfilter-persistent（规则改由 catSafety 管理）"
    fi
}

cs_takeover() { # [--dry-run] [--yes]
    local dry=0 yes=0 a
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; --yes|-y) yes=1 ;; esac; done
    local be; be=$(cs_backend_get)
    hr
    printf '  %b接管方案%b\n' "$B" "$R"
    printf '    当前后端选择 : %s\n' "$be"
    printf '    检测到外部   : %s\n' "$(cs_foreign_list)"
    printf '    SSH 端口     : %s\n' "$(cs_ssh_ports | paste -sd' ' -)"
    printf '    三内核端口   : X=%s M=%s SB=%s\n' \
        "$(cs_kernel_ports xray | wc -w)" "$(cs_kernel_ports mihomo | wc -w)" "$(cs_kernel_ports sing-box | wc -w)"
    hr
    if (( dry )); then
        info "预演：以下动作不会执行"
        cs_kernel_sync --dry-run
        info "将备份 /etc/ufw /etc/nftables* /etc/iptables /etc/fail2ban + crontab + 当前规则"
        info "将导入现有 ACCEPT 规则为 owner=legacy，并停用第三方防火墙服务"
        info "将用后端 $be 启用策略（带 180s deadman + SSH 校验）"
        return 0
    fi
    if (( ! yes )); then
        warn "接管会：停用第三方防火墙服务 + 启用 $be 的默认拒绝策略。"
        confirm_ "确认接管? (y/N)" || { info "已取消"; return 0; }
    fi
    local bak; bak=$(cs_backup) || { err "备份失败，拒绝接管"; return 1; }
    ok "已备份: $bak"

    cs_import_existing
    cs_import_listening
    cs_kernel_sync >/dev/null 2>&1 || true
    cs_disable_foreign
    cs_backend_set "$be" || { err "后端设置失败"; return 1; }
    cs_enabled_set 1
    if ! cs_enable; then
        err "启用失败 —— 已回滚到 panic 状态"
        cs_panic >/dev/null 2>&1
        err "备份在 $bak，可执行: catSafety restore $bak"
        return 1
    fi
    cs_install_guard >/dev/null 2>&1 || true
    cs_install_restore_unit >/dev/null 2>&1 || true
    ok "接管完成。当前后端: $be；SSH: $(cs_ssh_ports | paste -sd, -)"
}

# ---------------------------- systemd 单元 ----------------------------
cs_install_guard() {
    [[ -d /run/systemd/system ]] || { info "非 systemd 环境，跳过 guard 单元"; return 0; }
    local bin; bin=$(command -v catSafety 2>/dev/null || echo "$CS_INSTALL_DIR/catSafety.sh")
    cat >"$CS_UNIT_DIR/catSafety-guard.service" <<EOF
[Unit]
Description=catSafety SSH guard (auto-restore firewall rules)
After=network-online.target ufw.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${bin} guard
EOF
    cat >"$CS_UNIT_DIR/catSafety-guard.timer" <<EOF
[Unit]
Description=catSafety SSH guard timer

[Timer]
OnBootSec=20
OnUnitActiveSec=60
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now catSafety-guard.timer >/dev/null 2>&1 || true
    ok "已安装 SSH 守护: catSafety-guard.timer（每分钟）"
}

cs_install_restore_unit() {
    [[ -d /run/systemd/system ]] || return 0
    local bin; bin=$(command -v catSafety 2>/dev/null || echo "$CS_INSTALL_DIR/catSafety.sh")
    cat >"$CS_UNIT_DIR/catSafety-restore.service" <<EOF
[Unit]
Description=catSafety restore firewall rules from ledger
After=network-online.target ufw.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${bin} apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable catSafety-restore.service >/dev/null 2>&1 || true
    ok "已安装开机恢复: catSafety-restore.service"
}

# ---------------------------- 包安装 ----------------------------
cs_pkg_install() { # <pkg...>
    local p
    if have apt-get; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1
    elif have dnf; then dnf install -y "$@" >/dev/null 2>&1
    elif have yum; then yum install -y "$@" >/dev/null 2>&1
    elif have apk; then apk add "$@" >/dev/null 2>&1
    else
        err "没有可用的包管理器"; return 1
    fi
}

# ---------------------------- Fail2ban ----------------------------
cs_f2b_banaction() {
    case "$(cs_backend_get)" in
        ufw)       echo ufw ;;
        nft)       echo nftables-multiport ;;
        iptables)  echo iptables-multiport ;;
        firewalld) echo firewallcmd-multiport ;;
        *)         echo iptables-multiport ;;
    esac
}

cs_f2b_install() {
    have fail2ban-client || { info "安装 fail2ban..."; cs_pkg_install fail2ban || { err "安装失败（检查网络/源）"; return 1; }; }
    local jail=/etc/fail2ban/jail.d/zzz-catSafety.local
    local admin_ip="" ports ban
    ports=$(cs_ssh_ports | paste -sd, -)
    ban=$(cs_f2b_banaction)
    # 当前登录的管理 IP 自动加白，避免自己被 ban
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        admin_ip="${SSH_CLIENT%% *}"
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        admin_ip="${SSH_CONNECTION%% *}"
    fi
    mkdir -p /etc/fail2ban/jail.d
    local bak=""
    if [[ -f "$jail" ]]; then
        bak="$jail.bak.$(date +%Y%m%d-%H%M%S)"; cp -f "$jail" "$bak" 2>/dev/null || true
    fi
    {
        echo "[DEFAULT]"
        echo "banaction = ${ban}"
        echo "ignoreip = 127.0.0.1/8 ::1${admin_ip:+ ${admin_ip}}"
        echo "bantime = 1h"
        echo "findtime = 10m"
        echo "maxretry = 5"
        echo ""
        echo "[sshd]"
        echo "enabled = true"
        echo "port = ${ports}"
        echo "backend = systemd"
    } >"$jail"
    ok "已写入 $jail（banaction=$ban, 白名单=${admin_ip:-无}）"
    # 先做配置语法检查，过了再重启；失败自动恢复旧文件
    if ! fail2ban-client -t >/dev/null 2>&1; then
        err "fail2ban 配置检查失败"
        fail2ban-client -t 2>&1 | tail -8
        if [[ -n "$bak" ]]; then cp -f "$bak" "$jail" 2>/dev/null; warn "已恢复旧配置: $bak"; fi
        return 1
    fi
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban >/dev/null 2>&1 || { err "fail2ban 启动失败"; systemctl status fail2ban --no-pager 2>&1 | tail -5; return 1; }
    sleep 1
    cs_f2b_status
}

cs_f2b_status() {
    if ! have fail2ban-client; then info "fail2ban 未安装"; return 0; fi
    hr
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        printf '  %bFail2ban%b: %b运行中%b\n' "$B" "$R" "$GRN" "$R"
    else
        printf '  %bFail2ban%b: %b未运行%b\n' "$B" "$R" "$RED" "$R"
    fi
    printf '  banaction: %s\n' "$(grep -hE '^banaction' /etc/fail2ban/jail.d/*.local /etc/fail2ban/jail.local 2>/dev/null | tail -1 | sed 's/.*= *//')"
    printf '  白名单  : %s\n' "$(grep -hE '^ignoreip' /etc/fail2ban/jail.d/*.local /etc/fail2ban/jail.local 2>/dev/null | tail -1 | sed 's/.*= *//')"
    local j
    for j in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do
        printf '  %b%s%b: %s\n' "$B" "$j" "$R" \
            "$(fail2ban-client status "$j" 2>/dev/null | sed -n 's/.*Currently banned:[[:space:]]*//p') 个封禁"
        fail2ban-client status "$j" 2>/dev/null | grep -E 'Banned IP list' | sed 's/^/    /'
    done
    hr
}

# 检查"当前登录 IP 是否被自己的 fail2ban 封了"—— 这是 SSH 失联的常见原因之一
cs_f2b_check() {
    have fail2ban-client || { info "fail2ban 未安装"; return 0; }
    local ip="" j bad=0
    [[ -n "${SSH_CLIENT:-}" ]] && ip="${SSH_CLIENT%% *}"
    [[ -z "$ip" && -n "${SSH_CONNECTION:-}" ]] && ip="${SSH_CONNECTION%% *}"
    for j in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do
        if fail2ban-client status "$j" 2>/dev/null | grep -E 'Banned IP list:' | grep -qF "$ip"; then
            warn "当前 IP $ip 被 jail $j 封禁 → 自动解封"
            fail2ban-client set "$j" unbanip "$ip" >/dev/null 2>&1 && bad=1
        fi
    done
    (( bad )) && ok "已解封当前 IP" || ok "当前 IP 未被封"
    return 0
}

cs_f2b_unban() { # <ip|all>
    have fail2ban-client || { err "fail2ban 未安装"; return 1; }
    if [[ "${1:-}" == "all" || -z "${1:-}" ]]; then
        fail2ban-client unban --all >/dev/null 2>&1
        ok "已解封全部 IP"
    else
        fail2ban-client unban "$1" >/dev/null 2>&1 && ok "已解封 $1" || err "解封失败: $1"
    fi
}

cs_f2b_whitelist() { # <ip>
    local ip="${1:-}" jail=/etc/fail2ban/jail.d/zzz-catSafety.local
    [[ "$ip" =~ ^[0-9a-fA-F:.]+$ ]] || { err "IP 格式不对"; return 1; }
    [[ -f "$jail" ]] || { err "先安装 fail2ban"; return 1; }
    if grep -q "ignoreip =.*\b${ip}\b" "$jail"; then info "$ip 已在白名单"; return 0; fi
    sed -i "s|^ignoreip = \(.*\)$|ignoreip = \1 ${ip}|" "$jail" 2>/dev/null || echo "ignoreip = ${ip}" >>"$jail"
    systemctl restart fail2ban >/dev/null 2>&1 || true
    ok "已加入白名单: $ip"
}

# ---------------------------- 列表 / 对账 ----------------------------
cs_ports_list() {
    hr
    printf '  %-10s %-5s %-7s %-28s %s\n' "OWNER" "PROTO" "PORT" "标签" "状态"
    if [[ -s "$CS_LEDGER" ]]; then
        while IFS=$'\t' read -r owner proto port tag ts; do
            [[ -n "$port" ]] || continue
            local st=""
            cs_rule_exists tcp "$port" && st+="规则✓ " || st+="规则✗ "
            ss -Hltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$" && st+="监听✓" || st+="监听✗"
            printf '  %-10s %-5s %-7s %-28s %s\n' "$owner" "$proto" "$port" "${tag:0:26}" "$st"
        done <"$CS_LEDGER"
    else
        echo "  （账本为空）"
    fi
    hr
}

cs_drift_check() {
    local drift=0 p be; be=$(cs_backend_get)
    echo "后端: $be  启用: $(cs_enabled_get)"
    # SSH
    while read -r p; do
        [[ -n "$p" ]] || continue
        cs_rule_exists tcp "$p" || { echo "DRIFT: SSH $p 未放行"; drift=1; }
    done < <(cs_ssh_ports)
    # 账本规则
    if [[ -s "$CS_LEDGER" ]]; then
        while IFS=$'\t' read -r owner proto port tag ts; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            cs_rule_exists tcp "$port" || { echo "DRIFT: $owner $proto/$port 账本有、规则无"; drift=1; }
        done <"$CS_LEDGER"
    fi
    # 监听但没账本（只报内核端口）
    local owner ports cur
    for owner in xray mihomo sing-box; do
        ports=$(cs_kernel_ports "$owner")
        for p in $ports; do
            cs_is_protected "$p" && continue
            if ! cs_ledger_has "$owner" both "$p" && ! cs_ledger_has "$owner" tcp "$p" && ! cs_ledger_has "$owner" udp "$p"; then
                echo "DRIFT: $owner 端口 $p 在监听/配置里，但账本没有"
                drift=1
            fi
        done
    done
    (( drift == 0 )) && echo "OK: 无漂移"
    return $drift
}

# ---------------------------- 状态 / 自检 ----------------------------
cs_age_str() { # <ts> → "12s 前"
    local ts="${1:-0}" now age
    now=$(date +%s)
    [[ "$ts" =~ ^[0-9]+$ ]] || { printf '未知'; return; }
    age=$((now - ts))
    (( age < 0 )) && age=0
    if (( age < 60 )); then printf '%ss 前' "$age"
    elif (( age < 3600 )); then printf '%smin 前' "$((age/60))"
    elif (( age < 86400 )); then printf '%sh 前' "$((age/3600))"
    else printf '%sd 前' "$((age/86400))"; fi
}

cs_guard_age() { cs_age_str "$(cat "$CS_ROOT/guard.last" 2>/dev/null || echo 0)"; }
cs_scan_age()  { cs_age_str "$(cat "$CS_LAST_SCAN_FILE" 2>/dev/null || echo 0)"; }

cs_f2b_summary() {
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        local j; j=$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ' ')
        printf '运行中%s' "${j:+ · $j}"
    else
        printf '未运行'
    fi
}

cs_unit_state() { # <unit> → active/inactive/未安装（单行）
    if systemctl list-unit-files 2>/dev/null | grep -q "^${1}"; then
        local st; st=$(systemctl is-active "$1" 2>/dev/null)
        printf '%s' "${st:-inactive}"
    else
        printf '未安装'
    fi
}

cs_status() {
    local be enabled active
    be=$(cs_backend_get); enabled=$(cs_enabled_get)
    hr
    printf '  %bcatSafety%b v%s\n' "$B" "$R" "$CS_VERSION"
    printf '  后端        : %s\n' "$be"
    printf '  启用状态    : %s\n' "$([[ "$enabled" == "1" ]] && echo 已启用 || echo 未启用)"
    printf '  实际生效    : %s\n' "$(cs_backend_active && echo 是 || echo 否)"
    printf '  SSH 端口    : %s\n' "$(cs_ssh_ports | paste -sd' ' -)"
    printf '  SSH 监听    : %s\n' "$(cs_ssh_listening && echo 是 || echo 否)"
    printf '  SSH 规则    : %s\n' "$(cs_ssh_verify && echo 完整 || echo "缺失:$(cs_ssh_rule_missing)")"
    printf '  guard 定时器: %s\n' "$(cs_unit_state catSafety-guard.timer)"
    printf '  fail2ban    : %s\n' "$(cs_unit_state fail2ban)"
    printf '  外部防火墙  : %s\n' "$(cs_foreign_list)"
    printf '  账本条目    : %s\n' "$([[ -f "$CS_LEDGER" ]] && wc -l <"$CS_LEDGER" || echo 0)"
    printf '  内核端口    : X=%s M=%s SB=%s\n' \
        "$(cs_kernel_ports xray | wc -w)" "$(cs_kernel_ports mihomo | wc -w)" "$(cs_kernel_ports sing-box | wc -w)"
    hr
}

cs_selfcheck() {
    local fail=0
    echo "== catSafety 自检"
    bash -n "${BASH_SOURCE[0]:-$0}" && echo "  OK bash 语法" || { echo "  FAIL 语法"; fail=1; }
    local p; p=$(cs_ssh_ports)
    [[ -n "$p" ]] && echo "  OK SSH 端口: $(echo "$p" | paste -sd' ' -)" || { echo "  FAIL 检测不到 SSH 端口"; fail=1; }
    if [[ "$(cs_enabled_get)" == "1" ]]; then
        cs_ssh_verify && echo "  OK 所有 SSH 端口已放行" || { echo "  FAIL SSH 规则缺失"; fail=1; }
        cs_backend_active && echo "  OK 后端生效" || { echo "  FAIL 后端未生效"; fail=1; }
    fi
    [[ -f "$CS_LEDGER" ]] && echo "  OK 账本 $(wc -l <"$CS_LEDGER") 条" || echo "  -- 账本为空"
    echo "== 结果: $([[ $fail -eq 0 ]] && echo PASS || echo FAIL)"
    return $fail
}

# ---------------------------- 菜单 ----------------------------
cs_menu_header() {
    clear 2>/dev/null || true
    printf '%b\n' "$CYN"
    cat <<'EOF'
      /\_/\
     ( o.o )   catSafety
      > ^ <    防火墙 / 安全工具
EOF
    printf '%b' "$R"
    local be guard_state ssh_ports f2b auto_state
    be=$(cs_backend_get)
    ssh_ports=$(cs_ssh_ports | paste -sd, -)
    if systemctl is-active --quiet catSafety-guard.timer 2>/dev/null; then
        guard_state="${GRN}● 守护中${R}（${DIM}$(cs_guard_age)检查${R}）"
    else
        guard_state="${YEL}○ 未运行${R}"
    fi
    if [[ "$(cs_enabled_get)" == "1" ]]; then
        fw_state="${GRN}已启用${R}"
    else
        fw_state="${YEL}未启用${R}"
    fi
    auto_state=$([[ "$(cs_autoscan_on)" == "0" ]] && echo "${YEL}关${R}" || echo "${GRN}开${R}")
    printf '  ┌────────────────────────────────────────────────────────┐\n'
    printf '  │ 🛡  SSH 守护   %b  端口 %b%s%b\n' "$guard_state" "$B" "$ssh_ports" "$R"
    printf '  │ 🔥  防火墙     %b %b· 账本 %s 条%b\n' "$B$be$R" "$fw_state" "$([[ -f "$CS_LEDGER" ]] && wc -l <"$CS_LEDGER" || echo 0)" "$R"
    printf '  │ 👀  自动开放   %b  %b· 最近扫描 %s%b\n' "$auto_state" "$DIM" "$(cs_scan_age)" "$R"
    printf '  │ 🚫  Fail2ban   %b%s%b\n' "$B" "$(cs_f2b_summary)" "$R"
    printf '  └────────────────────────────────────────────────────────┘\n'
}


cs_menu_ufw() {
    while true; do
        cs_menu_header
        hr
        printf '  %bUFW%b  安装:%s  运行:%s\n' "$B" "$R" \
            "$(have ufw && echo 是 || echo 否)" \
            "$(have ufw && (ufw status 2>/dev/null | head -1) || echo -)"
        hr
        printf '  1) 安装 UFW\n  2) 启用 UFW（安全模式，带回滚）\n  3) 停用 UFW\n  4) 查看状态\n  5) 设为本工具后端\n  0) 返回\n'
        printf '  请选择 [0-5]: '; read -r c || return 0
        case "$c" in
            1) cs_pkg_install ufw && ok "UFW 已安装" || err "安装失败"; pause_ ;;
            2) cs_backend_set ufw; cs_enable; pause_ ;;
            3) ufw disable >/dev/null 2>&1; cs_enabled_set 0; ok "UFW 已停用"; pause_ ;;
            4) ufw status verbose 2>/dev/null | sed 's/^/  /'; pause_ ;;
            5) cs_backend_set ufw; ok "后端已设为 ufw"; pause_ ;;
            0) return 0 ;;
            *) err "无效选项"; pause_ ;;
        esac
    done
}

cs_menu_nft() {
    while true; do
        cs_menu_header
        hr
        printf '  %bnftables%b  安装:%s  本工具表:%s\n' "$B" "$R" \
            "$(have nft && echo 是 || echo 否)" \
            "$(nft list table inet "$CS_NFT_TABLE" >/dev/null 2>&1 && echo 存在 || echo 无)"
        hr
        printf '  1) 安装 nftables\n  2) 启用 nftables（自有表 + 默认拒绝）\n  3) 停用（删除自有表）\n  4) 查看规则\n  5) 设为本工具后端\n  0) 返回\n'
        printf '  请选择 [0-5]: '; read -r c || return 0
        case "$c" in
            1) cs_pkg_install nftables && ok "nftables 已安装" || err "安装失败"; pause_ ;;
            2) cs_backend_set nft; cs_enable; pause_ ;;
            3) cs_nft_delete; cs_enabled_set 0; ok "自有表已删除"; pause_ ;;
            4) nft list table inet "$CS_NFT_TABLE" 2>/dev/null | sed 's/^/  /' || info "表不存在"; pause_ ;;
            5) cs_backend_set nft; ok "后端已设为 nft"; pause_ ;;
            0) return 0 ;;
            *) err "无效选项"; pause_ ;;
        esac
    done
}

cs_menu_f2b() {
    while true; do
        cs_menu_header
        cs_f2b_status
        printf '  1) 安装 / 重配 Fail2ban\n  2) 解封全部\n  3) 解封单个 IP\n  4) 加白名单\n  5) 重启\n  6) 检查当前 IP 是否被封\n  0) 返回\n'
        printf '  请选择 [0-6]: '; read -r c || return 0
        case "$c" in
            1) cs_f2b_install; pause_ ;;
            2) cs_f2b_unban all; pause_ ;;
            3) printf '  IP: '; read -r ip; cs_f2b_unban "$ip"; pause_ ;;
            4) printf '  IP: '; read -r ip; cs_f2b_whitelist "$ip"; pause_ ;;
            5) systemctl restart fail2ban >/dev/null 2>&1 && ok "已重启" || err "重启失败"; pause_ ;;
            6) cs_f2b_check; pause_ ;;
            0) return 0 ;;
            *) err "无效选项"; pause_ ;;
        esac
    done
}

cs_menu_ssh() {
    while true; do
        cs_menu_header
        cs_ssh_status
        printf '  1) 立即补齐 SSH 放行\n  2) 安装/启动守护（每分钟自检）\n  3) 停止守护\n  4) PANIC 紧急放行\n  0) 返回\n'
        printf '  请选择 [0-4]: '; read -r c || return 0
        case "$c" in
            1) cs_ssh_protect; pause_ ;;
            2) cs_install_guard; pause_ ;;
            3) systemctl disable --now catSafety-guard.timer >/dev/null 2>&1; ok "守护已停止"; pause_ ;;
            4) confirm_ "确认 PANIC（会停用防火墙）? (y/N)" && cs_panic; pause_ ;;
            0) return 0 ;;
            *) err "无效选项"; pause_ ;;
        esac
    done
}

cs_menu_ports() {
    while true; do
        cs_menu_header
        cs_ports_list
        printf '  1) 放行端口\n  2) 关闭端口\n  3) 三内核同步\n  4) 漂移检查\n  5) 自动对账（按监听开关）\n  0) 返回\n'
        printf '  请选择 [0-5]: '; read -r c || return 0
        case "$c" in
            1)
                printf '  owner (xray/mihomo/sing-box/share/自定义): '; read -r o
                printf '  端口[/proto] (如 12345 或 12345/udp): '; read -r sp
                local pp; pp=$(cs_norm_port "$sp") || { err "端口格式不对"; pause_; continue; }
                cs_open "${o:-custom}" "${pp#* }" "${pp%% *}" "manual" && ok "已放行 $sp" || err "放行失败"
                pause_ ;;
            2)
                printf '  owner: '; read -r o
                printf '  端口[/proto]: '; read -r sp
                local pp; pp=$(cs_norm_port "$sp") || { err "端口格式不对"; pause_; continue; }
                cs_close "${o:-custom}" "${pp#* }" "${pp%% *}" && ok "已关闭 $sp" || err "关闭失败"
                pause_ ;;
            3) cs_kernel_sync; pause_ ;;
            4) cs_drift_check; pause_ ;;
            5) cs_autosync; pause_ ;;
            0) return 0 ;;
            *) err "无效选项"; pause_ ;;
        esac
    done
}

cs_menu_backup() {
    while true; do
        cs_menu_header
        local last; last=$(ls -1 "$CS_BACKUP" 2>/dev/null | tail -1)
        printf '  备份目录: %s\n  最近备份: %s\n' "$CS_BACKUP" "${last:-无}"
        printf '  1) 立即备份\n  2) 从备份恢复\n  3) 查看备份列表\n  0) 返回\n'
        printf '  请选择 [0-3]: '; read -r c || return 0
        case "$c" in
            1) d=$(cs_backup) && ok "已备份到 $d"; pause_ ;;
            2) printf '  备份目录名: '; read -r d; cs_restore "$CS_BACKUP/$d"; pause_ ;;
            3) ls -1 "$CS_BACKUP" 2>/dev/null | sed 's/^/  /'; pause_ ;;
            0) return 0 ;;
            *) err "无效选项"; pause_ ;;
        esac
    done
}

cs_restore() { # <dir>
    local dir="${1:-}"
    [[ -d "$dir" ]] || { err "备份目录不存在: $dir"; return 1; }
    confirm_ "恢复会覆盖当前防火墙配置，确认? (y/N)" || return 0
    if [[ -f "$dir/etc-fw.tar.gz" ]]; then
        tar -xzf "$dir/etc-fw.tar.gz" -C / 2>/dev/null || warn "解包部分失败"
    fi
    [[ -f "$dir/ledger.tsv" ]] && cp -f "$dir/ledger.tsv" "$CS_LEDGER" 2>/dev/null || true
    if [[ -f "$dir/iptables.v4" ]] && have iptables-restore; then
        iptables-restore <"$dir/iptables.v4" 2>/dev/null || true
    fi
    if [[ -f "$dir/ip6tables.v6" ]] && have ip6tables-restore; then
        ip6tables-restore <"$dir/ip6tables.v6" 2>/dev/null || true
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
    ok "恢复完成（必要时手动重启 ufw/nftables/fail2ban）"
}

main_menu() {
    while true; do
        cs_menu_header
        printf '  ┌──────────────────── 功能 ─────────────────────┐\n'
        printf '  │ %b1%b) UFW        安装 / 启用 / 停用 / 状态   │\n' "$B" "$R"
        printf '  │ %b2%b) nftables   安装 / 启用 / 停用 / 规则   │\n' "$B" "$R"
        printf '  │ %b3%b) Fail2ban   安装 / 状态 / 解封 / 白名单 │\n' "$B" "$R"
        printf '  │ %b4%b) 一键接管   导入规则 + 三内核 + 停第三方│\n' "$B" "$R"
        printf '  │ %b5%b) SSH 保护   状态 / 自动抢救 / PANIC    │\n' "$B" "$R"
        printf '  │ %b6%b) 端口管理   列表 / 放行 / 关闭 / 对账  │\n' "$B" "$R"
        printf '  │ %b7%b) 三内核同步 立即扫描并放行当前端口      │\n' "$B" "$R"
        printf '  │ %b8%b) 自动开放   监听端口自动开关 [%b%s%b]     │\n' "$B" "$R" "$([[ "$(cs_autoscan_on)" == "0" ]] && echo "$RED关$R" || echo "$GRN开$R")" "$R"
        printf '  │ %b9%b) 备份/恢复 / 自检                       │\n' "$B" "$R"
        printf '  │ %b0%b) 返回                                   │\n' "$B" "$R"
        printf '  └───────────────────────────────────────────────┘\n'
        printf '  请选择 [0-9]: '
        read -r c || return 0
        case "$c" in
            1) cs_menu_ufw ;;
            2) cs_menu_nft ;;
            3) cs_menu_f2b ;;
            4) cs_takeover; pause_ ;;
            5) cs_menu_ssh ;;
            6) cs_menu_ports ;;
            7) cs_kernel_sync; pause_ ;;
            8)
                if [[ "$(cs_autoscan_on)" == "0" ]]; then
                    cs_autoscan_set 1; ok "自动开放已开启"
                else
                    cs_autoscan_set 0; warn "自动开放已关闭（账本保留，不再自动开关端口）"
                fi
                pause_ ;;
            9) cs_menu_backup ;;
            0) return 0 ;;
            *) err "无效选项"; sleep 1 ;;
        esac
    done
}

# ---------------------------- CLI ----------------------------
cs_usage() {
    cat <<EOF
catSafety v${CS_VERSION} — 防火墙 / 安全工具

用法:
  catSafety menu                          交互菜单
  catSafety status                        总览
  catSafety takeover [--dry-run] [--yes]  接管第三方防火墙 + 导入三内核端口
  catSafety sync [--prune] [--dry-run]    同步三内核端口
  catSafety guard                         执行一次 SSH 守护（供 timer 调用）
  catSafety ssh {status|protect}          SSH 检查/放行
  catSafety backend {ufw|nft|iptables|status}
  catSafety enable | disable | panic      启用/停用/紧急放行
  catSafety open <owner> <port[/proto]>
  catSafety close <owner> <port[/proto]>
  catSafety list                          账本列表
  catSafety check                         漂移检查
  catSafety autosync                      立即按监听状态对账（开/关端口）
  catSafety autoscan [on|off|status]      自动开放开关
  catSafety owner-set <owner> <tcp:8080|udp:51820|8080>...   声明式端口清单
  catSafety owner-clear <owner>           删除清单并回收端口
  catSafety reconcile                     立即按清单对账
  catSafety switch <ufw|nft|iptables>     切换后端（账本保留）
  catSafety json                          状态 JSON（给其它项目/面板）
  catSafety enabled                       是否已启用（退出码）
  catSafety f2b {install|status|check|unban <ip|all>|whitelist <ip>}
  catSafety backup | restore <dir>
  catSafety install-guard | install-restore
  catSafety selfcheck
EOF
}

cs_cli() {
    local cmd="${1:-menu}"
    case "$cmd" in
        menu) main_menu ;;
        status) cs_status ;;
        takeover) shift; cs_takeover "$@" ;;
        sync) shift; cs_kernel_sync "$@" ;;
        import-listening) cs_import_listening ;;
        autosync)
            local _i _rc
            for _i in 1 2 3 4 5 6 7 8 9 10; do
                cs_autosync; _rc=$?
                [[ $_rc -ne 3 ]] && break
                sleep 1
            done
            [[ ${_rc:-0} -eq 3 ]] && warn "对账忙（guard 正在执行），稍后再试" ;;
        reconcile) cs_owners_sync ;;
        switch) shift; cs_switch "${1:?backend: ufw|nft|iptables|firewalld}" ;;
        json|status-json) cs_status_json ;;
        owner-set) shift; cs_owner_set "$@" ;;
        owner-clear) shift; cs_owner_clear "${1:?owner}" ;;
        owners) ls -1 "$CS_OWNERS_DIR"/*.ports 2>/dev/null | xargs -r -n1 basename | sed 's/\.ports$//' ;;

        port)
            shift
            case "${1:-list}" in
                open)
                    shift
                    local _o="${1:?owner}" _sp="${2:?port}" _pp
                    _pp=$(cs_norm_port "$_sp") || die "端口格式不对"
                    cs_open "$_o" "${_pp#* }" "${_pp%% *}" "api" || die "放行失败" ;;
                close)
                    shift
                    local _o="${1:?owner}" _sp="${2:?port}" _pp
                    _pp=$(cs_norm_port "$_sp") || die "端口格式不对"
                    cs_close "$_o" "${_pp#* }" "${_pp%% *}" || die "关闭失败" ;;
                list)  cs_ports_list ;;
                *)     cs_usage ;;
            esac ;;
        autoscan)
            shift
            case "${1:-status}" in
                on)  cs_autoscan_set 1; ok "自动开放已开启" ;;
                off) cs_autoscan_set 0; warn "自动开放已关闭" ;;
                status|"") [[ "$(cs_autoscan_on)" == "0" ]] && echo 关 || echo 开 ;;
                *) echo "用法: catSafety autoscan [on|off|status]" ;;
            esac ;;
        prune-legacy) cs_ledger_prune_legacy ;;
        guard) cs_guard ;;
        apply) cs_apply ;;
        ssh)
            shift
            case "${1:-status}" in
                status) cs_ssh_status ;;
                protect) cs_ssh_protect ;;
                *) cs_ssh_status ;;
            esac ;;
        backend)
            shift
            case "${1:-status}" in
                ufw|nft|iptables|firewalld) cs_backend_set "$1" && ok "后端 -> $1" ;;
                status|"") echo "$(cs_backend_get)" ;;
                *) err "未知后端"; return 1 ;;
            esac ;;
        enabled) [[ "$(cs_enabled_get)" == "1" ]] ;;
        enable) cs_enable ;;
        disable) cs_disable ;;
        panic) cs_panic ;;
        open)
            shift
            local owner="${1:?owner}" sp="${2:?port}" pp
            pp=$(cs_norm_port "$sp") || die "端口格式不对"
            cs_open "$owner" "${pp#* }" "${pp%% *}" "cli" || die "放行失败" ;;
        close)
            shift
            local owner="${1:?owner}" sp="${2:?port}" pp
            pp=$(cs_norm_port "$sp") || die "端口格式不对"
            cs_close "$owner" "${pp#* }" "${pp%% *}" || die "关闭失败" ;;
        list) cs_ports_list ;;
        check) cs_drift_check ;;
        f2b)
            shift
            case "${1:-status}" in
                install) cs_f2b_install ;;
                status) cs_f2b_status ;;
                unban) shift; cs_f2b_unban "${1:-all}" ;;
                whitelist) shift; cs_f2b_whitelist "${1:?ip}" ;;
                check) cs_f2b_check ;;
                *) cs_f2b_status ;;
            esac ;;
        backup) cs_backup ;;
        restore) shift; cs_restore "${1:?dir}" ;;
        install-guard) cs_install_guard ;;
        install-restore) cs_install_restore_unit ;;
        selfcheck) cs_selfcheck ;;
        version|-v|--version) echo "catSafety $CS_VERSION" ;;
        help|-h|--help) cs_usage ;;
        *) cs_usage; return 1 ;;
    esac
}

cs_root_check
cs_ledger_init
if [[ "${BASH_SOURCE[0]:-}" == "${0}" ]]; then
    cs_cli "$@"
fi
