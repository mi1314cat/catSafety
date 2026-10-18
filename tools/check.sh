#!/bin/bash
# catSafety 自检（不碰真实防火墙）
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad(){ FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$*"; }
t(){ local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

echo "== 语法"
for f in "$ROOT/catSafety.sh" "$ROOT/install.sh"; do
    bash -n "$f" && ok "bash -n $(basename "$f")" || bad "bash -n $(basename "$f")"
done

echo "== 安全红线（禁止破坏性操作）"
for pat in 'flush ruleset' 'iptables -F' 'ufw --force reset' 'rm -rf /etc/ufw'; do
    if grep -qF -- "$pat" "$ROOT/catSafety.sh"; then bad "出现危险操作: $pat"; else ok "无危险操作: $pat"; fi
done
grep -q 'cs_deadman_start' "$ROOT/catSafety.sh" && ok "启用路径带 deadman" || bad "缺少 deadman"
grep -q 'cs_ssh_ports' "$ROOT/catSafety.sh" && ok "SSH 端口检测存在" || bad "缺少 SSH 检测"

echo "== 纯函数/账本（临时目录）"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/x" "$TMP/m" "$TMP/sb"
cat >"$TMP/x/a.json" <<'J'
{"inbounds":[{"port":12345,"listen":"0.0.0.0"},{"port":23456,"listen":"127.0.0.1"}]}
J
cat >"$TMP/m/a.yaml" <<'Y'
listeners:
  - name: in
    type: mixed
    port: 34567
    listen: 0.0.0.0
Y
cat >"$TMP/sb/a.json" <<'J'
{"inbounds":[{"type":"vless","listen_port":45678}]}
J

export CS_ROOT="$TMP/root" CS_LEDGER="$TMP/root/ledger.tsv" CS_LOG="$TMP/root/log" CS_STATE="$TMP/root/backend"
export CS_X_DIR="$TMP/x" CS_M_DIR="$TMP/m" CS_SB_DIR="$TMP/sb"
export CS_X_LEDGER="$TMP/none1" CS_M_LEDGER="$TMP/none2" CS_SB_LEDGER="$TMP/none3"
# shellcheck disable=SC1090
source "$ROOT/catSafety.sh"

# catSafety 里也有 ok/bad（打印用），会覆盖测试计数器 —— 这里恢复
ok(){ PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad(){ FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$*"; }

r=$(cs_norm_port "8080/udp"); [[ "$r" == "8080 udp" ]] && ok "端口解析 8080/udp" || bad "端口解析: $r"
r=$(cs_norm_port "70000"); [[ -z "$r" ]] && ok "非法端口被拒" || bad "非法端口未拒: $r"

cs_ledger_add xray both 12345 tag1
cs_ledger_has xray both 12345 && ok "账本 add/has" || bad "账本 add/has"
cs_ledger_del xray both 12345
cs_ledger_has xray both 12345 && bad "账本 del 失败" || ok "账本 del"

[[ "$(cs_ssh_ports | head -1)" =~ ^[0-9]+$ ]] && ok "SSH 端口检测有输出" || bad "SSH 端口检测为空"
[[ "$(cs_kernel_ports xray)" == "12345" ]] && ok "Xray 端口扫描（跳过 loopback）" || bad "Xray 扫描: $(cs_kernel_ports xray)"
[[ "$(cs_kernel_ports mihomo)" == "34567" ]] && ok "Mihomo 端口扫描" || bad "Mihomo 扫描: $(cs_kernel_ports mihomo)"
[[ "$(cs_kernel_ports sing-box)" == "45678" ]] && ok "Sing-box 端口扫描" || bad "Sing-box 扫描: $(cs_kernel_ports sing-box)"

echo "== 联动接口"
mkdir -p "$CS_OWNERS_DIR"
printf 'tcp 12345\nudp 51820\n' >"$CS_OWNERS_DIR/demo.ports"
cs_owner_manifest_has demo 12345 && ok "owner 清单解析 tcp" || bad "owner 清单解析 tcp"
cs_owner_manifest_has demo 51820 && ok "owner 清单解析 udp" || bad "owner 清单解析 udp"
cs_owner_manifest_has demo 65000 && bad "owner 清单误报" || ok "owner 清单不误报"
echo '{"a":1}' >/dev/null
json_out=$(cs_status_json 2>/dev/null)
printf '%s' "$json_out" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null && ok "status JSON 合法" || bad "status JSON 不合法: $json_out"

echo "== 菜单/CLI 入口"
for fn in main_menu cs_menu_ufw cs_menu_nft cs_menu_f2b cs_menu_ssh cs_menu_ports cs_takeover cs_guard cs_enable cs_disable cs_panic cs_autosync cs_autoscan_on cs_listen_has cs_f2b_check cs_owners_sync cs_owner_set cs_owner_clear cs_switch cs_status_json cs_purge_kernel_rules cs_sweep_stale_kernel_rules; do
    declare -F "$fn" >/dev/null && ok "存在 $fn" || bad "缺少 $fn"
done

echo
echo "结果: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
