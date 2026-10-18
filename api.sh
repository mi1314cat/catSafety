#!/bin/bash
# =============================================================
# catSafety 联动 API（给其它项目 source 用）
#
#   source /opt/catSafety/api.sh
#   catsafety_open  <owner> <port[/proto]>
#   catsafety_close <owner> <port[/proto]>
#   catsafety_set_ports <owner> <tcp:8080|udp:51820|8080>...
#   catsafety_clear_ports <owner>
#   catsafety_status_json
#   catsafety_enabled && echo on
#
# 说明:
#   · 调用方**不需要知道**当前是 UFW 还是 nftables；
#   · 端口所有权按 owner 记账，SSH/80/443/分享端口受保护；
#   · set_ports 是声明式：写清单后由 catSafety 每分钟对账，
#     项目启动/停止只要更新清单即可。
# =============================================================

CS_API_BIN="${CS_API_BIN:-catSafety}"

catsafety_enabled() { "$CS_API_BIN" enabled >/dev/null 2>&1; }
catsafety_open()    { "$CS_API_BIN" port open  "$@"; }
catsafety_close()   { "$CS_API_BIN" port close "$@"; }
catsafety_set_ports()   { "$CS_API_BIN" owner-set "$@"; }
catsafety_clear_ports() { "$CS_API_BIN" owner-clear "$@"; }
catsafety_status_json() { "$CS_API_BIN" json; }
catsafety_reconcile()   { "$CS_API_BIN" reconcile; }

# 示例: 声明 myapp 需要 8080/tcp 与 5000/udp
#   catsafety_set_ports myapp tcp:8080 udp:5000
