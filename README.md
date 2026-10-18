# catSafety

防火墙 / 安全工具（UFW / nftables / Fail2ban）—— 为 Xray / Mihomo / Sing-box 三内核设计。

## 设计目标（按优先级）

1. **SSH 永不被自己的规则封死**
   - 启用任何策略前先放行 SSH，并校验规则真的进了后端；
   - 启用时挂 **180 秒 deadman**：超时没确认/校验失败自动回滚；
   - 开机守护 `catSafety-guard.timer`（每分钟）：
     - SSH 规则丢了自动补；
     - 账本里任何端口规则丢了按账本重放；
     - 发现第三方 iptables 针对 SSH 的 DROP/REJECT，在最前面插救急 ACCEPT；
     - sshd 没在监听会尝试拉起（仅主机命名空间）。
2. **接管第三方防火墙**
   - 一键导入现有 ACCEPT 规则、当前所有监听端口、三内核端口；
   - 停用第三方防火墙服务（nftables/`nftables-ufw-panel`/`sb-panel-nft`/firewalld），
     移除 `@reboot iptables-restore`（先备份 crontab）；
   - nft 模式下移除外来 `inet filter` 表（备份里可恢复）；
   - 全程备份：iptables/ip6tables/nft/ufw/crontab//etc 防火墙配置。
3. **与三个内核共用一套账本**
   - 自动扫描：Xray `conf/*.json`、Mihomo `conf/config.d/*.yaml`、Sing-box `config/*.json`；
   - 账本 `/etc/catSafety/ledger.tsv`（owner/proto/port/tag/时间）；
   - 不再相信三家历史的 `.fw-ports`（实测会漂移），配置里有才算。
4. **可归属、可回滚**
   - 规则统一带 `catSafety-<owner>`；
   - 只关账本里 owner 匹配的端口；SSH / 80 / 443 / 8443 永不自动关；
   - 备份/恢复/漂移检查/自检。

## 快速开始

```bash
bash install.sh
catSafety status          # 总览
catSafety ssh status      # 只读：SSH 端口与放行状态
catSafety sync --dry-run  # 预演：三内核端口
catSafety takeover --dry-run
catSafety takeover        # 备份 → 导入 → 停第三方 → 启用（带 deadman）
```

失联时（服务商控制台/救援模式）：

```bash
catSafety panic
```

## 菜单

```
防火墙 / 安全工具
  1) UFW          安装 / 启用 / 停用 / 状态
  2) nftables     安装 / 启用 / 停用 / 规则
  3) Fail2ban     安装 / 状态 / 解封 / 白名单
  4) 一键接管
  5) SSH 保护     状态 / 自动抢救 / 守护 / PANIC
  6) 端口管理     列表 / 放行 / 关闭 / 漂移检查
  7) 三内核同步
  8) 备份 / 恢复
  9) 自检
```

## 后端行为

| 后端 | 规则位置 | 默认策略 | 持久化 |
|---|---|---|---|
| UFW | ufw 规则（带 comment） | deny incoming | ufw 自身持久 |
| nftables | 独立 `table inet catSafety`，priority -10 | policy drop | 自有 `catSafety-restore.service` 开机从账本重建 |
| iptables | INPUT 规则（带 comment） | POLICY DROP | restore 服务重建 + ip6tables |
| firewalld | `--add-port`（无 comment） | 依赖 firewalld | firewalld 自身 |

## 账本

`/etc/catSafety/ledger.tsv`：

```
owner    proto    port    tag    created_at
xray     both     18300   kernel 1792...
mihomo   both     20523   kernel 1792...
share    both     9443    share-service ...
legacy   both     18090   imported-listening ...
```

## 验证记录（2026-10-18，RN 生产机）

- nft 模式：policy drop；SSH/443/内核端口/9443 从外部可达，未登记端口 timeout；
- 删除 M 端口规则后 60 秒内 guard 自动恢复；
- **删除 SSH 规则 → 外部立即不可达 → 约 60 秒内自动恢复**；
- UFW 模式：`ufw status` 200+ 条 ALLOW，外部可达性同上；同样验证 `ufw delete allow SSH` 后自动恢复；
- `catSafety check` 无漂移；站点 200；三内核服务均正常。

## 安全边界

- 不做 `nft flush ruleset` / `iptables -F` / `ufw reset` / `rm -rf /etc/ufw`；
- 接管是显式动作（二次确认 + 备份 + deadman）；日常 open/close 只动账本里自己的端口；
- fail2ban 配置写入 `/etc/fail2ban/jail.d/zzz-catSafety.local`（最后加载），
  会把当前登录的管理 IP 自动加入 `ignoreip`；安装前请确认不会覆盖你的自定义 jail。

## 文件

- `catSafety.sh` 单文件主程序
- `install.sh` 安装/卸载/状态
- `tools/check.sh` 自检（语法/红线/账本/端口扫描/菜单入口）
