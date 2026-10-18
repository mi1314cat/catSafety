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

## 内核项目零改动

不修改 Xray / Mihomo / Sing-box 的任何代码也能兼容：

- **监听对账**：内核把端口 listen 起来后，catSafety 自动补放行；监听关掉、宽限后回收；
- **残留规则清扫**：UFW 后端下，内核留下的 `MIHOMO-Panel` / `SB-Panel` iptables 规则
  如果对应端口已不监听、也不在内核配置里，会被自动删除（只删带明确注释的规则）；
- 代价是回收不是"删除节点那一刻"，而是"监听消失 + 宽限期"（默认 15 分钟，可调）。

如果愿意改一行代码，也可以走 `source /opt/catSafety/api.sh` 的即时接口。

## 内核兼容（旧说明，已不要求改内核）

- **Mihomo**：`src/lib/fw.sh` 的 `fw_open_port/fw_close_port` 在检测到 catSafety 已启用时，
  改为调用 `catSafety open/close mihomo`，不再自己写 iptables；
- **Sing-box**：`conf/lib.sh` 的 `open_port/close_node_port`（以及 `install.sh` 的分享端口）
  同样优先调用 catSafety；自己的 `.fw-ports` 仍保留用于面板展示；
- **Xray**：本身没有放行代码，由 catSafety 的自动监听对账覆盖；
- 没有安装 catSafety 时，三者保持原来的行为（零依赖回退）。

## 给其它项目的联动（不依赖 UFW / nftables）

其他项目只需要认 catSafety 一个接口，**不用关心当前后端是什么**：

### 方式 A：声明式清单（推荐，零代码改动）

```bash
catSafety owner-set myapp tcp:8080 udp:51820
# 或直接写文件 /etc/catSafety/owners/myapp.ports:
#   tcp 8080
#   udp 51820
#   both 443
```

- catSafety 每分钟按清单放行；清单删掉端口 → 自动回收；
- 切换后端（UFW ↔ nftables）时账本保留，自动重放。

### 方式 B：source API

```bash
source /opt/catSafety/api.sh
catsafety_open  myapp 8080/tcp
catsafety_close myapp 8080/tcp
catsafety_set_ports myapp tcp:8080 udp:51820
catsafety_status_json
```

### 方式 C：直接 CLI

```bash
catSafety port open  <owner> <port[/proto]>
catSafety port close <owner> <port[/proto]>
catSafety json
catSafety switch nft     # 或 ufw；账本/端口自动迁移
```

### 后端切换与 hooks

- `catSafety switch ufw|nft|iptables`：停旧后端 → 设新后端 → 按账本重放；失败自动回退；
- 切换前后会执行（存在且可执行）：
  - `/etc/catSafety/hooks/pre-switch <old> <new>`
  - `/etc/catSafety/hooks/post-switch <old> <new>`

## 界面

- 启动有绿色加载条；顶部是猫咪横幅 + 渐变色标题（对齐 Catmiup 面板风格）；
- 「运行状态」卡片：SSH 守护 / 防火墙 / 自动开放 / Fail2ban，状态用绿/黄/红显示；
- 「功能菜单」卡片：编号、名称、说明三列按中文宽度对齐；
- 所有子菜单统一「状态 + 操作」两段，危险项标红。

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
- `catSafety check` 无漂移；站点 200；三内核服务均正常；
- 自动开放：起一个临时监听 → `autosync` 自动放行（外部可达）；停监听 → 宽限期后自动回收（外部不可达）；
- 内核委托：M 的 `fw_open_port`、SB 的 `open_port` 实测写入 catSafety 账本并由它放行/关闭；
- Fail2ban：`catSafety f2b check` 会检查当前登录 IP 是否被自己的 jail 封禁并自动解封。

## 安全边界

- 不做 `nft flush ruleset` / `iptables -F` / `ufw reset` / `rm -rf /etc/ufw`；
- 接管是显式动作（二次确认 + 备份 + deadman）；日常 open/close 只动账本里自己的端口；
- fail2ban 配置写入 `/etc/fail2ban/jail.d/zzz-catSafety.local`（最后加载），
  会把当前登录的管理 IP 自动加入 `ignoreip`；安装前请确认不会覆盖你的自定义 jail。

## 文件

- `catSafety.sh` 单文件主程序
- `install.sh` 安装/卸载/状态
- `tools/check.sh` 自检（语法/红线/账本/端口扫描/菜单入口）
