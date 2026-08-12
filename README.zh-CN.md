# Context Guard

[![CI](https://github.com/GreenLv/codex-context-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/GreenLv/codex-context-guard/actions/workflows/ci.yml)
[![HOL Plugin Scanner](https://github.com/GreenLv/codex-context-guard/actions/workflows/hol-plugin-scanner.yml/badge.svg)](https://github.com/GreenLv/codex-context-guard/actions/workflows/hol-plugin-scanner.yml)
[![Release](https://img.shields.io/github/v/release/GreenLv/codex-context-guard)](https://github.com/GreenLv/codex-context-guard/releases)
[![License](https://img.shields.io/github/license/GreenLv/codex-context-guard)](LICENSE)

[English](README.md)

Context Guard 是面向 Codex 长任务的本地正确性旁路（correctness sidecar）。它把
权威需求、验收标准、后续修订、有限的原生计划状态、委托 Agent 来源和验证证据保存
在私有本地账本中，避免上下文压缩后任务契约被静默遗忘。

它**不替代** Codex 的 compaction、Plan/Goal mode、memories、subagents、
worktrees 或 transcript。上述能力仍由 Codex 原生系统负责；Context Guard 只在旁边
补充有界恢复与完成证据门禁。

> 发布状态：`0.6.1` 是最近一次已发布版本；`0.6.3` 是已合并、已完成原生验收但尚未打 tag 的当前源码线。
> Stop protocol 1.1.0 将兼容保留的 `continue` 降为仅诊断提示，在终态控制
> 不一致时保留 pending 并安全让出，同时使用引号感知的 shell 意图解析。`0.6.3`
> 还会在归档旧 live cache 前先按可信索引修复漂移，并且仅当受信产品 manifest
> 前后不变时移除历史仓库元数据。已经安装过的 `0.6.2` 包保持不可变；该版本从未
> 打 tag 或发布，但在这些 manager 生命周期修复前已经被消耗。`0.6.0`
> 候选引入了 state schema 5、
> Stop protocol 1.0.0 和 diagnostic classifier 2.0.0，但在正常信任 Hook 的
> fresh Codex Code Mode 任务中暴露了 raw-stdout staging 失败，因此未创建 tag
> 或 Release；其已安装 cache 不可变，版本号已经消耗。`0.6.1` 只修改成功的
> 私有 stage receipt，schema、protocol、classifier 和八 Hook wire 均不变。
> 0.6.3 已通过限定的 macOS source/install/archive 门；private/public
> identity 均在正常 Hook 信任、无 trust bypass 下通过 `user_wait`、completion
> checkpoint 和手动 schema-5 `/compact` 恢复。Windows 0.6.3 原生验收也已完成；代码已合并到 main，tag 与 GitHub Release 仍是独立的发布动作。精确公开提交和 tag 的自动化门禁单独验证；CI 不替代
> 任何一次原生验收。

### 30 秒脱敏 compact/recovery 演示

```text
1. 为一个只有两项要求的合成任务启用 Context Guard。
2. 正常执行工作，然后运行 /compact。
3. 恢复后的任务收到同一份有界要求清单。
4. 两项要求都有成功证据前，任务仍不能宣称完成。
```

该演示不包含任何真实提示、路径、任务状态或插件数据。

## 为什么需要它？

长任务经过上下文压缩后，可能仍然“记得做过哪些工作”，却丢失真正决定正确性的
细节：最初的禁止事项、后来修正的要求、必须满足的验收标准，或者“某个局部测试
通过并不代表整个任务已经完成”。普通摘要很有用，但它不是不可变的任务契约。

Context Guard 因此把四件事分开记录：

1. 用户实际提出了什么要求；
2. 后续修订明确替代了什么；
3. 工具实际产生了什么结果，这个结果是否成功；
4. 哪些证据足以支持完成声明。

## 核心能力

- 使用 SHA-256 绑定的元数据记录根提示和委托提示。
- 为需求和验收项分配稳定 ID，显式记录 supersession，不静默改写历史。
- 在压缩前保存有界恢复包，并在 compact 或 resume 时恢复任务边界。
- 将最近一次成功的原生 `update_plan` 调用镜像为只读恢复索引。
- 保存有来源的有界委托契约和 Agent 结果，不保存 transcript 或隐藏推理。
- 将无结构或含糊的工具输出记为 unknown，阻止其满足完成门禁。
- 每轮最多保留一个私有、turn-bound staged control：完成 checkpoint，或
  `continue`、`user_wait`、`external_wait`、`deferred` 之一。
- 私有 stage request 只有在精确 hash marker 与成功工具 outcome 同时成立时才会被
  接受；raw stdout 路径由成功 CLI 最终输出独立 `Script completed` receipt。
  bare marker 仍会被拒绝，structured failure、非零状态或硬失败文本优先。
  控制命令不会成为关闭 requirement 的成功 evidence。
- 未 stage disposition 时安全让出，本轮结束但需求继续 pending。已验证 checkpoint、
  窄范围整体完成声明和用户显式 persistence 仍按固定 Stop 优先级处理。兼容保留的
  `continue` 仅作为提示，不能强制开启新一轮。
- 自然语言动作归属只作为诊断信号；普通的 assistant future、用户交接、外部等待或
  延期描述本身不能再直接触发强制续轮。
- 最多保存 32 条 Stop 决策的时间、turn ID、protocol/control source、声明的
  disposition、诊断 outcome、哈希与 reason codes，不保存原始回复正文。
- 使用有界跨平台文件锁串行化同一会话的并发更新，并覆盖公开 CI 发现的 Windows
  access-denied/持有者退出竞态。
- 将二进制和 data URL 替换为类型、长度与哈希元数据。
- 校验私有状态完整性；只允许从通过哈希验证的不可变提示记录重建，无法重建时
  fail closed。
- 支持脱敏 handoff 和显式、受限、不可覆盖的 successor pack。

## 架构

```mermaid
flowchart TB
  A["1 · 用户定义任务契约<br/>目标 · 必须保留的行为 · 禁止修改范围 · 验收检查"]
  B["2 · Context Guard 保存私有检查清单<br/>并记录后续修订"]
  C["3 · Codex 正常工作<br/>文件 · 工具 · 测试 · subagents"]
  D["4 · /compact 或恢复任务后<br/>重新注入仍然有效的检查清单"]
  E{"5 · 清单中的每一项<br/>都有成功证据吗？"}
  F["否 · 返回第 3 步<br/>继续工作或明确报告阻塞"]
  G["6 · 全部具备<br/>允许正常完成"]

  A --> B --> C
  C -->|"上下文被压缩或任务恢复"| D
  D --> E
  E -->|"否"| F
  E -->|"是"| G

  classDef native fill:#f6f8fa,stroke:#57606a,color:#24292f;
  classDef private fill:#ddf4ff,stroke:#0969da,color:#24292f;
  classDef decision fill:#fff8c5,stroke:#9a6700,color:#24292f;
  class A,C,D,F,G native;
  class B private;
  class E decision;
```

任务执行、上下文压缩、Plan/Goal 状态和 subagents 仍由 Codex 原生系统负责。
Context Guard 只把与正确性有关的有界检查清单带过上下文边界，并在宣告完成前核对它。

完整职责边界见[架构说明](docs/ARCHITECTURE.md)和
[隐私说明](docs/PRIVACY.md)。

## 日常示例：重构代码，但不能破坏现有调用方

假设一个项目已经有多个调用方依赖 `submit_order(payload)`，但结算模块越来越难维护，
于是你让 Codex 整理这部分代码。

### 1. 最初的任务

```text
把 checkout.py 中的订单校验逻辑重构到 validators.py。

要求：
- 保持公开接口 submit_order(payload) 的签名和行为不变。
- 不得新增或修改数据库 migration。
- 为无效优惠券和重复订单补充回归测试。
- 只有现有测试和新增测试都通过，任务才算完成。
```

Context Guard 把这些要求整理成私有检查清单。Codex 仍可正常读取文件、制定计划、
编辑代码、运行工具或把有界子任务交给 subagent。

### 2. 中途又补充了一条限制

```text
再补充一条：保留 normalize_phone() 作为兼容包装函数，因为旧集成仍会直接导入它。
```

这条修订会追加到检查清单中，而不是静默改写最初的任务。

### 3. 任务变长并触发 `/compact`

经过大量文件阅读、代码修改、测试失败和修复后，对话发生上下文压缩。普通摘要也许
还记得“移动校验逻辑并让测试通过”，却可能漏掉兼容包装函数或禁止修改 migration。
Context Guard 会恢复仍然有效的检查清单：

```text
压缩后仍须满足：
- submit_order(payload) 对现有调用方保持兼容。
- 数据库 migration 未被修改。
- normalize_phone() 仍作为兼容包装函数存在。
- 已覆盖无效优惠券和重复订单。
- 现有测试和新增测试全部通过后才能完成。
```

### 4. “重构完成”必须先通过证据核对

在 Codex 宣告完成前，每个未完成事项仍需要已经捕获的成功证据：

| 检查事项 | 示例证据 | 缺少证据时 |
| --- | --- | --- |
| 公开接口未变化 | 检查函数签名，并运行兼容性测试 | 继续工作 |
| migration 未变化 | 对 migration 目录执行成功的差异检查 | 继续工作 |
| 包装函数保留 | 检查实现并运行对应回归测试 | 继续工作 |
| 必要行为有覆盖 | 无效优惠券和重复订单测试确实存在 | 继续工作 |
| 重构整体通过 | 现有与新增测试套件均成功退出 | 允许完成 |

最终回复便可以说明改了什么，并列出真正通过的检查，而不是依赖压缩后的摘要记住所有
限制。

这是一个有代表性的重构案例，不是基准测试或语义正确性证明。Context Guard 保证要求
持续可见，并让完成声明绑定证据；实现本身是否正确，仍然需要测试和人工判断。

## 环境要求

- Python 3.10 或更高版本；Hook runtime 没有第三方运行时依赖。
- Codex CLI `0.146.0` 或更高版本是当前已测试的最低基线。这只是经过验证的下限，
  不是对所有未来 Codex 版本的兼容承诺。
- 能够加载插件和生命周期 Hook 的 Codex 使用界面。

## 从本地克隆安装

从公开 GitHub 仓库安装：

```shell
git clone https://github.com/GreenLv/codex-context-guard.git
cd codex-context-guard
python3 scripts/manage_plugin.py --apply
```

Windows 使用 Python 3.10+ launcher：

```powershell
py -3.10 scripts\manage_plugin.py --apply
```

安装器会注册这个非默认 repo marketplace，安装
`context-guard@codex-context-guard`，检查源码与缓存一致性，并在升级时保留旧版本
缓存。如果源码在相同版本号下发生变化，它会拒绝就地刷新，因为仍在运行的任务
可能继续调用旧的绝对 Hook 缓存路径。

安装插件并不等于信任 Hook。安装后应启动一个新的 Codex CLI 任务，打开 `/hooks`，
逐项检查八类 Hook 定义，只在内容与本仓库一致时信任。不要使用 trust bypass。
安装或 Hook 变化后，再启动一个全新任务进行测试。

相关官方文档：[插件打包](https://developers.openai.com/plugins/build/plugins)、
[安装和使用插件](https://learn.chatgpt.com/docs/plugins)以及
[Hook 高级配置](https://learn.chatgpt.com/docs/config-file/config-advanced#hooks)。

## 快速检查

在全新任务中输入：

```text
$context-guard
```

然后运行：

```text
context-guard status
context-guard diagnose
```

如需验证恢复链，应创建一个非简单任务，执行 `/compact`，并检查紧接着的 continuation
是否恢复相同需求。单元测试通过不能代替真实 compact/resume 验证。

维护者可以对已安装缓存运行隔离生命周期 smoke：

```shell
python3 scripts/smoke_installed.py
```

## 用户控制

- `$context-guard` 或 `context-guard on`：启用完整恢复与完成门禁。
- `context-guard off`：关闭恢复和完成门禁，但继续记录提示。
- `context-guard status`：显示保护状态、Stop protocol/classifier 版本和最近决策，
  不暴露原始提示。
- `context-guard diagnose`：显示有界的 protocol/control source、声明的 disposition、
  诊断 outcome、reason codes 与哈希，不暴露原始提示或回复。
- `context-guard export <path>`：在当前项目中生成脱敏 handoff；默认路径为
  `.codex/context-guard/CONTEXT_HANDOFF.md`。
- `context-guard rollover <directory>`：验证用户显式准备的 successor 输入，写入
  不可覆盖的有界 handoff 和哈希清单；它不会创建或授权另一个任务。

使用 `rollover` 前请阅读
[Successor Pack 输入说明](skills/context-guard/references/successor-pack.md)。

## 实测 token 开销

Context Guard 会向受保护任务注入提示和恢复上下文。在一组经过匿名化的 5 个已完成、
工具调用较多的 0.6.1 桌面任务中，Hook/恢复上下文约占总 token 的 **1.4%**；把插件
触发的状态核对也计入后，加权观测值约为 **1.5%**。单任务观测范围约为
**0.2%–2.1%**，因此对相似的长任务，可以把 **约 1%–2%** 作为量级参考，而不是
固定保证值。

实际占比会随 compact 频率、ledger 大小、是否显式加载 skill 以及工具调用密度变化。
Token 占比也不等于费用占比，因为本地会话日志无法精确归因缓存输入的计费贡献。

## 私有数据与保留期

插件运行时数据写入 Codex 管理的 `PLUGIN_DATA`。直接 CLI fallback 只用于隔离开发。
提示正文、任务状态、证据摘要和恢复文件都是本机运行时数据，不属于本仓库。

已结束会话在 30 天后可以被清理。脱敏导出只在用户明确请求时创建，并保留在用户
选择的项目中，因此由用户决定保留时间。未经检查，不要提交插件数据或生成的
`.codex/context-guard/` 文件。

导出会省略原始提示文件、transcript 正文、凭据、认证头、URL query 和插件私有
路径。详见[隐私说明](docs/PRIVACY.md)。

## 更新与卸载

更新本地克隆：

```shell
git pull --ff-only
python3 scripts/manage_plugin.py --apply
```

插件源码变化必须更新版本号。安装器通过可信 SHA-256 索引持久归档所有历史版本，
只在 `--apply` 时从可信归档修复缺失或变化的 live cache，且从不自动清理归档。
版本策略见 [Versioning](docs/VERSIONING.md)。

卸载公开插件和 marketplace：

```shell
codex plugin remove context-guard@codex-context-guard
codex plugin marketplace remove codex-context-guard
```

卸载代码并不等于删除私有运行时数据。删除前应检查插件数据位置；如果仍有任务依赖
旧 Hook 路径，应继续保留。

## 验证

```shell
python3 scripts/validate_public_repo.py .
python3 scripts/audit_public_tree.py .
python3 -m unittest discover -s tests -p "test_*.py"
ruff check .
```

CI 矩阵覆盖 Ubuntu、macOS、Windows，以及 Python 3.10、3.12、3.13。平台能力只能
按实际证据描述，详见[兼容性说明](docs/COMPATIBILITY.md)。

Windows 原生 0.5.1 验收只作为历史证据。0.6.1 正式版本已通过限定的 macOS 与 Windows
source/install/archive 门，且 private/public identity 均在正常 Hook 信任、无 trust
bypass 运行中通过 `user_wait`、completion checkpoint 和手动 schema-5 `/compact`
恢复。精确发布提交还必须通过 PR/main CI、HOL 和 tag CI；CI 不能替代原生运行。
未发布且版本号已消耗的 0.6.0 候选已经在真实 Code Mode fresh gate 失败，不得创建
tag 或原地修补。证据边界见[本地发布验收记录](docs/LOCAL_ACCEPTANCE.md)。

## 明确不做

Context Guard 不是：

- 证明实现语义正确的 verifier；
- 通用安全沙箱或访问控制系统；
- transcript 备份或云同步服务；
- 第二套 Plan/Goal 控制器、Agent 调度器、mailbox 或共享工作区；
- 人工审查、测试或验收的替代品。

需求—证据语义相关性不属于 0.6.x 能力，顺延到可能的 0.7.0，并要求先批准含
false-acceptance、false-rejection 和 abstention 阈值的 benchmark。共享多 Agent
工作区与 telemetry 仍是独立研究决策。

## 贡献与安全

开发要求见 [CONTRIBUTING.md](CONTRIBUTING.md)。敏感问题请按
[SECURITY.md](SECURITY.md)通过 GitHub Private Vulnerability Reporting 报告。

项目采用 [Apache License 2.0](LICENSE)。
