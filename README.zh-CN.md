# Context Guard

[![CI](https://github.com/GreenLv/codex-context-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/GreenLv/codex-context-guard/actions/workflows/ci.yml)
[![HOL Plugin Scanner](https://github.com/GreenLv/codex-context-guard/actions/workflows/hol-plugin-scanner.yml/badge.svg)](https://github.com/GreenLv/codex-context-guard/actions/workflows/hol-plugin-scanner.yml)
[![Release](https://img.shields.io/github/v/release/GreenLv/codex-context-guard)](https://github.com/GreenLv/codex-context-guard/releases)
[![License](https://img.shields.io/github/license/GreenLv/codex-context-guard)](LICENSE)

[English](README.md) | [介绍文章](https://blog.csdn.net/LvGreat/article/details/163534498) | [更新日志](CHANGELOG.zh-CN.md)

Context Guard 防止长时间 Codex 任务在上下文压缩后漏掉关键要求。它在 compact 或 resume 后恢复私有检查表，并要求每个待办都有成功证据，任务才能报告完成。它不会用自带的审批提示去门禁普通编辑、提交或推送。

它与 Codex 的 Plan、Goal、记忆、子 Agent、工作树和会话记录并行工作，不会替代或控制这些原生能力。

> 当前正式版本：`0.12.4`。详见[发布说明](docs/releases/v0.12.4.md)、[更新日志](CHANGELOG.zh-CN.md)、[兼容性说明](docs/COMPATIBILITY.md)和[本地验收记录](docs/LOCAL_ACCEPTANCE.md)。
>
> `0.13.0` 是 `main` 上的未发布源码候选：默认 Context Guard 不再用自带的授权提示门禁普通编辑、提交、推送、打标签和发布，只保留需求恢复、任务状态连续、诚实完成核对、答复送达跟踪和私有控制完整性。它尚未安装或发布；详见[更新日志](CHANGELOG.zh-CN.md)。
>
> `0.12.4` 修复补充指令丢失原有限制、确认错解除暂停、恢复正文不完整，以及提交并推送的目标识别问题。变化见[更新日志](CHANGELOG.zh-CN.md)，平台检查见[验收记录](docs/LOCAL_ACCEPTANCE.md)。

## 安装

需要 Python 3.10 或更高版本、Codex CLI `0.146.0` 或更高版本作为当前已测试下限，以及能够加载插件和生命周期 Hook 的 Codex 界面。

```shell
git clone https://github.com/GreenLv/codex-context-guard.git
cd codex-context-guard
python3 scripts/manage_plugin.py --apply
```

Windows 使用：

```powershell
py -3.10 scripts\manage_plugin.py --apply
```

安装器会把本仓库添加为 marketplace，安装 `context-guard@codex-context-guard`，并检查安装结果。它也会保留升级前任务仍需要的版本化副本。

安装插件不会自动信任 Hook。请启动新的 Codex 任务，打开 `/hooks`，检查并信任全部九个定义，然后再启动一个新任务，让它加载当前版本。

### 升级说明

通过受管安装器升级后，启动新任务加载新版。旧任务仍可能使用旧版缓存，请继续保留；已安装缓存不可变，0.13.0 绝不刷新已消费的副本。

`0.13.0`（未发布源码候选）调整了职责分工：默认守卫不再询问执行授权，升级后编辑、提交、推送不会再出现审批提示。私有状态会从 schema 11、10、9 迁移到 schema 12。旧会话中缺少可信送达事实的待答问题会标注"历史答复状态不确定"，不会被机械重问；旧的自然语言授权记录保留为历史，永远不会阻塞任何动作。降级前请阅读[兼容性说明](docs/COMPATIBILITY.md)。

若所需 Python 解释器和受管缓存都不可用，Context Guard 会停止并提示重装。版本历史见[更新日志](CHANGELOG.zh-CN.md)，详细行为及仍依赖宿主验证的情形见 [0.12.4 行为基线](docs/BEHAVIOR_BASELINE_0_12_4.md)。

## 试用

在全新任务中启用 Context Guard：

```text
$context-guard
```

然后检查受保护状态：

```text
context-guard status
context-guard diagnose
```

验证恢复链时，请使用一个非简单的合成任务，执行 `/compact`，并确认未完成要求随即恢复出来。

## 它保护什么

- 需求、验收条件、禁止项和后续修正都有稳定的任务内 ID。
- 上下文压缩和任务恢复会还原未完成检查表，不只依赖会话摘要。
- 工具证据必须对应指定的文件、URL、图片或其他结果，才能关闭对应条目。
- 答复送达不等于任务完成。纯问题的自然答复真正送达后，该条目以 `answered` 关闭，压缩后不再重放；执行义务始终需要证据；未知送达状态绝不会冒充完成。
- 图片等多模态输入只保存哈希和必要元数据；如果用户要求修改图片，完成证据可以绑定到修改后的图片回读，而不只是“工具运行成功”。
- 含糊输出保持 `unknown`（未知）；损坏或无法验证的私有状态会安全拒绝继续。
- 导出必须显式触发并经过脱敏。图片字节、凭据和会话正文不会复制进需求记录。

只有目标足够具体时，Context Guard 才会自动核对，例如指定文件、URL、修改后的图片或必须全部覆盖的对象清单。如果无法精确验证，它会保留待办，而不是猜测结果。等待用户、外部结果或后续处理不会关闭未完成要求。

## 谁决定什么

- 用户决定任务目标以及允许哪些变更。
- 仓库说明和已选择的 Skill 规定工作流程，但不能增加授权。
- Codex Plan 记录模型当前的执行步骤；Context Guard 可以保留只读引用，但不会修改计划。
- 工具、文件、图片、UI 和公开页面的读回只说明事实，它们本身不能决定一个动作是否获得授权。

从 0.13 开始，职责这样分工：

- **执行授权由你和主执行 Agent 决定。** 一次编辑、提交、推送、打标签或发布是否在你的授权范围内，由主执行 Agent 依据真实对话、仓库规则和宿主权限判断，而不是由 Context Guard 提示决定。Context Guard 的放行从来不是授权，现在产品把这一点写明。
- **Context Guard 负责正确性连续。** 它在压缩和恢复后还原要求与约束，保持任务状态连续，用匹配的确定性证据核对完成声明，跟踪要求的答复是否真正送达，并保护自己的私有控制状态。这些检查保持 fail-closed，也绝不会要求你重新授权普通工作。
- **显式采用的发布执行合同负责精确身份动作。** 只有显式采用或显式 `context-guard release` 声明之后，tier-A 动作——打标签、registry publish/yank、GitHub Release——才需要精确的一次性动作票据。

Context Guard 不授予权限，也不替代平台审批；未接入 Hook 的专用工具仍在它的视野之外。

## 保护级别

Context Guard 的检查强度跟随当前保护级别。Skill、仓库说明或安装插件只能"建议"级别，只有你能打开更严格的级别。

| 级别 | 如何开启 | 实际行为 |
| --- | --- | --- |
| **standard**（默认） | 启用守卫 | 在压缩和恢复后还原你的要求，保持任务状态连续，依据确定性证据诚实核对完成，并跟踪答复送达。没有执行审批，也不会反复要求授权：普通编辑、提交、推送、状态提问和压缩都不会触发 Context Guard 提示。 |
| **strict** | 你明确要求严格证据保护 | standard 之外，对当前工作单元启用强制证明义务——适合正式交付和多图任务。strict 绝不暗示发布或 Git 门禁。 |
| **release** | 只有显式采用的发布执行合同或显式 `context-guard release` 声明 | standard 之外，对已覆盖的 tier-A 身份动作（打标签、registry publish/yank、GitHub Release）要求候选闭包、发布就绪凭据和精确的一次性票据。标签或 Release 的授权永远不会自动成立。 |
| **observe** | 维护者或灰度配置 | 只记录有界的"本来会怎样"结果，不实际拦截。 |

其余保持开放：本地修改、测试、普通提交、读取、搜索和 dry-run 不需要授权；`context-guard off` 会停止全部门禁，仅保留提示记录。普通动作被放行时屏幕上什么都不会出现；动作被拒绝时——发布合同票据失败或完整性失败——你会看到一句可操作的简短原因。

## 工作流程

```mermaid
flowchart TB
  A["你交给 Codex 一个任务<br/>需求 · 禁止项 · 验收条件"]
  B["Context Guard 保留私有检查表<br/>并记录后续修正"]
  C["Codex 正常工作<br/>文件 · 工具 · 测试 · subagents"]
  D["/compact 或 resume 后<br/>恢复未完成检查表"]
  E{"每项是否都有<br/>匹配的成功证据？"}
  F["否 · 继续工作<br/>或报告阻塞"]
  G["是 · 允许正常完成"]

  A --> B --> C --> D --> E
  E -->|否| F
  E -->|是| G
```

工作过程和原生计划状态仍由 Codex 管理。Context Guard 负责跨上下文保留检查表；项目显式采用仓库说明后，它还会恢复未完成阶段和计划引用，再核对任务是否完成。

## 日常示例：撰写技术方案，但不能漏掉已确认决策

假设任务是：

```text
编写 docs/design/checkout-v2.md。

- 保持已确认的 API 和数据流决策不变。
- 不修改上线日期，不新增基础设施承诺。
- 使用 RFC 模板。
- 每条建议都提供来源链接，或标注“待确认”。
```

经过调研、修改、绘图和 `/compact` 后，Context Guard 恢复相同检查项。Markdown 检查通过不能代表整个任务完成：已确认决策、RFC 模板、来源链接和禁止项仍需各自证据。

这个例子只说明契约边界，不表示 Context Guard 能判断技术方案本身是否合理。

同样的边界也适用于日常执行。当你说"完成修改，提交并推送"后，普通编辑、提交、推送、状态提问和压缩都不会再触发 Context Guard 重新授权，`/compact` 前后都是如此。回复声称整个任务完成时，仍需要与未完成事项匹配的证据。

## 在受保护任务中可能看到什么

| ID | 含义 |
| --- | --- |
| `R001` | 当前任务捕获的一条需求。 |
| `A003` | 需要独立检查的一条验收项。 |
| `E####` | 可以关闭兼容条目的成功证据记录。 |

这些都是任务内 ID，不是 GitHub issue 或全局任务编号。它们可能出现在进度说明中，但私有记录不会原样打印在最终回复里。

## 看到“任务尚未安全完成”时

当仍有要求缺少匹配证据、而回复声称整个任务已完成时，Context Guard 可能用下面这条标准脱敏提示要求 Codex 继续：

```text
[Context Guard continuation] The task is not yet safely complete.
```

确实还有工作未完成时，这条提示属于正常保护。如果提示与预期不符，可以直接问 Codex 还缺什么，并运行 `context-guard status` 或 `context-guard diagnose`。默认反馈只提到当前工作单元的未验项数量、一个原因和一个下一步，不会罗列全部历史 ID；每回合最多纠正一次，之后未完成的工作保持待办，回合安全结束。等待用户、外部结果或明确延期的回合会静默结束，不会关闭未完成要求。普通结束不需要任何命令：回复可验证地完成当前单元时，守卫会自行绑定唯一的成功证据。

已有任务可能继续使用启动时加载的 Hook 版本。升级后请启动新任务；如果旧 Hook 路径缺失，请按[版本策略](docs/VERSIONING.md)中的说明恢复。

## 用户控制

| 命令 | 用途 |
| --- | --- |
| `$context-guard` 或 `context-guard on` | 启用恢复和完成门禁。 |
| `context-guard off` | 关闭门禁，但继续记录提示变更。 |
| `context-guard status` | 查看保护状态计数，不暴露原始提示。 |
| `context-guard diagnose` | 查看有界诊断，不暴露原始提示或回复。 |
| `context-guard export <path>` | 在当前项目中显式写出脱敏交接文件。 |
| `context-guard rollover <directory>` | 验证准备好的后续任务输入，写出不可覆盖的交接文件与哈希清单。 |

使用 `rollover` 前请阅读[后续任务输入说明](skills/context-guard/references/successor-pack.md)。它不会创建或授权另一个任务。

## 私有数据与保留期

运行时数据写入 Codex 管理的 `PLUGIN_DATA`。提示正文、任务状态、证据摘要和恢复文件都属于本地运行时数据，不属于本仓库。

已结束会话在 30 天后可以清理。脱敏导出只在显式请求时创建，并省略原始提示、会话正文、凭据、认证头、URL 查询参数和插件私有路径。详见[隐私说明](docs/PRIVACY.md)。

## 更新与卸载

```shell
git pull --ff-only
python3 scripts/manage_plugin.py --apply
```

插件源码变化必须更新版本号。历史缓存和可信归档会继续供已经加载它们的任务使用。

```shell
codex plugin remove context-guard@codex-context-guard
codex plugin marketplace remove codex-context-guard
```

删除代码不会删除私有运行时数据。如果活动任务仍可能依赖旧数据或缓存，请继续保留。

## 文档

- [架构](docs/ARCHITECTURE.md)
- [隐私](docs/PRIVACY.md)
- [兼容性](docs/COMPATIBILITY.md)
- [版本策略](docs/VERSIONING.md)
- [本地验收](docs/LOCAL_ACCEPTANCE.md)
- [更新日志](CHANGELOG.zh-CN.md)

## 验证

```shell
python3 scripts/validate_public_repo.py .
python3 scripts/audit_public_tree.py .
python3 scripts/run_current_behavior_suite.py
python3 scripts/check_phase3_transition.py
ruff check .
```

current-behavior runner 会发现除字节冻结的 0.11.x 观察基线外的全部当前 `test_*.py` 模块。transition 审计会单独运行该历史基线，并且只有 fixed/inverted 精确清单一致时才成功；若把冻结文件当成普通的“全部应通过”套件直接发现，它会按设计报告失败与 unexpected success。

Hook 运行时只使用 Python 标准库。CI 覆盖 Ubuntu、macOS、Windows 和 Python 3.10–3.13；CI 不能替代原生 Hook 信任或已安装生命周期证据。

## 明确不做

Context Guard 不是语义证明系统、安全沙箱、会话备份、云同步服务、第二套 Plan/Goal 控制器、Agent 调度器，也不能替代测试和人工审查。它不保证任意内容的语义正确性，只执行自己能表达确定性检查的部分；它不替代 Codex 权限系统、`repository-release` 发布合同、人工审查或平台 readback。

0.13 保持 model/agent-agnostic 基线：它不假定模型或 Agent 自带可靠的长上下文保护与恢复。从恢复、工作单元、证据到完成的闭环由 Context Guard 本地提供，协议语义与 Codex Hook adapter 保持分离；一个动作是否获得授权，由你、执行 Agent 和宿主权限判断，而不是由 Context Guard 提示判断。

只有发起根任务的用户执行 `context-guard adopt <project-relative-json>` 后，项目说明和计划引用才会被采用。安装 Skill、加载模板或在普通文字中提到计划都不会启用这项行为。采用项目说明不会修改 Codex Plan 状态，也不会授予权限。已覆盖动作的检查遵循上文的保护级别。

## 贡献与安全

开发说明见 [CONTRIBUTING.md](CONTRIBUTING.md)。敏感问题请按 [SECURITY.md](SECURITY.md)通过 GitHub Private Vulnerability Reporting 报告。

项目采用 [Apache License 2.0](LICENSE)。
