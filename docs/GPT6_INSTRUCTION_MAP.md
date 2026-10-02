# GPT-6 精简的规则承接映射（WP-02）

日期：2026-10-02。基线 Skill root：8,017 bytes / 131 行（subject
`d24899d8202a58d7426208541c58d193464e93de`）。本版把 Skill root 与
description 缩短，并把可选流程外移到既有 references。删去或外移的每条规则
在下面标注承接位置：运行时检查（R）、规范/文档（D）或条件引用（Skill root
中的短路由行）。删除重复指导不等于删除断言。

## description（frontmatter）

- 旧：470 chars，含"任何需要正确性都使用"类过宽触发。
- 新：约 250 chars，仅保留可发现的启用条件：显式启用（`$context-guard` /
  `context-guard on`）、长/复杂/恢复任务、私有账本完成审查。子任务结果与
  compact/resume 恢复保留为短语。
- 承接：触发由 Codex Skill 匹配执行；误用防护由 SKILL.md 首段职责边界与
  advanced-completion.md "Do not invoke merely because loaded" 承接（R+D）。

## root 正文删去/外移条目 → 承接

| 旧 root 内容 | 承接 |
| --- | --- |
| "Do not invoke them merely because this Skill loaded"（高级命令防误触发） | 保留在 root（一行），细节在 advanced-completion.md（D） |
| `checkpoint-status`/`register-proof`/`stage-checkpoint`/`stage-disposition` 命令名与用法 | advanced-completion.md 全文 + 注入命令改为 checkpoint-status 发现式入口；默认 status 不携带命令清单，`--commands` 只读输出提供全部命令（R，CGN-04；R1 对齐） |
| 独立回答审查的完整执行约束（最多一次新输入、失败不自动重试、coverage unknown 语义、不循环等待模型） | answer-review.md（D）；root 保留一行摘要"once, `--execute`；不可用则 coverage unknown 并继续" |
| 审查事件"不 veto 普通工具 / Hooks 不调用模型" | 运行时不变量 N01/N02（R，test_cg130_default_path 等）+ authority-and-controls.md（D） |
| "agent-triggered integration still needs native acceptance" 版本状态行 | 移到 docs（本文件与 LOCAL_ACCEPTANCE.md 的当前状态入口）；不作为常驻 Skill 内容（CGN-06） |
| release profile 的 ticket/runner/observe 细节段 | authority-and-controls.md（D）；运行时由 release 契约检查强制（R） |
| "Platform approvals remain independent; tools without Hook events remain outside Hook coverage" | authority-and-controls.md（D）；root 保留"Authority stays with the user and the host"一段摘要 |
| "strict adds enforced current-unit proof obligations; not a Git-approval gate" | authority-and-controls.md（D）；R：strict 仅添加 proof 义务，无审批 |
| 恢复投影细节（plan mirror、memories recall） | root 保留两行摘要；完整语义在 docs/ARCHITECTURE.md（D） |
| "Do not weaken the advanced proof, integrity, private-control, or authority rules when moving between paths" | 不变量 N02/N03/N05（R，负控测试）+ 本映射（D） |
| 多模态"bounded metadata, hashes, dimensions, availability"细节 | root 保留一行；完整字段见 docs/PRIVACY.md 与 state schema（D+R） |

## root 保留的核心（对应不变量）

- 工作单元闭合与祖先约束（N04）、恢复包权威与显式 supersession（N03/N06）、
  证据分离与 carry-forward（N04/N08）、完整性失败阻断与 fail-closed
  （N05）、普通完成零命令（N02/N06）、隐私不外泄（N10）、委派结果边界、
  授权归属用户/宿主（N02）。

## 数据

- description：470 → 250 chars（-47%）。
- root：8,017 → 见本版测量报告（目标 ≥40% 减少）。
- references 未常驻，不计入常驻量；实际读取总量在模型批次中报告。

## 高级路径可达性

root 保留三处条件路由（advanced-completion / authority-and-controls /
answer-review、successor-pack），且注入的 checkpoint-status 命令追加
`--commands` 即可打印全部私有命令（默认 status 不携带），不依赖读原始
state 文件。
