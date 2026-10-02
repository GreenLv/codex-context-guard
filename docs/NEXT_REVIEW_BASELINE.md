# 下一版本审查基线

日期：2026-10-02。源码检查 subject：`d24899d8202a58d7426208541c58d193464e93de`。进入本轮时工作区干净；当前产品标识为 0.14.3。此文是可更新的事实快照，不是完整代码审查通过证明；正式实施仍须完成下面所有审查面。

## 1. 已确认问题及候选风险

| ID | 状态/优先级 | 源码定位与证据 | 本版处理 |
| --- | --- | --- | --- |
| CGN-01 | 已复现，P1 | `context_guard.py::filesystem_session_lock`（当前 7381 行）：仅 mtime >30s 即 unlink；finally 再按路径 unlink。两个真实 Python 进程，首个持锁时将临时锁时间老化 31s，第二个进入；首个释放时第二个锁文件消失。 | 关闭 owner、旧观察、崩溃、旧新版本互操作整个有限家族；先审查子设计。人工老化是确定性边界反例，不是声称正常 Hook 已运行 31s。 |
| CGN-02 | 已复现，P2 | `EvaluationContext`（10194 行）：1 byte 文本预算下，14,014 byte 输入仍被 search memo 保留，source-clause memo 也纳入；`_parsed_bytes=0`。 | 总预算覆盖全部 memo 及派生值；现有条数限制不能称为总内存预算。不是已观测 OOM。 |
| CGN-03 | 源码确认，性能机会 | `cg_hook.py::_delegate` 总是 subprocess 启动 heavy core；大部分非 PreToolUse 事件走这里，SessionEnd 已直达。 | 全入口测量，保留 light path，减少二次启动并验证流/退出/清理等价。 |
| CGN-04 | 源码确认，上下文机会 | `completion_command_context`（15944 行）构造四条重复长绑定命令；SessionStart 在 4000 字符总预算内先扣其长度，并在保存后再次生成。 | 按需发现高级指令，把预算优先用于需求；测完整普通任务的工具往返，防止用额外查询换字符。 |
| CGN-05 | 已核查，覆盖更新 | 公共历史快照固定 55 registry +16 legacy、52 active；当前权威输入为 56 registry（45 active）+16 legacy（8 active）。新增 `CGI-20260928-dsh-warm-resolver-scope-drift`。 | 刷新并冻结逐案输入，旧 pass 不转写成新执行；仍需完整性和适用性裁定。 |
| CGN-06 | 源码确认，读者歧义 | 当前架构、版本、Skill reference 中同时有已发布 0.14.x 与旧 `candidate`/pending 描述；部分指向有意保留的窄证据缺口。 | 建立当前事实入口，历史标为历史；逐项保留真实未验部分，禁止全局替换成 passed。 |
| CGN-07 | 待 profile | `handle_pre_compact`/`handle_session_start` 多次 save、恢复投影、transcript/控制来源重复读取；Stop 已有 context，其他入口仍需逐点检查。 | 以事件事务/崩溃语义决定可否重用，不能仅凭调用数删除保存。 |
| CGN-08 | 待故障注入 | `filesystem_session_lock` 在进入 yield 的 try/finally 前写 owner；write 失败可能留下 descriptor/文件；进程内锁无有界等待，SessionEnd 却只有 3s。 | init/partial write/close/unlock/长队列/kill 注入；确认影响再修复，不能报告为已发生生产事故。 |

动态 probe 只使用临时合成锁和新进程，未读取或修改日常私有账本、缓存及原事故会话。结果与脚本在私有交接包中，开发者应将等价反例转成正式回归。基线未测得本版性能收益，未执行新候选全测试或原生验收。

## 2. 已有证据与准确边界

上版[验收记录](LOCAL_ACCEPTANCE.md#0143--2026-09-29)记载：Stop S1/S4 的完整核心进程中位数，macOS 约 0.472/0.662s，Windows 约 0.489/0.690s；PreToolUse 冷启动中位数约 0.369/0.459s。它们是上版特定环境证据，本轮没有重新计时。

上版已有 Stop 事件内复用、消费前来源复核与业务状态回滚，13+13 次 prompt read 和 113 次 parse 等确定性回归应保留。不能从“已优化 Stop”推断其他 Hook/全启动链已足够快，也不能把 dispatch 与 subprocess 或宿主时长混用。

本轮检查的 Skill 为 8,017 UTF-8 bytes，131 行；AGENTS 为 14,303 bytes，238 行（含受管理区块）。这些是文本量，不是 tokenizer 计数。产品运行时核心文件约 21,431 行；不因此安排一次大拆分，按边界抽取确需修改的部分。

相似 DSH 项目的只读参考提示应审查 stale observer、owner 初始化崩溃、缓存可变输入、oracle 闭包和测试身份。这些是审查视角，不是本项目缺陷或通过证据。本轮未对该项目写入、派发任务或借用其结果。

## 3. 完整源码审查地图

每行须有 owner、reviewed paths、结论（confirmed/hypothesis/no finding）、反例或测试入口、状态和证据身份。测试名是入口线索，不代表此轮已执行。新文件同样纳入，不允许只审查下列已知热点。

| 审查面 | 主要实现 | 已有测试/资料入口 | 决策重点 |
| --- | --- | --- | --- |
| 启动/Hook wire | `hooks/hooks.json`、两个 launcher、`cg_hook.py`、`cg_protocol.py`、`cg_codex_adapter.py` | `test_public_contract`、phase2/4、Windows platform suite | 九事件、原始字节、流/退出码、Python floor、快路径、取消 |
| 根需求/控制/动作 | `context_guard.py`、`cg_instruction.py`、`cg_actions.py`、`cg_authority.py` | `test_stop_v5`、`test_cg142_instruction_objects`、core/control/conformance tests | 语句与对象、span、supersession、执行与信息、作用域 |
| 共享 core/摘要 | `cg_core_v2.py`、`cg_core_v2_schema.py`、`cg_codex_core_adapter.py`、`reference_digest_encoder.py`、core assets | `test_conformance_fixtures`、`test_reference_digest_encoder`、`SEMANTIC_COMPATIBILITY.md` | canonical bytes、类型/空值/Unicode、镜像身份与未知能力 |
| 存储/互斥/迁移 | state schema、`context_guard.py` 的 lock/load/save/migrate/rebuild/atomic write | `test_context_guard`、migration/integrity/lock tests | 单 writer、崩溃、恢复、权限、软链接、回滚、旧版 |
| 观察/证据/效果 | PostToolUse、`cg_commit.py`、adapter facts、process/host collectors | `test_stop_v5`、`test_context_guard` 中 PostToolUse/readback 用例、`test_commentary_live_observer` | terminal outcome、exit/结果/效果分离、文件/Git readback、顺序 |
| 完成/等待/交付 | `handle_stop`、`cg_stop3.py`、`cg_delivery.py`、proof helpers | `test_stop_performance`、`test_evaluation_context`、stop subject/default path/wait tests | 不误关执行、不重开有效完成、未知不变成功、一次纠正 |
| 恢复/子任务/多模态 | recovery/page、SubagentStart/Stop、asset reconciliation | recovery、scope、subagent、asset tests 和 state schema | 缩短上下文仍全覆盖，source/父子身份、分页/预算 |
| 回答/来源审查 | `cg_answer_review.py`、`cg_commentary*.py`、`cg_process_tree.py` | answer review、commentary/control/source tests | 显式采用、MAC/来源、最多一次新输入调用、取消与子进程 |
| 发布适配 | `cg_release_adapter.py`、显式 action tickets、release latch | `test_cg130_default_path`、release contract tests | 仅明确采用生效；损坏 posture 不扩大默认工具 veto |
| 安装/归档 | `manage_plugin.py`、`smoke_installed.py`、`.codex-plugin` | `test_manage_plugin`、`test_smoke_installed` | 不可变 cache、archive identity、并发、失败恢复、no-op |
| 验证可信度 | `check_incident_coverage.py`、candidate identity、benchmark、native 工具、selector、CI | negative controls、benchmark oracle、acceptance identity、selected validation | 错 subject/假 pass/skip/空运行、输入闭包、全入口计时 |
| 文档/隐私/治理 | Skill/references、AGENTS、README 双语、CHANGELOG 双语、architecture/version/privacy/compatibility | public contract、tree audit、reader cold review | 最短读者路径、历史/当前状态、token 负担、授权边界 |

不要将目录表本身作为“完整 review 已完成”。开发者应通过 `rg --files` 和导入/调用关系补齐实际文件归属，所有生产/验证/安装模块都要有一行或明确所属项。固定的旧 baseline 测试只审查兼容解释，不改写其冻结字节。

## 4. 附加输入和工作区边界

实施入口重新解析 HEAD、dirty scope、发布版本占用、Python/CLI、现有 worktree 和 host 能力。当前权威历史库存在另一任务的未跟踪 DSH 验收文件；它们不属于本开发批次，不提交、删除或覆盖。私有交接包列出实际位置及快照；公共文档仅保留上述匿名分母和方法。

计划和本轮反例不能替代候选验收。下次回交报告只更新新增事实；保留这些原始 subject 和限制，避免把旧结果改贴到新 commit。
