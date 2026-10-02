# 下一版本整仓审查矩阵（源码候选）

日期：2026-10-02。候选分支 `candidate/next-gpt6-perf`，head `2f574e411cb1e47d7e586b6458c9d9becc5a4edf`（基线 `d24899d8202a58d7426208541c58d193464e93de`）。状态标注：**confirmed**（本轮已修，附旧失败/新通过测试）、hypothesis（登记待证据，未修复）、no-finding。三个面由并行只读审查覆盖，其余由实现者直读；两轮审查的确认缺陷均已在候选内关闭。

| 审查面 | 结论 | 证据与入口 |
| --- | --- | --- |
| 启动/Hook wire | no-finding（新进程内委派经专项审查）；1 confirmed 已修（子进程回退负信号码→128+N） | `test_context_guard_phase2`（路由表/回退/进程内等价）；`cg_hook.py::_delegate` |
| 根需求/控制/动作 | 1 confirmed 已修（supersession 按 prompt_id 波及同源 acceptance → 改为仅当该 prompt 最后活跃 requirement 被取代时波及）；2 hypothesis 登记 | 旧失败/新通过：`test_supersession_scoped_to_targeted_requirement`（基线 FAIL） |
| 共享 core/摘要 | no-finding（canonical bytes/类型/Unicode/未知能力逐节直读）；1 hypothesis 登记（「」『』引号清单差异，受 root 来源/scope 校验兜底） | `test_conformance_fixtures`、`reference_digest_encoder` 套件 |
| 存储/互斥/迁移 | CGN-01/CGN-08 closed（WP-01，见 `LOCK_SUBDESIGN_NEXT.md`）；互操作边界如实声明 | `tests/test_session_lock_protocol.py`（基线 7/10 失败→全过）；真实子进程/kill/legacy 模拟器 |
| 观察/证据/效果 | no-finding（terminal/exit/效果分离、readback 时序、复合命令拒绝逐项直读）；1 hypothesis 登记（失败措辞先于结构化 exit code，方向 fail-closed） | `handle_post_tool`、`cg_commit.py`、adapter readback 用例 |
| 完成/等待/交付 | 实现者直读（`handle_stop` 事务快照/消费前复核/回滚、等待与一次纠正、delivery 关联）；no-finding | `test_stop_v5`、`test_stop_performance`、`test_evaluation_context` |
| 恢复/子任务/多模态 | 实现者直读 + 复用评审（分页 revision 绑定、`clip_preserving_suffix` 预算、Subagent 记录、资产对账）；no-finding | recovery/scope/subagent/asset 套件；`test_warm_scope_resolution_freshness` |
| 回答/来源审查 | 实现者直读（O_EXCL claim-once、身份摘要绑定、撤销检查、单次模型调用）；no-finding | `cg_answer_review.py::pending_review`、commentary 套件 |
| 发布适配 | 1 confirmed 已修（分类器异常在已采用 release 会话内 fail-open → 改为 diagnose 导向 deny；普通会话保持契约 fail-open）；2 hypothesis 登记（SHA-1 长度正则、adapter 键缺失面） | 旧失败/新通过：`test_classifier_exception_keeps_release_gate_and_ordinary_path`（基线 ERROR） |
| 安装/归档 | no-finding（不可变缓存/并发/失败恢复/no-op 复核）；隔离安装实测通过；2 hypothesis 登记（archive 崩溃窗不自愈、Windows 锁等待语义差异） | 本轮隔离 `--codex-home` 安装 + strict no-op + `smoke_installed.py` PASS |
| 验证可信度 | no-finding 新增；2 处 oracle 契约随协议更新（benchmark 锁释放改为功能等价探针、负控分母改为索引派生） | `test_benchmark_oracle`、`test_incident_coverage_negative_controls` |
| 文档/隐私/治理 | Skill 精简见 `GPT6_INSTRUCTION_MAP.md`（承接映射逐条）；双语 Unreleased changelog；仓库 AGENTS/开发流程面本轮复核后未改动（无明显无风险去重，留待读者冻结评审决定） | validator/隐私审计通过；reader 冷评审待协调者 |

## 登记的 hypothesis（未修复，不冒充缺陷）

1. off→on 后 profile 保持（strict 再臂不披露）——可能是有意持久化，需契约裁定。
2. core 引号清单缺「」『』（`cg_core_v2.py`），影响面受 root 来源与 scope 校验限制。
3. commit/push 验证硬编码 `main` 分支——非 main 默认分支只见 fail-closed 可见性缺口，无假成功。
4. 失败措辞标记先于结构化 exit code（方向 fail-closed：可把真实成功记为 failed/failure_marker）。
5. `cg_release_adapter` 40-hex 提交正则（SHA-256 仓库全拒，方向 fail-closed）与 action 键直取。
6. installer archive 崩溃窗（移动与索引写之间）需手工恢复；Windows 安装锁等待语义与 POSIX 不同。
7. Hook 缓存回退选择器不接受 prerelease semver 目录（PLUGIN_ROOT 主路径不受影响）。
8. 安装级 smoke 不覆盖 router/launcher/SessionEnd wire（已列入原生验收 pending）。

## 平台与证据边界

本轮全部证据为 macOS 源码级 + 隔离安装级；Windows 原生（含 `msvcrt.locking` 字节范围语义、PowerShell 启动器、原生历史行）、真实宿主九 Hook、GPT-6 模型批次、精确提交 full CI/HOL 均为 pending，未声称通过。锁子设计（方案 A 与互操作边界）待协调者有界审查后方可视为冻结契约。
