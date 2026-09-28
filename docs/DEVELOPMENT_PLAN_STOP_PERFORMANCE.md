# Stop 全路径性能修复开发计划

状态：实现与协调者源码复核已完成；当前推进双平台原生验收和发布门槛，未发布。原始计划要求及各轮执行索引保留。

编写日期：2026-09-28。

适用仓库：`GreenLv/codex-context-guard`。

检查基线：`aea556d8ac651b1b94c200f88108c87cf8371893`。

受影响产品版本：0.14.2；建议修复版本：0.14.3（实施入口重新确认版本占用）。

## 1. 目标、范围与交付边界

消除长会话中 Stop 对相同输入重复解析、重复构造动作依据、重复读取根记录造成的时间放大。在保留既有完整性、证据、作用域、等待、交付和完成语义的条件下，让完整 Stop 在现有 10 秒时限内有充分余量，并用可复现的合成数据、确定性计数和真实宿主证据验证。

运行时实现只在这个公开产品仓库修改；历史错误库的唯一维护入口是 `context-guard-effectiveness`，其案例、映射和验收清单维护属于本计划的配套范围。开发 Harness 在 macOS 完成实现、历史错误库逐案回归、本机性能与安装验证，并交回源码、测试和候选说明。本聊天协调者负责独立开发复核，以及候选交回后的 Windows 跨主机线程协调和综合验收；不要求开发 Harness 拥有 Windows。其他仓库的实现、用户日常安装及发布不是默认开发范围。结构化交接文件只传递状态与对象，不授予额外操作权限。

用户补充的硬条件：本次案例已在 `context-guard-effectiveness` 正式收录为 `CGI-20260928-codex-stop-performance-timeout`（旧本机来源编号 `CGI-2026-046`）；这一版必须在完整历史错误库上全部通过。开发 Harness 执行历史库回归，Windows 原生部分由协调者组织；上一版本的豁免和 unknown 不自动继承到本版。

### 1.1 必须保持的契约

- Python 标准库运行时，Python 3.10+；九个 Hook 事件及 POSIX/Windows 命令形式继续一致。
- 计划目标不改变 schema 13、Stop 5.0.0、Proof、Work-unit、Execution 协议或共享 core v2 语义。
- `standard`/`strict` 不增加普通业务工具批准门槛，不重新索要已有自然语言授权。
- 完整性损坏、来源失效、私有控制错误、证据冲突、作用域错误保持原有 fail-closed/unknown 行为。
- observed 不等于 completed；已交付回复不等于执行证明；子任务通过不能代替父任务闭合。
- 无法确定的对象仍是 unknown/legacy_fallback；不得通过缩小必需项目、丢弃旧约束或截断计算来获得性能通过。
- Hook 不调用模型、不引入网络、不新增后台常驻进程。
- 现有已消费版本缓存不可修改；不能在原始事故会话上重放写入、删除锁或“修复”诊断证据。

### 1.2 本次不做

不以单纯延长 timeout、关闭 Stop、绕过完整性检查、减少证据覆盖或过滤某种回复措辞作为修复。不为绕过失败而重写语义分类器、不改变锁协议、不自动清理历史缓存、不移植 DSH 实现、不调整宿主权限和信任设置。历史错误库若暴露当前已接受契约的真实违例，本版必须补齐相应修复及回归；不能以“与性能无关”为由漏验。若修复确实需要改变权威/协议/锁契约，应提出最小反例和设计偏差供协调者决策，不能夹带语义改动或自行豁免验收。

版本升级、双语变更记录和必要的版本状态同步属于候选源码工作；安装到日常 HOME、启动或重启用户宿主、提交推送、标记版本与发布由用户后续实际授权决定。没有某个平台不妨碍交回源码，但该平台验收必须标记 pending。

## 2. 已知事实与不确定性

| 事实 | 已核查边界 | 不可推导的结论 |
| --- | --- | --- |
| 事故 UI 显示 194 次 Hook、0 次阻止、1 次未成功，失败项为 Stop | 用户提供截图 | 截图未展开宿主 timeout 字段，不能声称直接读到了该字段 |
| 最后回复至 turn 完成约 10.976 秒；残留锁且无对应 Stop 决策 | 本机持久化记录只读检查 | 不能仅凭残留锁认定锁竞争或状态损坏 |
| 隔离副本重构 Stop 输入，未带残留锁，11.951 秒后退出 0、返回空 JSON、无 stderr | macOS，已安装 0.14.2；运行文件与检查基线相同；原始状态摘要前后不变 | 不是原始宿主 payload 捕获；不能称为新版本原生验收 |
| 单独 cProfile 重放约 25.248 秒 | 定位热点；含 profiler 开销 | 不得把 25.248 秒当作原始钩子的真实耗时 |
| 旧 Windows 原生 r24 曾有 SessionStart/Stop 10 秒超时 | [本地验收历史](LOCAL_ACCEPTANCE.md)，2026-09-24 的 `5a85faba7c4247e63eb09afda7938638233421fc` | 同类性能故障，不证明历史调用栈与本次完全相同 |
| `c1382bb927c37c0a7d01245853874ebee10b567c` 已优化单次 feedback 内 scope 重用 | 同上，233 次投影降至一次的合成对照 | 未覆盖整个 Stop；既有 Windows compaction/Stop 历史仍未闭合 |

现有证据确认一个可重现的超时风险，且足以高置信解释本次 UI 失败。计划将“已证实的性能缺陷”和“宿主终止原因的推断”分开，不把后者补写为已捕获事实。

事故形状：12 条 prompt 元数据、12 个 requirement、98 个 acceptance item、200 条保留 evidence、3 个 work unit；没有 root control 或 wait condition。数字仅用于合成负载设计，不携带原始正文、会话 ID 或机器路径。

性能采样中主要调用数：

| 函数 | 次数 |
| --- | ---: |
| `_current_action_basis` | 1,455 |
| `current_scope_projection` | 736 |
| `read_prompt_record` | 10,502 |
| `cg_instruction.fragments` | 213,691 |

## 3. 根因模型与代码地图

以下符号比行号稳定，执行入口应按当前源码重新定位。

| 位置 | 当前作用及风险 | 计划处理 |
| --- | --- | --- |
| `scripts/context_guard.py::handle_stop` | 分类、反馈、control、delivery、闭合及保存串联，单个辅助函数的速度不能代表全路径 | 画出实际读取/写入顺序，建立事件内可复用视图和明确的变更边界 |
| `remaining_action_facts` → `_live_current_action_bases` | 按 scoped item × action category 调用依据计算 | 共享同代 scope、根记录、索引及纯解析结果 |
| `_current_action_basis` | 未提供复用参数时重复构造 scope/根记录；相同原文反复切片 | 保留所有过滤与标志语义；拆分纯输入准备与针对 item/category 的决策 |
| `current_core_projections` | 已重用根记录/scope，仍有 item/category 级重复词法工作 | 接入同一纯解析层；不可只补另一套局部缓存 |
| `current_root_control_projection` | 必须验证完整控制目录及接收时绑定 | 覆盖有 control 的测试；不因事故中没有 control 而跳过 |
| `record_delivery` / `finish` | 可能重新分类，修改交付、完成状态并保存 | 建立复用前提；变化后重算，不盲目删除第二次分类 |
| `scripts/cg_instruction.py` | fragments、instruction_text、action_search 反复构造相同视图 | 复用纯词法视图，保持字符/UTF-8 坐标与歧义处理 |
| `recovery_packet`、SessionStart、PreCompact、status/diagnose | 共享投影和解析函数 | 做影响范围回归；历史超时不能因 Stop 修复自动宣告解决 |

主要故障族是“完整 Hook 内重复准备相同语义输入”。应以调用图、数据来源和真实 profile 收敛，而不是针对一条中文回复增加快速放行分支。

## 4. 推荐设计

### 4.1 事件内读取上下文

引入私有、显式传参的 `EvaluationContext`（名称可调整），其生命周期限定在一次顶层计算的一个稳定状态阶段。可放在现有模块或小型 stdlib 模块中，避免为了性能优化进行广泛文件拆分。

建议内容：

1. 当前 session/work unit、输入状态版本及不可变源身份；这些是复用条件，不是授权凭证。
2. 本阶段唯一 scope 投影；prompt、item、unit、evidence 的索引。
3. 已验证根记录及依赖集合；每条根正文对应的词法片段、masked instruction view、原文 clause/span 索引。
4. 纯计算结果 memo；必须将相关参数及其语义标志纳入键。
5. 仅供测试/基准的计数器；默认生产路径不写性能日志或正文。

禁止模块级无界缓存、跨事件 LRU、按 session ID 或 mtime 单独命中的缓存，以及将新的 memo 写入产品状态。公开函数保留现有调用方式；未传 context 时创建一次性上下文，不能隐式复用另一事件的数据。

### 4.2 三类结果分别处理

| 类别 | 可以复用什么 | 必须重新验证什么 |
| --- | --- | --- |
| 纯词法 | 完全相同字符串的 fragments、masked view、clause 切分 | 原文变化必须产生新值；不得以截断文本或对象 ID 代替相同正文 |
| 已验证不可变根记录 | 单次稳定读取内的记录及解析 | 目录成员、文件替换/缺失/篡改、源摘要/绑定变化；接受结论前核查所依赖来源 |
| 状态/外部事实 | 同代不可变状态快照的纯投影 | state 变更、proof/review 变化、文件/Git/Host 事实变化；不能用缓存替代原有新鲜度和 TOCTOU 检查 |

默认只 memo 纯词法与纯投影。含文件系统、Git、Host、review sidecar 读取或有状态副作用的完整 action basis 不得直接 memo；先审计并分离其依赖，才能重用其中纯部分。不能用整个 state 的每次深复制/哈希替代设计问题，导致新的热循环。

### 4.3 明确状态阶段与失效

实施第一步列出 Stop 内所有潜在写入：delivery 记录、ordinary result retire、checkpoint 应用、续行计数、decision log 和最终保存，以及 helper 中隐藏的修改。

- 每个稳定阶段持有只读 view；只有真正影响依赖的修改才开启下一阶段。
- 在所有影响纯投影的写入之后，显式废弃旧 context。不能仅依赖一个不覆盖所有字段的现有序号。
- 对 delivery 前后的分类建立参数/依赖对照。完全相同才重用；不同则保留独立计算。
- 同代结果返回不可变值或防御性副本，防止一个调用者污染另一个调用者的缓存。
- 复用来源验证不等于永久信任。为根目录/记录建立稳定读取和消费前复核；发现变化使用现有 unknown/完整性失败路径，不从旧值完成任务。
- 不能在已经保存了完成结果之后才检查依赖是否变化。需要回滚语义或新事务协议时，应先停止扩展设计范围并说明，不以局部补丁伪装成纯性能修复。
- 不缓存 final allow/block 结果，也不跳过预算、作用域、私有控制与完整性检查。

测试必须同时覆盖“同一状态重复读取能复用”和“同一对象被原地修改后必须失效”，包括 source_seq 不变但参与判断字段发生变化的反例。

### 4.4 词法复用保持精确语义

原始字符串和 UTF-8 span 仍是权威。不能对原文做空白折叠、大小写折叠、NFC 归一化、路径规范化或翻译后再做缓存键。路径中的 `test`、`review`、`commit` 不得获得动作语义；引号、代码围栏、CJK 相邻文件名和 ambiguous object 保持原行为。

推荐一个只读 parsed-text 对象提供 fragments、两种 preserve_newlines 视图及 clause/span 索引。action pattern 的匹配使用这个视图，pattern/flags 和选项完整区分。现有 `action_search` 构造全部 matches 后取第一个是可检查的局部优化点，但只有证明与旧函数完全等价才替换，不能靠它代替全路径修复。

内存限制按“不同原文总字节 + 派生片段/索引开销”设界。缓存满后不再纳入新项或使用原有计算路径，不能漏掉条件或返回 fabricated success。只保存本次实际需要的输入；不预展开所有组合的巨大结果表。

### 4.5 保留锁和错误语义

保持现有会话锁和跨平台入口。事故重放无锁仍慢，优先修复计算放大。不得改 stale-lock 年龄、擅自删除其他进程锁或以减少锁覆盖隐藏数据竞争。

异常路径仍释放本次获取的锁；进程被宿主强制终止可能留下锁，本计划不许承诺完全消除所有残留锁。新增测试可以验证现有恢复语义，但任何锁协议修复需要独立理由和覆盖。

## 5. 工作包与依赖顺序

| 工作包 | 具体任务 | 退出标准 |
| --- | --- | --- |
| SP-01 基线与复现 | 确认 base/dirty、版本、解释器；读取仓库契约；保存源码/运行树身份；建立合成事故形状及完整 Stop 基准 | 旧版能展示高调用数或同类耗时放大；不得将宿主速度差异误作未复现 |
| SP-02 输入准备 | 纯词法视图、根/item/evidence 索引、同代 scope；维持旧 API | 纯函数差分、对象/引号/UTF-8 回归通过 |
| SP-03 Stop 集成 | live action、feedback、control、delivery 走可复用视图；写入边界失效 | 全 Stop 正/负/对抗用例通过；重复准备计数达到门槛 |
| SP-04 故障族与历史库闭合 | 1×/2×/4×、共享入口、T01–T20，以及完整历史库逐案映射、执行和补修 | 全部源码案例有真实断言和结果；平台依赖单列，不能丢失历史条目 |
| SP-05 候选文档与版本 | 新版本、双语变更记录、兼容/架构/隐私说明、验证映射 | 未发布状态一致；无无证据的 native/历史闭合宣称 |
| SP-06 冻结与验收 | 完整源码门槛、隔离安装、宿主前置检查；随后实际获授权的平台验收 | 每项有 exact-subject 证据或准确 pending；运行树改变后不沿用旧原生结果 |
| SP-07 交回 | 窄 diff、复现与测试、性能数据、版本/摘要、未完成项和下一步 | 协调者可独立重跑及审查；不以提交或测试数量代替结论 |

SP-02/SP-03 可以小步交错，但不要每次局部修复就运行全矩阵或创建新“正式候选”。第二个同族反例出现时，先补齐输入家族矩阵，再冻结。目标是一次完整候选验证；新失败引起的输入变化例外。

## 6. 复现与基准设计

### 6.1 公共合成夹具

由确定性 generator 构建合法、通过现有完整性校验的状态和 prompt records，优先复用真实 UserPromptSubmit/PostToolUse/Stop 测试构造路径。不能只填数值计数或关闭 verifier。状态填充可放在计时区外；计时必须包含完整 Hook 入口、加载、锁、判断、保存与清理。

建议新增 `tests/test_stop_performance.py`、`tests/test_evaluation_context.py` 及 `tools/validation/benchmark_stop.py`，名称可按项目约定调整。新增验证工具进入 `validation-map.json` 的正确覆盖；不要把基准辅助依赖装进 Hook 运行时。

夹具至少包括：

- S0：短会话小样本，用于无回归对照。
- S1：事故形状（12 roots、110 总项目、200 retained evidence、3 units），普通待外部修复/部分审核回复；必须明确 scoped/historical/ancestor 分布。
- S2：S1 的项目数 2 倍，根文本长度和 evidence 数先固定，以隔离项目规模影响。
- S4：项目数 4 倍，同样固定其他输入；独立一组再增加 roots/text/evidence，测不同维度。
- LX：等量项目来自少数长根正文，含引用、代码、Unicode、路径对象及执行子句，捕获重复词法放大。
- CT：有显式持续执行、暂停、exact marker、supersession、祖先约束及多个候选动作。
- EV：成功/失败/unknown/重复或冲突 evidence、缺失 proof、合法 proof、review 信息闭合及 execution 仍 pending。

如果产品已有 evidence 保留上限，generator 应遵守它并模拟真实保留行为；不得生成实际上不可加载的“4 倍证据”。报告真实 root/item/scoped/evidence/原文字节数和输入摘要。

### 6.2 差分比较

同一夹具、同一解释器/环境分别运行不可变旧基线和候选，使用不同临时数据目录，不能反复污染同一个状态后宣称输入相同。

比较外部返回、decision outcome/reasons、可见反馈、scope/等待/交付/完成语义、状态变更集合、提示完整性和后续事件行为。仅显式列出的时间戳、临时根位置等非语义字段可归一化；保留 ID 关系、事件顺序、摘要绑定、reason codes 和拒绝行为。状态 `content_hash` 因非确定时间字段变化时，不直接要求原 hash 相等，但双方必须各自通过完整性验证。

旧实现自身不正确的语义不能借差分固定为新规范。历史库所要求的当前契约违例必须修复，并以已接受契约建立正确 oracle；其他不影响本次义务的新议题单独记录。不静默改变 oracle。

### 6.3 计时规则和性能门槛

以下是本计划提出的验收门槛，不是当前已达成结果。两平台分别记录机器/OS、Python、Codex、基线/候选摘要、负载、并发压力、计时方式和全部失败尝试。profiler 与正式耗时分开。

- 每个正式计时样本启动新 Hook 进程和 fresh fixture clone，记录 wall time；区分进程冷启动与无法保证的 OS 文件缓存冷状态。
- 完整采样保存 20 个测量值；可先运行 3 个诊断样本。p95 使用 nearest-rank；不能把 3 个样本称为稳定 p95。
- S1：median ≤ 2 秒、p95 ≤ 3 秒、max ≤ 5 秒；且 median 至少比同机旧基线降低 70%。
- S4：p95 < 8 秒，max < 10 秒；任何真实 Hook timeout 都是失败，不能删除该样本。
- 固定其他维度的 S2→S4 median 增长比目标 ≤ 2.8；不将合并增加 roots、items、text、evidence 的实验误解为单变量线性测试。
- S0 不得出现显著倒退：median 增量 ≤ max(旧 median 的 20%, 50 毫秒)。
- 若受限/高负载宿主无法可靠计时，记录环境不满足并保持性能验收 pending；不能事后修改阈值或剔除失败样本来“通过”。

共享 CI 不使用紧 wall-clock 阈值作为唯一回归测试。CI 使用确定性工作量门槛；专用零模型平台批次和真实宿主记录 wall time。基准工具应区分 `passed`、`failed`、`environment_unavailable`，环境不可用不能 exit 0 并标记 pass。

### 6.4 确定性工作量门槛

令 P 为被依赖的不同根记录，I 为 scoped items，C 为动作类别，B 为真正因相关状态修改产生的稳定阶段数，T 为不同原文/子句集合。

- 无状态语义修改的普通 Stop：scope 构造目标不超过 4 次（包括必要的收尾独立检查），不能随着 I×C 成比例增长。
- 根记录读取/认证最多为每阶段的一次初始读取和一次消费前复核，即原则上 ≤ 2×B×P 加明确列出的独立安全读取；例外逐项说明且不能来自 category 热循环。
- 相同原文/选项的词法切分在稳定阶段最多一次；记录 cache miss 的真实执行数，而非只统计包装函数进入次数。
- 相同纯 action-basis 子问题键在一个阶段至多求值一次；键包含所有语义选项，不允许为了计数好看合并不同问题。
- 无状态修改的 S1 相比旧版 fragments 实际构造与根记录读取至少减少 90%；同时使用上面的绝对/结构约束，避免只设宽松比例。
- CT/EV 的 B 必须由真实写入边界解释。不能每个 item 开启一代使公式形式上通过。
- 统计存储条目及引用的原文总字节；连续新事件结束后不能保留上一事件缓存。使用 tracemalloc 观察至少 50 次顺序事件的存活分配，区分 Python 分配器保留和仍可达缓存。

计数器只用于诊断与测试，不得计入用户任务执行证据。必要安全复核不能因计数预算被跳过；超预算应修复结构或公开说明未达标。

### 6.5 完整历史错误库硬门槛

本版同时承担“修复本次性能问题”和“历史错误库全过”。后者不是可选质量加分，也不是只跑几个精选反例。“历史错误库”一律指 `context-guard-effectiveness`。本次 intake 后，该仓库 `benchmarks/incidents/cases/` 有 52 条记录、41 个 active case，包含新增 `CGI-20260928-codex-stop-performance-timeout`。原始记录数、supersession 后 active 数、产品适用数及实际执行数必须分别报告；旧本机来源库的 29 条不是本版验收分母。执行入口按 `AGENTS.md`、`docs/INCIDENT_WORKFLOW.md` 读取当前 registry、冻结 legacy 谱系与关联索引，消除身份重复并绑定逐文件摘要。若新增记录，保留已有结果并加入新增项，不能沿用更小的分母。

开发 Harness 的职责：

1. 读取 `context-guard-effectiveness` 的完整 case registry、有效 supersession 关系、冻结 legacy 谱系及 source references；生成一份冻结清单和逐案覆盖表，保留原始记录 ID。不要使用产品仓库 public fixtures、旧本机 archive 或旧 26/28/29-case 表替代完整清单。该库同时包含 Codex/DSH；逐案写明当前产品适用性及不变量映射，由协调者复核，不能自行删去 DSH 来源的通用语义反例，也不能把 DSH 的通过结果移作 Codex 证据。
2. 将每个历史案例映射到当前产品仍必须保持的具体不变量、真实触发序列、输入、可观察输出与断言。对完整链路案例，必须复现相应 Stop/compact/resume、授权延续、丢失编辑 provenance 等链路；单次函数、普通首次启动或配置存在不能代替。
3. 对已经被版本化契约明确替代的旧行为，保留 original 与 current 两栏，说明替代依据，执行当前不变量的正/负验证并由协调者复核。不能恢复已移除的默认工具审批；仅标 not_applicable/retired/analogue_only 或写“设计不同”不算通过。
4. 对源证据不足的案例主动补齐可证实的重现条件。旧报告中的 unknown、documented_only、缺失宿主链以及上一版本获准放宽的条目仍在本版清单；未解决前标 pending，不得改名、删除或排除后报全过。
5. macOS 上先执行所有可移植源码和本机案例，包含本次完整 Stop 性能回归。为每案关联候选源码/运行树、fixture 摘要、测试函数及断言、实际命令、原始结果和反例。
6. 需要 Windows OS 或真实宿主才能成立的断言单列，由开发 Harness 提供同一候选的精确输入、命令和期望；协调者组织 Windows 线程执行并回读结果。开发侧不能完成该子门槛不影响交回，但不允许将其标成已通过。

历史覆盖表至少包含：`incident_id`、原始记录摘要、当前契约依据、触发/状态转换序列、正例/反例、test locator、candidate identity、source_result、macos_result、windows_result、evidence locator、missing evidence、owner、final verdict。无要求的平台可明确“不要求”，但不能把案例本身标 N/A 计作通过。

`CGI-20260928-codex-stop-performance-timeout` 必须使用 full Hook process 重放及性能门槛；旧 `scripts/incident_corpus.py benchmark` 主要验证文本/协议 fixture，不能证明本次性能故障或原生生命周期闭合。它可以作为必要子集执行，不能作为全库验收的唯一入口。若现有 tooling 缺少统一逐案 runner/coverage validator，开发 Harness 补充测试/验证层入口，要求拒绝漏项、重复项、空断言、缺少候选绑定，以及把 skipped/unknown 当 pass 的报告。

本版“历史库全过”的判定：冻结清单逐案全部为经证据支持的 `passed`，相关平台子门槛全部满足，failed/pending/unknown/unmapped/skipped-required 均为零。仅 source 全过而 Windows pending 时，报告“历史库源码回归通过，平台验收未闭合”，不得用任何仅源码的 N/N 数字报告“全库全过”。真实反例按家族修复后重跑受影响组；最终必须有一份完整清单的结果，不靠分散摘要猜测覆盖率。

canonical registry 清单以 `context-guard-effectiveness` 为准；私有现场来源仅通过该库 Git 忽略的本地 mapping 在同机定位。不提交原始库、会话、截图或机密路径。公共仓库只新增经过隐私审查的合成夹具、测试映射和匿名结果说明。未获得全库访问时，将 intake 访问标成依赖，不用公共子集假装完成。

## 7. 正向、负向和对抗测试矩阵

| ID | 输入/扰动 | 必须观察 |
| --- | --- | --- |
| T01 | 同一稳定状态连续两次纯投影 | 输出相同，状态不变，重复解析减少 |
| T02 | 同一 state 对象原地改变 active unit、status、evidence、wait | 旧 view 不可复用，结果反映变化 |
| T03 | root 正文变化但 session/turn/长度相同；mtime 伪装 | 原字节身份变化被发现，不能命中旧结果 |
| T04 | 初始化后替换/删除/损坏 prompt 或 companion | 不从缓存完成任务，保留完整性/unknown 边界 |
| T05 | 新增目录成员、冲突根目录清单 | 完整 catalog 验证仍有效，不收缩范围 |
| T06 | 符号链接/越界路径；Windows stat provider 差异 | 保持现有路径与稳定读取契约；能力 skip 明确 |
| T07 | 未完成工作回复、真实等待、纯信息回复、合法完成 | 外部输出、闭合和交付各自符合旧契约 |
| T08 | 真实缺少证据却宣称完成，明确持续执行却停止 | 仍产生应有纠正，最多一次的预算不变 |
| T09 | observed edit + 未运行 test；child pass + parent pending | 不误闭合、不重复要求已证明的 edit |
| T10 | proof/review 存在、缺失、损坏、过期、撤销、来源变化 | 无 stale evidence 提升；review 不越权闭合执行 |
| T11 | current/historical/ancestor 与 supersession | 祖先约束不丢、历史不被误拉回 current |
| T12 | control catalog、exact marker、pause/resume、one-shot | 原权威和匹配条件保持，ordinary tool 不增加审批 |
| T13 | 同 session 下一事件改变正文/证据；不同 session 同 ID | 不跨事件/会话复用，含 fresh subprocess 与同进程调用 |
| T14 | cached 对象被调用者修改 | 不污染其他调用，或明确禁止并被测试检测 |
| T15 | 正常返回、内部异常、真实进程 timeout、锁冲突 | 完整入口结果/退出码/锁清理被如实记录；无伪通过 |
| T16 | 中英、Unicode span、围栏、路径动作词、歧义对象 | fragments/坐标/匹配与旧版等价，歧义仍未知 |
| T17 | action 参数组合 include_satisfied/unready/controlled、allowed IDs、reply clause | 不同语义键不混用；去重顺序/候选选择不变 |
| T18 | delivery/retire/checkpoint 改变状态后再投影 | 失效或重建正确，不能直接删掉第二次分类 |
| T19 | 缓存达到内存预算、多种长文本 | 回退后结果完整一致，无无界增长或丢项 |
| T20 | source 在最终消费前变化；外部文件/Git 事实变化 | 安全复核仍运行，旧成功不得保存为新完成 |

每个故障族至少一个正例、一个反例；关键性能回归应在旧基线上以工作量断言失败。只验证 memo 命中不够，必须通过 `dispatch`/stdin Hook 路径检查落盘状态和下一次事件。

现有重点模块包括 `tests/test_cg142_feedback.py`、`tests/test_cg142_instruction_objects.py`、`tests/test_stop_v5.py`、`tests/test_host_terminal_wire.py`、`tests/test_context_guard.py`；审计实际 import/caller 后补选 control、delivery、proof、review、recovery 所有受影响测试。

## 8. 源码、安装与原生验收

### 8.1 源码门槛

开发中先运行新复现、语义差分和 owning test modules。收敛后运行仓库要求的完整门槛；解释器用已验证环境，下面 `python`/`ruff` 指同一验证环境的工具。

```sh
# POSIX shell: stop on the first failed required command.
set -eu
python scripts/validate_public_repo.py .
python scripts/audit_public_tree.py .
python scripts/run_current_behavior_suite.py
python scripts/check_phase3_transition.py
python scripts/context_guard.py self-test
ruff check .
python -m compileall -q scripts tests tools
git diff --check
```

新增文件、测试和验证工具必须被 selector/full suite 实际发现。记录 `validation-map.json` 选择结果；unknown input 保持 full fallback。准备提交时另行检查 staged diff、identity 和 tracked-tree privacy，不能以干净 worktree 代替隐私审计。

### 8.2 隔离安装

候选版本及运行字节稳定后，使用仓库安全 installer 和新的隔离 HOME，运行首次安装、严格第二次 no-op、source/cache parity、installed smoke。精确参数从实际 `--help` 与仓库入口获得，不手抄进 live cache。版本 metadata 也在运行树摘要域内；最终版本号变化后重建身份。

验证结果放在源码 checkout 和可销毁 fixture 之外；命名不覆盖旧结果。Hook wrapper 必须实际指向候选版本，不允许 fallback 悄悄执行其他存活缓存。

### 8.3 原生验收分层

1. macOS/Windows 零模型：完整 Hook stdin 子进程、各自实际 shell wrapper、退出码、耗时、状态和锁；运行 S0/S1/S4/CT/EV。该结果是平台进程/文件系统证据，不是 Codex 宿主调度证据。
2. macOS/Windows 宿主：开发 Harness 负责 macOS 可执行部分；协调者在开发复核后负责 Windows 线程调度、输入身份核对与结果回读。获得相应执行授权且平台可用后，经正常信任加载候选，在新任务上执行长会话 Stop 正例、应纠正反例和一次后续继续。官方记录核对 Hook start/completed/exit/duration、candidate runtime、状态决策与无残留锁。保留 10 秒时限。
3. 共享恢复路径：在真实 compact/resume 上检查 SessionStart、PreCompact 的时延与恢复语义；不把手工构造 SessionStart 输入当作真实 compaction 证据。
4. 仓库现有 `tools/validation/native_acceptance.py` 版本化入口：先用实际参数 `--preflight`。若现有 profile 不能表达本次性能场景，补充一个版本化、可验证的性能附件/映射，并保留原 profile 的边界；不可把任意自制 JSON 填成已通过的 `native-acceptance/v2`。

原生准备时读取 native repair/auth lifecycle 指引。优先复用有效登录；每个协作批次最多一次交互登录，不能因 fresh HOME 或换候选重新消耗登录。不能复制凭据或信任状态来跨越边界。缺少认证/宿主能力时返回明确 pending，不静默转成合成验收。

开发 Harness 不承担 Windows 执行。开发侧完成源码、完整历史库可移植回归与 macOS 验证后，一次性交回 Windows 所需精确输入和命令；协调者负责通过跨主机线程执行并回读，必要修复回送开发侧收敛。不能把 macOS/CI 当作 Windows native pass。既有 scoped native 结果保留历史身份，不替新运行字节背书。

### 8.4 私有事故回放

公共合成夹具是跨 Harness 的主要复现材料。原始会话只在持有者本机、用户授权的范围内以隔离副本回放；缺少私有数据不阻塞其他执行者开发，不要求将状态/正文导出到公共仓库。回传只含经审查的耗时、计数、结果摘要及身份，不含原始提示词、路径或控制数据。

私有回放通过也不能代替公共回归或真实宿主验收。

## 9. 版本、文档与变更文件

建议使用 0.14.3 patch；实施前先查本地当前分支和版本。0.14.2 已发布，不能在同版本 live cache 内替换运行字节。若 0.14.3 已被占用，说明选定的后继 patch 及基线，不覆盖已有版本或改写标签。

必须一致更新 `pyproject.toml`、`uv.lock` 项目版本、`.codex-plugin/plugin.json`、实际 validator 中的版本常量，以及受版本约束的测试。保持协议常量不变，除非识别出实际协议变化并先说明。

- `CHANGELOG.md` 与 `CHANGELOG.zh-CN.md`：新版本标记 Unreleased，按 Highlights/Changes/Validation 写，说明长任务 Stop 时延修复及证据边界。
- `README.md`/`README.zh-CN.md`：仅同步必要版本/行为/升级信息，不扩写实现细节。
- `docs/ARCHITECTURE.md`：事件内复用、依赖/变更边界和失败策略。
- `docs/PRIVACY.md`：只有临时内存、不持久化正文缓存；如无持久字段变化，明确这一点。
- `docs/VERSIONING.md`/`docs/COMPATIBILITY.md`/`docs/LOCAL_ACCEPTANCE.md`：候选、实测、未做的原生与历史事故分开。
- 本计划：追加执行结果索引，不覆盖本次诊断和旧失败。计划内门槛变化需显式说明依据，不能验收后倒改目标。

新 helper 和本次 runtime 文件会改变运行树摘要；`tools/validation/` 与 tests 的单独变化不自动改变运行树，但其验证输入变化仍使对应测试证据失效。共享 core 或 conformance 若没有语义改动，不要求制造 DSH 同步提交；真的改动时按映射单独审查下游契约。

## 10. 验收清单与结果格式

| Gate | 必须交付 | 开发交回时允许状态 |
| --- | --- | --- |
| G1 复现 | 旧基线高工作量/耗时证据，合法合成夹具及生成参数 | passed/failed，不能只有描述 |
| G2 语义 | T01–T20 对应测试与差分结果，失效边界说明 | passed/failed |
| G3 性能 | 完整 Hook 样本、分位数、计数、内存与 scale 对照 | 每个平台独立 passed/failed/pending |
| GH 完整历史库 | 当前完整清单、逐案原义/当前契约映射、源码与平台结果；含 CGI-20260928-codex-stop-performance-timeout | 开发交回可有明确 Windows pending；本版最终验收必须全部 passed |
| G4 源码 | 全门槛、解释器、精确源码/运行树身份 | passed/failed |
| G5 候选文档 | 双语、版本、隐私、兼容与未发布状态一致 | passed/failed |
| G6 隔离安装 | first install/no-op/parity/installed smoke | passed/failed/pending，说明未执行原因 |
| G7 原生 | 两平台分别官方 Hook 记录、Stop/continuation/compact 证据 | passed/failed/pending，不能用 CI 替代 |
| G8 独立审核 | 协调者对 diff、证据和故障族的复核 | 由协调者完成 |
| G9 发布/日常安装 | 授权后的 CI/HOL/tag/release/readback/consumer | 本开发交接 out of scope |

开发完成交回不等于新版本已发布。G1–G5 通过、GH 的源码/本机部分逐案完成且明确列出 GH/G6/G7 的平台缺口，可提交给协调者审核；协调者完成开发复核与 Windows 跨主机验收后，只有 GH/G6/G7 的全部必需项均通过才可宣称本版验收闭合。不能把 pending 项隐藏在附注。

交回采用 Outcome / Evidence / Validation / Limitations / Next，附：

- 基线与 head 全 SHA；未提交时给 prepared-source 身份和精确 dirty scope，不能伪造 commit。
- diff 路径、版本、运行树摘要、合成输入摘要、操作完成记录。
- 旧/新耗时分布与真实计数表；profiler 仅作热点附件。
- 每条测试的入口和结果位置、failed/skipped/not_run；被修复反例及旧基线失败证据。
- 每个 context 字段、依赖、缓存键、失效点和不能缓存的读取清单。
- 安装和原生验证的独立结果；未执行项、负责者、恢复条件。
- 完整历史库清单与逐案回归表，Windows 待办包，以及一份验证通过的 `agent-handoff/v1` 结果；原始私有证据留在所属本机。

不要把尚未执行的阶段写成勾选完成，不自动提交、推送、发布或启动用户宿主。取得新的明确授权后只推进对应动作，不重新询问已经包含在那次授权中的普通实现和检查。

## 11. 审核重点与停止扩展条件

审核首先看安全语义是否保持，其次看完整 Stop 的真实工作量，最后看发布/安装身份。拒绝以下“修复”：用全局 memo 隐藏源变化、只运行小型 feedback benchmark、增加 timeout 掩盖增长、截断项目后允许完成、跳过 proof/review/根目录完整性、把手写状态当 native 结果。

如果达到门槛需要修改状态 schema、权威/完成协议、锁协议或跨仓库共享语义，执行者应先交回最小反例、测量和设计偏差；继续完成不受影响的工作，等待该范围的决策。普通实现细节（内部类型名、测试文件拆分、纯函数局部组织）由执行者自行决定，无需逐项确认。


---

## 12. 执行结果索引（2026-09-28 开发侧交回；不改动上文任何诊断与旧失败记录）

本节由开发 Harness 在候选实现完成后追加；上文第 1–11 节保持原样。

- 基线与候选：基线 `aea556d8ac651b1b94c200f88108c87cf8371893`；候选为未提交 prepared source（版本 0.14.3 Unreleased，运行树摘要 `abcffa8423a56f0ccb8b2e75db29c6f12999006d42d571084f81dc0c43e9e3f5`，43 文件）。
- SP-01/02：夹具 `tools/validation/stop_performance_fixture.py`（S0/S1/S2/S4/LX/CT/EV，全部经真实 dispatch 构建）；基准 `tools/validation/benchmark_stop.py`（count/process/pretool）。旧基线复现：S1 进程内 7.138 s（profile 12.744 s：2,487 basis / 17,758 记录读取 / 97,335 fragments），20 样本进程 S1 median 5.860 s、S4 median 36.890 s。候选：S1 median 0.084 s / p95 0.108 s / max 0.268 s；S4 p95 0.262 s / max 0.439 s；计数门槛 S1/S4 passed。
- SP-03：`scripts/context_guard.py` 新增 `EvaluationContext`（内容键词法层、按阶段失效的状态投影、单次已验证记录读取/阶段、纯 (root,category) 来源过滤、不含 TOCTOU 解析的纯 basis memo、提交前消费复核 `consumed_source_changed_before_commit`）。
- SP-04：T01–T20 映射于 `tests/test_evaluation_context.py`、`tests/test_stop_performance.py`（关键计数断言在旧基线 12 项失败）；旧/新归一化差分 9/9 场景一致（恢复包仅存 checkout 路径长度打包噪声，已归一化并记录）。
- 历史错误库（验收范围更新后唯一指 `context-guard-effectiveness` @ `16fc0a8d`）：逐案矩阵 `tests/fixtures/incidents/historical_case_coverage.json`（schema v2，55+16 行）与校验器 `scripts/check_incident_coverage.py`。52 条 active 裁定：31 executed_pass、15 DSH analogue_only（仅 Codex 侧共享语义）、6 pending（全部为原生 Windows 证据：043/044/045、压缩续行、Windows 反馈链、本性能修复的 Windows 计时）；19 条 superseded 已注明承接者。本批顺带修复 040 家族的 why 疑问信息闭合（0.14.2 基线可复现其仍不闭合）。
- PreToolUse 冷启动（CGI-20260928-codex-archive-pretool-cold-start）：候选 median 0.173 s / max 0.180 s vs 基线 0.164 s（同机 20 样本，解释器/导入主导；无本版新门槛，50 ms 旧门槛保持退役）。
- SP-05：0.14.3 版本号、双语 CHANGELOG（Unreleased）、README 双语候选段、ARCHITECTURE/PRIVACY/VERSIONING/COMPATIBILITY/LOCAL_ACCEPTANCE、validation-map 已同步；VERSIONING 中 0.14.2 遗留的 Unreleased 标注已按发布事实更正。
- SP-06：完整源码门槛全绿（validate/audit/behavior 1880 测试 0 失败/phase3 matches_manifest/self-test/ruff/compileall/diff --check）；最终字节上的全新隔离 HOME：首装、严格 no-op、43 文件字节 parity、SMOKE_PASS。
- SP-07：Windows 待办包与 agent-handoff/v1 交回（含全部工件 sha256）；原始私有证据留在所属本机。
- 门槛未变；本节不将任何 pending 项记为通过。


### 复审修复轮（2026-09-28，R1–R5）

- R1：Stop 入口保存事务快照；`consumed_source_changed_before_commit` 失败分支回滚全部原地业务写入（显式/自动 checkpoint、单元闭合、proof、纠正计数）后仅落盘失败决策与诊断。5 项新测试直接断言磁盘 state.json 原始字段（三种损坏模式 × 显式 checkpoint、自动 checkpoint、delivery/retirement 未提交、干净提交正控）。
- R2：why 疑问改为受限尾部解析（拒绝继续/时间连接与执行动词，尾部 ≤40 字符、无句读）；协调者两个反例恢复 0.14.2 行为（pending），纯 why 问答保留闭合收益；17 项形状表 + 交付/恢复全链回归（tests/test_information_delivery_closure.py::BoundedWhyQuestionTests）。
- R3：`benchmark_stop.py` process/pretool 改为真实 `context_guard.py hook` CLI 全进程外层计时（路径走 argv，无代码字面量；Windows unicodeescape 消除），校验退出码/stdout JSON/状态完整/无残留锁/decision log 增长，产品失败与环境缺失分类（failed vs environment_unutable）。新增 S0/S2/S4/CT/EV 与 S2→S4 增长比门槛（实测 1.243）。候选全进程：S1 median 0.425 s / p95 0.452 s / max 0.626 s；基线同机 S1 median 7.252 s / S4 median 44.563 s（failed）；S0 候选 0.340 s vs 基线 0.365 s（无倒退）。差分 v2（等长克隆 + 共用 cwd + 字段级白名单归一 + 内置负控自检）9/9 场景 match，source_sha256/subject/evidence 身份差异保持可检；旧 dispatch 级数据保留原口径不冒充。
- R4：`library_case_index.json` 升级 v3，逐条钉住库内 55+16 条记录的 title/family/runtime/status/真实承接者与记录摘要；`check_incident_coverage.py` v3 逐条身份核验 + 类-方法从属解析 + `--execute` 执行回执（52/52 行通过）；`tests/test_incident_coverage_negative_controls.py` 10 项对抗负控（换 ID/假 successor/假文件/错类属/pass 盖 pending 等）。040 链保持 Guard 开启贯穿 compact/restore 并断言恢复包内容；042 链补真实编辑观察缺失→提交观察→push→Stop→恢复与 release-lane 负控。
- R5：见本轮 agent-handoff/v1（正式 schema，经 validate_agent_handoff.py 校验通过）与可执行 Windows 待办包；运行树摘要改用仓库正式 tree_manifest 编码。`stop-performance-agent-handoff.json` 确认位于本聊天输出目录，第一轮"未找到"表述有误。

### 库清点文件核对（2026-09-28 补充）

已读 `benchmarks/incidents/local-archive-index.json`（29 条正式来源记录全部映射到脱敏案例，`legacy_relation: distinct_bytes_same_numeric_id`）与 `local-archive-reconciliation.json`（89 个业务文件、3 条辅助新案、031–039 保持草稿未提升）。程序化核对确认：29 条映射全部落在本次冻结的 55 案注册表内；89 文件引用的案例 ID 无一未知；ux10/ux11/pretool-cold-start 三条辅助案在册；数字后缀重叠（009–016）在两谱系中保持不同记录。分母口径与执行索引一致，无增量需要纳入。


### 复审第二轮修复（R1–R4 问题族闭合）

- R1：消费复核移至最终提交边界（record_delivery、delivered 投影、ordinary retirement 全部完成之后、save_state 之前）；失败恢复事件入口快照并仅落盘失败诊断。`tests/test_stop_commit_boundary.py`：4 路径（显式/自动 checkpoint、问答 delivery、ordinary retirement）× 4 注入阶段（源读取后/闭合应用后/delivery 构造中/retirement 中）× 3 损坏方式（改写/删除/等长替换）= 48 格矩阵，直接断言原始磁盘 state.json；30 格注入回滚全部通过，18 格生产不可达如实记录（retirement 阶段在现有合成形状下不被生产调用，由 reachability 测试固定该事实而非伪造）。
- R2：why 尾部改为正向受限文法（白名单描述性谓语 + 结构约束，无动词黑名单）。复审反例（顺手清理缓存/删掉缓存/重启服务）与全新未知动词（格式化/编译/迁移）全部保持 pending；纯 why 正例保留闭合；表驱动与 delivery→Stop→恢复全链回归通过。
- R3：process/pretool 在 runner 层断言语义 oracle（期望 stdout、decision outcome 与 turn 绑定）；fail_closed/block JSON、未增日志、错 turn 一律 failed。count 模式要求必需计数键存在（缺失即 failed，不默认 0）；SyntaxError 归为候选失败；`--json` 对已存在目标 exit 3 拒绝覆盖。`tests/test_benchmark_oracle.py` 9 项负控通过。
- R4：覆盖表校验采用封闭平台/源结果枚举与适用性规则（任何 failed/not_run/环境缺失不得与 executed_pass 共存）；`--execute` 展开并执行每行**全部**必需 nodeid（61 个，含多 locator 行的第二断言），回执绑定测试文件字节摘要并带陈旧防护；汇总绑定候选 prepared_source。`tests/test_incident_coverage_negative_controls.py` 扩至 17 项（平台失败提升、词表外状态、pending 无未过平台、第二 locator 必败、空收集、回执陈旧等）。
- Windows 接收包：`windows-acceptance/` 提供单命令入口（真实 native 入口 --preflight + W1/W2 oracle 计时 + W3–W7 每案专属进程重放 driver，全部经真实 hook CLI 子进程）；macOS 冒烟通过，Windows 结果待跨主机批次。不覆盖声明与工具行为一致。


### 复审第三轮修复（R4/R1/Windows 包）

- R4 结构化回执：必需 nodeid 依 pytest `-rA` 摘要归类（passed/skipped/xfailed/xpassed/failed/error/not_collected），仅 passed 记执行通过；skip/xfail/零收集即使退出码 0 也判未过。平台适用性冻结进 `library_case_index.json` 的 `windows_not_required_case_ids`（由库契约派生：非 Windows 起源案例 + 活动 legacy 行），待验证行不得自我豁免（负控覆盖 archive-043 自豁免反例）。
- R4 身份统一：默认 CLI 的 hashlib NameError 修复（模块级导入）；`prepared_source_identity()` 成为 checker/handoff/`tools/validation/acceptance_identity.py` 三方共用的规范编码（sha256 over sorted dirty paths：path+NUL+文件摘要），负控断言 checker 输出与手工重算逐字节相等。
- R1 覆盖缺口关闭：ordinary retirement 经真实 `test_host_terminal_wire` harness 链（结构化 transcript + pytest 终端摘要 + 陈述式报告回复）在 P4 路径真实到达 `retire_verified_ordinary_core_result`；矩阵 P4×S4×3 损坏全部注入并断言原始磁盘回滚。reachability 测试固定生产可达性（含 `ordinary_core_result_verified`）。
- Windows 接收包：入口脚本对每个原生命令检查 `$LASTEXITCODE` 即刻传播；执行前用 `acceptance_identity.py` 重算候选 prepared/runtime digest 并与交接身份比对（错 digest exit 3 拒绝）；秒级目录存在即拒绝；五个 driver 各自校验候选身份、拒绝已存在输出；W5 改为真实 turn + 错误 token 负控与 diagnose 正控分离。native preflight 保持 base-commit portable_runtime（其校验对象是工具与存储而非工作树；候选身份由 digest 门禁单独验证）。


### 复审第四轮修复（Windows 预检 / pytest 回执 / prepared-source 编码）

- Windows 预检：新增版本化 `tools/validation/prepared_batch_preflight.py`（schema `prepared-batch-preflight/v1`），绑定 base HEAD + 候选 prepared/runtime digest + driver 清单逐文件 SHA-256，全部重算比对；错 HEAD/digest/driver、已存在输出 fail-closed；仅认证 W 类输入准备并显式声明不冒充 portable_runtime。8 项正负控（`tests/test_prepared_batch_preflight.py`）含“portable_runtime 对未提交候选仍拒绝（clean 契约不动）”负控。PS 入口替换为该入口并保持逐步 `Assert-Exit` 传播。
- pytest 回执：`execute_receipts` 改用 JUnit XML 机器可读报告 + 非零退出码双重门——必需节点须“实际 passed 且子进程 exit 0 且无 failure/error/skipped 子节点”；teardown/setup 错误、call 失败、skip、xfail、XPASS、零收集、后续节点失败九格矩阵全部拒绝（含协调者 teardown 反例：pass 表面 + 非零退出 = 拒绝）。
- prepared-source 编码 v2（`acceptance_identity.py` 单一实现，checker 委托）：HEAD 绑定进摘要；`--porcelain=v1 -z --untracked-files=all`（新目录展开、空格/中文/引号/换行字节精确）；删除绑 `deleted`、重命名绑目的内容 + 来源 `renamed-away`、symlink 显式编码链接目标；未知文件类型拒绝而非 missing。真实临时仓库正负控 8 项（新目录内容变化改变摘要、同 dirty 集 不同 HEAD 不共享身份等）；checker/工具/独立重算三方相等断言。


### 复审第五轮修复（driver 身份链）

- driver-manifest 改为**包相对路径 + 逐文件 SHA-256** 的冻结交付文件（`prepared-batch-drivers/v1`），显式 REQUIRED 集合（PS 入口 + 五个 per-case driver）；manifest 字节与摘要跨主机一致，`--driver-package-root` 指定本机解析根。
- `prepared_batch_preflight.py` 增加完整 manifest 验证：schema、非空、必需集合完整、唯一路径、逃逸/绝对路径拒绝、逐文件 sha 重算、（可选）冻结 manifest sha 比对——空集、删项、换 manifest、篡改 driver 全部 fail-closed。
- PS 入口删除缺失 manifest 时的自签 fallback：缺 manifest 即 exit 2 不生成替代清单；`--expected-manifest-sha256` 必参。
- 交付物补齐 `driver-package-identity.json`（schema v1：manifest sha + 全部文件 sha，已逐项核对），并给出两根迁移正控与 PS 静态契约负控（无自签 fallback、冻结 sha 必参、staged manifest 完整性）。
- 运行树字节本轮未变化（runtime digest 与 r4 一致），既有 runtime/install 证据按字节同一性复用；prepared 身份因 tools/tests 变化重算。

## 协调者最终验收索引（2026-09-29）

R1–R4 修复族独立复核通过；Windows W1–W7 进程门槛及 macOS/Windows CLI 0.158.0 的 `stop_host/v1` 有界真实宿主批次已通过并由协调者重放。历史库活动行 37 executed_pass + 15 analogue_only，无 Windows pending；DSH 类比不认证 DSH。最终源码套件 2036 项、零失败、22 跳过；012 字节冻结与库红项未改。具体计时轨道、宿主边界及不可变证据摘要见 [LOCAL_ACCEPTANCE](LOCAL_ACCEPTANCE.md)。本索引不将过程内 dispatch 计时改称全进程，也不将编号输入条数改称抽取义务数。原先各轮 pending 与 prepared-source 身份保留为历史事实；发布阶段的精确提交安装、CI/HOL 与公开身份独立核验。
