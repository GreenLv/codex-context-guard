# 下一版本执行、回交与发布附录

R3 实现注记（2026-10-02）：锁与升级规范由 [修订 4](LOCK_SUBDESIGN_NEXT.md)
取代早期迁移建议。本版不支持任何 legacy 迁移，不清扫 legacy；新会话用
独立 sessions-v2，旧会话只读拒绝，N09 保持。原宿主续跑需要独立证据，
缓存保留不证明加载。性能 driver 的 formal 模式必须执行完整注册格；
诊断子集只证明所选格。本文原性能目标和原生/模型/发布门槛未削弱。


日期：2026-10-02；与[规范](DEVELOPMENT_PLAN_NEXT.md)修订 1 配套。此附录是执行契约，以下指标均为目标，未声称达到。

## 1. 工作包与退出条件

| 包 | 工作 | 必须交回 | 依赖/负责人 |
| --- | --- | --- | --- |
| WP-00 | 入口和基线 | HEAD/dirty/toolchain/runtime identity、生产调用链、九事件基线、全量历史输入摘要 | 开发者；先做零模型检查 |
| WP-01 | 锁/状态设计及反例闭合 | CGN-01/08、所有权与线性化说明、旧/新互操作和迁移方案、正式故障矩阵；协调者确认版本/契约 | 开发者提出，协调者有界审查；先于锁方案合入及制品冻结 |
| WP-02 | GPT-6 指令精简 | description/root/references/动态注入/项目规则 diff，规则承接映射、字符与真实 token 数据、普通/高级路径回归 | 可与 WP-01 独立推进；不编辑 managed 全局块 |
| WP-03 | 性能实现 | 启动去重、事件内复用、完整 memo 预算、必要 I/O 减少；每个优化有调用数/失效/成本证据 | 开发者；不得隐藏锁风险 |
| WP-04 | 整仓审查和历史库 | 全文件审查矩阵、缺陷闭合；全库逐案记录与实际运行回执、不完整例外及适用性清单 | 开发者；平台不足明确 pending |
| WP-05 | 候选收敛 | 版本/双语变更、当前架构/兼容/隐私、全源码门槛、隔离安装及完整性能表、agent-handoff/v1 | 开发者；未发布候选 |
| WP-06 | 独立复核/有限返修 | 精确 diff、已知反例、失败家族及 oracle/身份核查；只重开受影响项 | 协调者；不能仅阅读实现报告 |
| WP-07 | 双平台与模型验收 | 同一 runtime 树的 macOS/Windows install/portable/native，GPT-6 实测矩阵和历史平台行 | 协调者组织，平台执行者分别负责 |
| WP-08 | 发布与收尾 | 精确提交 full CI/HOL、annotated tag、双语 Release、公开读回、适用的 consumer/安装后续项 | 协调者；release skill 与平台权限继续适用 |

开发者先自行关闭确定性回归，遇到第二个相邻反例先补同族矩阵，不把半修复交回要求协调者逐个找下一个。WP-01 的实质契约决策需要一次有界交回；普通实现选择不需要逐项确认。若只能完成某平台，交回其实际结果和另一平台可执行包，协调者继续推进，不重复已通过且输入未变的部分。

## 2. 性能与上下文验收

### 2.1 测量协议

- 同机、同解释器/宿主、同负载生成参数，对不可变 0.14.3 基线与候选做交错 A/B；每次复制 fresh fixture，不污染下次输入。
- 3 次诊断样本仅定位问题；正式每个关键 cell 预先安排至少 20 次尝试，失败/timeout 不得补跑顶替。所有已启动尝试的 elapsed 进入分布，使用 nearest-rank p95 并报告 median/p95/max；timeout 标明耗时右删失（只知至少到达该时限），不能把该数值当真实完成时间或据此宣称性能通过。失败退出另使正确性门槛失败。启动前环境失败单列，不计成零秒；无法取得可比较计时则性能保持 pending。基线失败同样保留。
- 同时保存 core-process、production-entry、live-host 三个边界，不将旧边界阈值套在另一边界后称为对比。profiler 只诊断，计时批次关闭 profiler。
- 确定性计数在 CI 执行；精确 wall-clock/RSS 在指定本地平台批次执行，不因共享 runner 抖动改 oracle。并发负载单列，不剔除慢样本。
- 状态/输入摘要、测试与生成器摘要、所有相关工具版本、环境、exit/JUnit 和输出语义均入回执。指标采集不保留正文/命令/秘密；脱敏摘要可公开。

### 2.2 目标表

| 指标 | 接受标准 |
| --- | --- |
| 正确性 | 全部既有不变量、新增正/负/对抗回归通过；性能改善不抵消任何 failed gate。 |
| 生产进程 | stateful 事件最多一个产品 Python 计算进程；若平台必需另一进程，先证明原因并经子设计审查，不偷偷保留旧实现宣称目标达成。解释器 probe 独立计数。 |
| 普通 PreToolUse | 不新增私有状态 load/lock/write；同机 production-entry median 目标降低 ≥25%，p95 增量不超过 max(基线 10%, 50ms)。最低 SAFE 路径本已很快时不强求相对收益，但需保留无回归证据。 |
| 高频事件累计开销 | 固定 100 次普通工具生命周期脚本（Pre/Post 混合；含真实结果观察）产品累计 wall time 目标降低 ≥20%，并报告任务总时长。不能减少事件或删除有效 evidence 达标。 |
| Stop S1/S4 | 保留上版核心边界的硬上限：S1 median ≤2s、p95 ≤3s、max ≤5s；S4 p95 <8s、max <10s；S4/S2 median ≤2.8。相对已优化 0.14.3 不显著倒退：median 增量 ≤max(10%,50ms)。本版收益主看完整入口及累计开销。 |
| 九事件时限 | 无实际宿主 timeout；单 writer 无竞争的代表负载 production-entry p95 目标 ≤该事件时限一半。已有不同输入历史值不能冒充本版达标。竞争超时应有界、无状态破坏，单列为负控。 |
| Skill 与常驻注入 | Skill 根文本 bytes 和固定 tokenizer tokens（可得时）目标减少 ≥40%；普通回合动态指令目标减少 ≥50%；高级 reference 不计入常驻量但计入实际读取总量。 |
| 恢复范围 | 所有必需当前/祖先约束可直接读取或由有效分页恢复；全范围摘要一致；不得把 token 节省建立在义务丢失上。 |
| memo/内存 | 预算覆盖所有 memo，超预算退化保持同义；1×/2×/4×状态与长文本压力中证明预算有界；进程 RSS 不增加超过 max(基线 10%,16MiB)，例外先审查。 |
| 实际模型成本 | 同模型/配置固定场景的中位输入 token 目标降低 ≥20%，累计总 token 不升高且完成正确率不下降；逐项报告读取 reference、重复测试、诊断调用、人工问询和失败。小样本只支持有界验收，不宣称总体统计提升。 |

相对收益目标在 WP-00 固定输入后检查可实现性。若优化基线已经接近不可避免成本或 measurement 不可用，先报告测量/影响和有界替代目标，由协调者在正式批次前决定；不能在失败后降低门槛。真实宿主/模型耗时与本地 Hook 成本分别解释。

### 2.3 负载与测试矩阵

沿用 S0/S1/S2/S4/LX/CT/EV 夹具，增补：

| 族 | 必须覆盖 |
| --- | --- |
| P01 启动 | 九个事件、canonical/alias/malformed、JSON/Unicode 原字节、stdout/stderr/exit、Python 3.10–3.14、POSIX 与 Windows PowerShell 5.1/当前宿主。 |
| P02 快路径 | read/普通编辑/测试/commit/branch push，inactive/off/standard/strict/observe/release，损坏 release latch、opaque runner、分类异常。 |
| P03 投影 | 同内容命中、同对象原地改动、不同选项/flags、phase 写入、root/control/review/Host/文件变化、消耗前篡改及磁盘回滚。 |
| P04 预算 | 单条超长、很多唯一文本、匹配/clauses 膨胀、全部 memo、上限后直接计算、最大源目录及缺失文件。 |
| P05 恢复 | long paths/CJK/Unicode、低预算/零预算、分页过期、compact/resume、独立任务与祖先、用户纠正、全部 omitted IDs 可回取。 |
| P06 互斥 | 活 owner >30s/暂停、dead/unknown/foreign owner、PID reuse、两 contender、旧观察后 pathname 替换、同进程队列、超时/取消、acquire/write/save/release 各边界崩溃。 |
| P07 旧新兼容 | 旧→新、新→旧并发，旧任务保留、迁移时活旧 writer、源快照变更、目标失败恢复、回退和错误数据目录；无法独占必须不写。 |
| P08 生命周期 | 正常/异常退出、SessionEnd 3s、锁与 descriptor 泄漏、子进程终止、cleanup 误删活会话、安装并发/中断、archive 篡改/no-op。 |
| P09 token/行为 | 普通任务无需 status/checkpoint；高级 proof/release 可发现；已授权继续无需重复询问；侧问、等待、压缩后仍保持完整工作目标。 |
| P10 回执负控 | 错 commit/runtime/input/test node、失败 exit 但 JUnit pass、setup/teardown error、skip/xfail/XPASS/空收集、漏 case/换标题/伪 successor、不完整例外滥用。 |

锁测试用真实子进程和确定性屏障，不能只有 monkeypatch 的理想状态。mtime 老化反例可快速稳定执行；最终须验证真实暂停/kill 和生产 state append/save 的互斥。模型回归无需与全部 OS×Python 组合笛卡尔积：平台运行时门槛双平台完整执行，GPT-6 行为批次按实际支持面选择；失败定位后只重跑相关 cell。

## 3. 源码门槛与历史回执

修复阶段先跑 reproducer/owning modules，使用仓库 selector 列出 affected checks。正式候选至少运行：

```sh
python scripts/validate_public_repo.py .
python scripts/audit_public_tree.py .
python scripts/run_current_behavior_suite.py
python scripts/check_phase3_transition.py
python scripts/context_guard.py self-test
ruff check .
python -m compileall -q scripts tests tools
git diff --check
```

解释器必须已验证，validation 依赖按 CONTRIBUTING 的锁定环境安装。提交前再审查 staged paths、`git diff --cached --check`、author/committer noreply identity。没有提交授权时交回 prepared-source/full dirty scope，不伪造 commit。

历史执行复用/增强 `scripts/check_incident_coverage.py` 的真实节点/JUnit 校验。当前仅支持既有 verdict vocabulary；新增不完整例外时同步 validator、fixture schema、测试和负控，或者在独立 release adjudication 层严格验证例外，不能随意给旧表塞一个会被忽略的字段。执行报告必须绑定 candidate 源码、测试/生成器/案例摘要、平台和解释器。

避免每个 case 重跑整套 tests：先建立 case→具体断言→owning module 映射，运行去重的节点/模块一次，再将同一真实回执映射回多条 case。共享测试可证明多个同义场景，但原始差异需有自己的参数断言；不能用一个通用“测试通过”覆盖所有记录。规范要求的当前库全量覆盖必须完整；不能以去重为由减少案例。

对旧 case 的改动使用历史库支持的 supersession，不覆写原记录。私有源映射和原始日志保持在库外。开发批次可以维护本版配套脱敏案例/结果，但不改动其他任务的文件。最后历史汇总需明确：完整且适用的 required cells 全 pass；每个排除/非适用/类比都有独立理由，所有待测平台清零。

## 4. 回交格式与独立复核

使用 `agent-handoff/v1` 并运行协调 skill 的 validator；同时给出短的 Outcome / Evidence / Validation / Limitations / Next。机器路径仅放私有附单，不进入可移植 envelope。

交回材料最少包括：

1. base/head 全 SHA 或 prepared-source、完整 staged/unstaged/untracked scope、版本和 runtime-tree digest。
2. 稳定 issue ID→不变量→修复→旧失败/新通过测试；完整模块审查表，待定风险与排除理由。
3. baseline/candidate 同输入性能原始样本与汇总，三个计时边界、进程数/内存/token/工作流成本。
4. Skill 规则承接、动态普通/高级路径、恢复与分页全覆盖、实际模型/参数和无模型部分。
5. 完整历史冻结清单、逐案映射、执行/JUnit 回执、材料不完整排除及 Windows pending 包。
6. 源码/安装/native 各自证据、复用输入证明、未执行项与下一 owner。旧候选证据保留原身份。

协调者独立复现 CGN-01/02 和修复涉及的关键负控，读 exact diff/实际测试实现，不仅校验 JSON。确认失败家族闭合和版本/文档后才进入完整冻结。若有阻断，集中给出有限返修清单；下一次只复查受影响面和已登记问题。

## 5. 双平台与发布

### 5.1 同一候选的两平台验收

先运行仓库 native entrypoint 的 `--preflight`，参数必须与正式运行相同，结果放源码树及 disposable fixtures 外且路径未占用。预检只证明输入/存储就绪，不证明登录、trust、模型或原生行为。适用入口为 `tools/validation/native_acceptance.py`、`stop_host_acceptance.py` 及其版本化 profile；先按当前 `--help` 取参数，不手写成功回执。

两平台各自验证：first isolated install、strict second no-op、source/cache/runtime-tree parity、installed smoke、正常 trust 下的新任务、九 Hook 实际加载、普通工具与 release 边界、Stop 正负、合法等待、compact/resume/冷恢复、修复相关锁/取消/SessionEnd，以及历史 required native cells。source/portable/native/loaded/模型分别记录。

同一冻结 runtime 字节跨平台传递，不按平台重建不同包。非 packaged 文档或 CI 修改不自动使 runtime 证据失效；打包字节变化则重新绑定 artifact/install/native，保持未变行为证据的合法复用。native 工具变化只重验其受影响证据闭包。

认证复用已有批准的批次方式，绝不复制凭据或自动重试已失效登录。操作前按协调 skill 读 native-auth-lifecycle/native-repair-cycle；HOME 和宿主/端口各有单一 owner，预检先发现资源冲突。实际需要停宿主或额外登录时一次性给出具体已准备批次。其他项目的端口/日常 HOME 不因本任务被占用。用户将在新线程启动开发；本轮不自动创建开发聊天。跨聊天发消息需要用户明确授权，读取参考聊天无需发送。

### 5.2 发布硬门槛及顺序

所有门槛的 subject 和适用性明确后，按仓库顺序：

1. 关闭源码 P1、全历史 required cells、批准的不完整排除审查、读者文档及隐私；完成双平台精确 runtime 验收。
2. 用同一候选版本完成双语 README/CHANGELOG 和 release disclosure；发布日期替换 Unreleased，并固定最终 release commit。版本/打包元数据改变需重新核对运行树身份。
3. 按批准流程 push main；要求该精确提交的 **full** CI（3 OS×Python 3.10–3.14）与 HOL 绿。daily 或 PR summary 不替代 release full profile；已有 exact full 绿则不重复 dispatch。
4. repository-release 准备与权限检查通过后，为同一提交创建并推送 annotated tag。标签不触发重跑候选矩阵。
5. 从接受的双语 changelog 派生非 draft、非 prerelease Release；英文/中文各链接自己的 changelog。
6. 公开读回 tag target、Release metadata、实际发布正文及本地干净状态。若原授权包含 consumer pin/安装，随后走 managed adoption 并单独回报；本计划不静默修改私有消费者或日常安装。

本任务已要求协调者推动后续验收和发布；接收开发结果后继续既有授权范围，不在每阶段重复问“是否继续”。发布工具或平台要求的具体权限仍执行；不能由 handoff JSON 生成授权。未通过必要门槛不得发布，未核验 native 不得写“双平台通过”。

### 5.3 证据失效与最小重复

| 变化 | 重做 | 可保留 |
| --- | --- | --- |
| 纯文档且不在 runtime root | 文档 contract/privacy/cold read、最终 exact-commit CI/HOL | 未变 runtime 的安装/native，保持原 digest 身份 |
| runtime/Skill/Hook/manifest 字节 | affected behavior、runtime/artifact、隔离 install、相关 native/模型 | 不受影响且输入闭包相同的测试结果；不能把旧 artifact 当新 |
| 历史 case/oracle/fixture/工具 | 对应案例与回执、分母/闭包、相关模型或平台 | 未变案例的原 subject 证据，附复用论证 |
| 新反例 | 对应不变量家族和受影响 gate | 无关已接受功能 |
| 仅 tag 创建 | tag/public readback | 精确提交 CI、源码、制品和 native |

维护一张短状态表：subject、已接受证据、剩余 gate、owner、blocker、next/resume event。开发交回后由协调者推进复核；真正等待外部开发/平台时明确恢复事件。不能因一个阶段结束而丢失总目标。
