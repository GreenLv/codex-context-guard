# 更新日志

[English](CHANGELOG.md)

以下版本从新到旧排列，未发布候选会明确标注。`0.10.0` 是当前最新正式版本，实现基线为提交 `e4fccf690bcbc2be79d0b8d42a1a269f87072120`。Schema 和协议的完整历史见[版本策略](docs/VERSIONING.md)，测试过程与平台边界见[本地验收记录](docs/LOCAL_ACCEPTANCE.md)。

## 0.10.0 - 2026-09-03

### 重点

- 否定句或引文中对物理对象的描述不再被误记为要求。用户确实要求核对对象物理身份时，Context Guard 仍会要求对应证据。
- 证据必须证明用户实际要求的操作。读取成功不能替代写入要求，一个具体操作的证明也不能关掉另一个操作。
- 如果 Context Guard 无法判断用户要求的操作，它会保留待办，不会直接丢弃。`clear-pending` 只清除这些尚未判定的操作，不删除需求或证据。

### 变更

- Schema 8 从非否定条款推导强制执行的 `(operation, subjectId, requestedSurface)` 合同。证据会记录 adapter manifest 版本；具体操作或 manifest 不一致时，证明会失败关闭。
- Schema 7 继续作为只读兼容输入，并用新的私有控制状态确定性升级。提示词、压缩、恢复、分叉、子代理、需求替代和证据重放的既有优先级不变。

### 验证

- 精确候选已通过本地完整源码套件，以及包含 12 项 Ubuntu、macOS 和 Windows 任务的 CI 矩阵；具体身份和测试数量见[本地验收记录](docs/LOCAL_ACCEPTANCE.md)。
- macOS 和 Windows 分别对同一运行时树通过了原生安装、重复安装/no-op、字节一致性、自检和 lifecycle 检查。Context Guard 从源码 tag 安装，不另行发布独立软件包；公开读回仍是独立门禁。

## 各版本主要保护什么

- **0.9.x——结束任务前必须有完整且当前有效的证据：** 0.9.4 规定只有覆盖全部要求且通过验证的 checkpoint 才能确认完成，并保证中文等非 ASCII Hook 输入不被破坏。0.9.5 会自动准备常规文件和文字证据，减少 UI 措辞误判，并拒绝绑定到错误任务或路径的证据。
- **0.8.x——分清用户要求、Skill 和模型计划各自能决定什么：** 用户决定任务目标和写入授权；已采用的 `AGENTS.md` 或 Skill 规定工作流程；Codex Plan 只是可以调整的执行安排；工具、文件、图片和公开读回提供事实证据。0.8.3 会记录这些来源和可选计划绑定，来源变化时要求重新确认，但不会因此增加授权或拦截工具。
- **0.7.x——把证据绑定到需要验证的对象：** 检查证据是否对应正确的需求、文件或页面以及完整范围；同时加入图片等多模态输入保护，只保存哈希和必要元数据。用户要求修改图片时，还要检查修改后的图片，不能只凭“工具运行成功”判定完成。
- **0.6.x——把“任务已经完成”和“这一回合可以先停下”分开：** 只有通过检查的完成 checkpoint 才能把任务标为完成；等待用户、等待外部结果或明确延期时可以结束当前回合，同时保留未完成要求。`0.6.0` 首次实现这套机制但没有发布，`0.6.1` 是该系列第一个正式版本。
- **0.5.x——说明为什么拦截，并让升级可恢复：** 用户和维护者可以查看一次回复为什么被允许或阻止；旧版 Hook 会按原始内容存档，缓存损坏时可以从可信副本恢复。
- **0.4.x——记住用户交代的任务：** 在上下文压缩和恢复后保留用户输入、需求、后续修正、委派工作和未完成的验收项；只要用户要求的工作仍未完成，就不能报告整个任务已经结束。

## 0.9.5 - 2026-09-01

### 重点

- Context Guard 会在 checkpoint 检查时从私有检查表生成常规非视觉证明，Agent 不再需要为普通文件或文字结果单独写 proof JSON。图片检查、UI 回读和无法精确核对的情况仍使用显式 `register-proof` 路径。
- UI 相关措辞的判断更窄，普通的“列表”或“可见文字”不再触发无关 UI 检查；明确要求查看或操作 UI 时仍会检查。
- Codex 任务、文件和 Windows 路径的证据必须来自对目标本身的实际读取。只打开界面或回显路径不算证据，不支持的 Windows 路径会被明确拒绝。

### 变更

- 只有实际读取目标才算证据。已登记的读取工具和简单只读 shell 命令可以提供证据；回显路径、无关输出或额外读取其他对象都会被拒绝。
- 证明创建与 checkpoint 保存为一个整体。检查失败不会留下半条证明，调用方也不能增加对象或扩大范围。
- UI 能力只来自宿主提供的已验证信息或精确工具名单，不再根据工具名称或输出文字猜测。
- 拒绝消息会说明需要什么结果、现有哪些证据以及绑定哪里不匹配。schema 7、既有协议、Python 3.10 支持、已保存会话状态和隐私规则均不变。

### 验证

- macOS 通过 343 项源码测试（9 项按能力跳过）、隔离与日常受管安装、严格重复安装/no-op、安装态 lifecycle smoke、17 文件产品一致性和全新可信 Hook 任务。Windows 独立通过原生源码、隔离安装/no-op/一致性和全新可信 Hook 门禁。
- 只改文档的发布提交已通过 main 与 tag 的 12 项 CI 矩阵，同一提交也通过 main 分支 HOL 扫描。注释 tag `v0.9.5` 和非预发布的双语 GitHub Release 均已完成公开读回；下游采用仍是独立的 consumer 门禁，详见[本地验收记录](docs/LOCAL_ACCEPTANCE.md)。

## 0.9.4 - 2026-08-28

### 重点

- Hook payload 现在显式按 UTF-8 解码 stdin，中文等非 ASCII prompt 与回复可在日志中按字节精确保存，非法字节会被可见地拒绝。
- Stop protocol 2.0.0 规定：只有经过认证且覆盖完整的 checkpoint 才能把任务标为完成；fail-closed 门禁和 typed wait 继续保护未解决事项。
- 标准库事故库和人工复核的公开 fixture，为协议回归（包括 Windows ACL 行为）提供可复现证据。

### 变更

- `Stop`/`UserPromptSubmit` 入口读取原始 stdin 字节并独立按 UTF-8 解码。八 Hook wire、schema 7、classifier 2.3.2、Proof/Execution protocol 1.0.0 和 Python 3.10+ 支持均不变；已安装缓存保持不可变。
- Classifier 2.3.2 只把 `observed_outcome` 写入诊断；`protocol_default` 和 `protocol_user_persistence` 才是权威来源。加载 Stop 1.1 状态时丢弃进行中的旧 control，同时保留 requirements、evidence、proof 和 decision history。
- `scripts/incident_corpus.py` 仅使用标准库，提供 `ingest`、`validate`、`summarize`、`benchmark` 和 `export-public`；公开 CI 只读取人工复核的脱敏 fixture，不访问私有事故库。
- 受管 staging 排除本地环境、测试/lint 缓存和构建输出。事故数据继续使用精确的 POSIX 权限或受保护的 Windows DACL（仅当前用户、`SYSTEM` 和 Administrators），写入与验证失败仍 fail closed，标准用户不需要 `SeSecurityPrivilege`。

### 验证

- 固定公开 manifest 包含八类根因的八条复核 fixture。不可变的 0.8.12 runtime 复现两次错误续跑；0.9 候选为零，并通过八条权威结果预期，diagnostic accuracy 单独统计为 1.0。
- 原生 Windows 和 macOS 分别通过源码/隐私门禁、233 项测试、Hook self-test、受管安装/no-op/parity/lifecycle 检查和 fresh-Hook 运行；各平台 skip 与详细证据保留在[本地验收记录](docs/LOCAL_ACCEPTANCE.md)。CI、tag CI、双语 GitHub Release 和未认证公开回读均已通过。

## 0.8.12 - 2026-08-27

### 重点

- Stop 不再把被标注为一类声明的完成短语（例如 `“任务已完成”类声明`）误当成助手对整个当前任务的完成声明。
- 独立引用式声明和第一人称明确确认等直接完成声明仍会被拦截。
- Schema 7、Proof、Stop 与 Execution 协议、Python 3.10+ 要求和八个 Hook 事件均未改变。

### 变更

- Classifier 2.3.2 识别引号内完成短语之后受限的中文元讨论后缀，不会放宽所有带引号完成语句的处理。
- 已安装 Hook runtime 字节不可变，因此插件版本前进；已发布的 0.8.11 缓存保持不变。

### 验证

- 定向源码回归重放了本次 Stop 决策，并保留中文直接完成声明。macOS 已通过仓库与隐私检查、219 项测试（含 5 项能力性 skip）、八 Hook 自检、Ruff、外部缓存编译和 `git diff --check`。
- 精确候选 `c66ac824f0d9d2015f1725417a2e50f5a96f31da` 在原生 macOS 和 Windows 上均通过受管安装、严格重复安装/no-op 读回、安装态自检、lifecycle smoke 和全新可信八 Hook 任务；两个任务在正常退出后都持久化了干净的 schema-7 状态和 `SessionEnd` 恢复记录。后续发布状态提交仅修改文档与公开契约测试。
- PR 自动化已通过 12 项 OS/Python 矩阵、HOL Plugin Scanner 和 plugin scanner。Main/tag 自动化、注释 tag、GitHub Release、公开读回和下游采用作为独立发布表面分别验证。

## 0.8.11 - 2026-08-27

### 重点

- Codex 删除旧版插件缓存后，进行中的任务仍可继续运行 Hook：先使用原来的插件目录，目录不存在时再使用受管缓存中最新的有效版本。
- Stop 不再把明确脱敏的值或简短易读的 token 示例误判为私有信息泄露；看起来像真实控制 token 的值仍会被拦截。
- 历史缓存缺失时，安装器会直接说明原因并给出恢复方法。

### 变更

- POSIX 和 Windows Hook 只接受名称严格符合 `X.Y.Z`、没有前导零且不是符号链接的回退目录。被救回的任务可能因此使用比最初信任版本更新的 runtime；只有可信 archive 能恢复精确历史版本。找不到有效版本时，Hook 会给出修复提示并退出，不会运行未知路径。
- 隐私分类器现在会检查序列化 `token` 字段的值，而不是只看到字段名就拒绝。脱敏占位值和易读示例可以通过；伪装或疑似真实的私有值仍会失败关闭。
- 本版包含已消费但未发布的 0.8.9 和 0.8.10 候选修复，已安装缓存保持不变。Schema 7、现有协议、Python 3.10+ 和八个 Hook 事件均未改变。

### 验证

- 仓库与隐私检查、218 项测试、lint、编译、安装态自检、lifecycle smoke、严格重复安装 no-op，以及 source/cache/archive 一致性均已通过。macOS 和 Windows 还分别在 Codex CLI 0.149.0 上完成了全新交互 Hook 信任。
- macOS 复现了宿主清理缓存，并从可信 archive 恢复全部已索引版本；Windows fresh task 没有删除历史缓存，因此不能把该清理行为泛化到所有平台。
- PR 自动化已通过 12 项 OS/Python 矩阵、HOL Plugin Scanner 和 plugin scanner。Main/tag 自动化、注释 tag、GitHub Release 和下游 consumer pin 作为独立发布门禁分别检查。精确环境、skip、提交和哈希见[本地验收记录](docs/LOCAL_ACCEPTANCE.md)。

## 0.8.8 - 2026-08-25

### 重点

- Hook 现在会选择可用的 Python 3.10+ 解释器，不再直接使用 `PATH` 中排在最前面的 `python3` 或 `python`。
- 如果 macOS 的裸 `python3` 指向不受支持的 Apple Python 3.9，而 `PATH` 后面存在受支持版本，launcher 会跳过前者；完全找不到受支持解释器时，会 fail-closed 并向 stderr 输出可执行的错误说明。
- POSIX 与 Windows launcher 保持现有八事件 Hook 协议、仅标准库 runtime、stdin/stdout 合同和私有状态行为不变。

### 变更

- POSIX Hook 改为调用一个小型 `sh` launcher，先探测带版本号的 Python，再尝试通用命令。Windows Hook 先验证常见的通用命令以缩短启动时间，再尝试带版本号命令和 `py -3.x` fallback。
- 定向回归把不受支持的 `python3` 放在受支持的 `python3.12` 前面，要求 launcher 跳过前者并用后者通过八 Hook 自检。

### 验证

- macOS 已在最终发布 pin 上通过 0.8.7 真实安装、严格 no-op、只读审计、installed lifecycle smoke 和八 Hook 自检。新信任的交互 Hook 随后失败，因为宿主把裸 `python3` 解析为 `/usr/bin/python3` 3.9.6；直接复现得到相同的 Python 3.10+ 版本门失败。
- 候选已在 macOS 通过仓库/隐私验证、209 项测试（含 2 项能力 skip）、八 Hook 自检、Ruff、外部 cache 编译和 diff 检查。一次性 Codex home 通过首次安装、严格 no-op、只读审计、launcher 自检、lifecycle smoke 和禁留检查。
- 全新交互式 Codex CLI 0.149.0 任务已检查并信任候选的全部 8 个 Hook。`UserPromptSubmit` 和 `Stop` 不再出现此前的 code-2 失败，精确固定回复返回，私有状态以 `0600` 权限落盘，0.8.8 live cache 也没有 Git 或 bytecode 残留。
- Windows 已通过下游精确 pin 应用候选提交 `40987d48d6a6f7a8ea8b3ae6e468c472170748a4`。受管升级、第二次严格 no-op、只读读回、八 Hook 自检、lifecycle smoke、PowerShell launcher 和全新交互信任均通过。0.8.3/0.8.5/0.8.6/0.8.7 历史 live tree 逐字节不变；新 staging/live/archive 均保留 41 个文件且无 Git 或 bytecode 残留，source、staging、live cache 和 archive 的 15 个产品文件完全一致。
- 精确候选的 PR 自动化已通过 12 项 OS/Python 矩阵、HOL Scanner 和 plugin scanner。Main/tag 自动化、注释 tag、GitHub Release 读回和下游最终发布 pin 与原生 runtime 验收分别验证。

## 0.8.7 - 2026-08-25

### 重点

- 插件升级现在会保留 trusted product manifest 之外的历史 live-cache 文件，包括 lifecycle 生成并留作证据的 `.pyc`；即使 Codex 整体替换插件 cache root，也不会静默丢失这些文件。
- 产品 archive 仍然只作为产品文件的信任来源。历史非产品差异通过独立的 SHA-256 绑定事务跨升级保全，恢复到同一版本 live 路径，但不会进入 trusted archive。
- 事务中断后，只读检查会 fail-closed；下一次受管 `--apply` 会先恢复历史文件。Manifest 无效、内嵌 Git 元数据或 symlink 都会在破坏性刷新前被拒绝。

### 变更

- 执行 `codex plugin add` 前，installer 通过全文件 manifest 比较每个已索引历史 live tree 与 archive，只为确有差异的历史版本建立事务备份。
- Codex 刷新 cache root 后，installer 恢复并验证历史全文件树；验证无法完成时保留备份，仅在精确恢复成功后删除事务目录。
- 定向回归覆盖 bytecode 原样保留、升级失败、中断恢复、只读 no-write 和 symlink 拒绝。Schema 7、八 Hook wire、runtime 行为、私有数据和产品 archive 哈希均不改变。

### 验证

- macOS 已通过公开仓库/隐私门、206 项测试（含 2 项能力 skip）、八 Hook 自检、Ruff、外部 cache 编译和 diff 检查。真实 Codex CLI 0.149.0 隔离环境从 0.8.6 升级到 0.8.7 时，原样保留了一枚真实的 339,172-byte 历史 `.pyc` 及旧 live tree 的完整 SHA-256 快照，同时旧 trusted archive 继续保持 product-only。
- 隔离候选还通过第二次 apply 严格 no-op、只读读回、installed self-test、无外层 bytecode guard 的 lifecycle smoke，以及 staging/live/archive parity；新版本中无事务或 bytecode 残留。PR CI 的 12 项 OS/Python 矩阵、HOL Scanner 和 plugin scanner 均通过。
- Windows 原生验收把精确候选安装到真实 Codex home，升级前后 0.8.3、0.8.5 和 0.8.6 的历史 live-tree 快照均未变化。0.8.7 smoke 也没有改变自身全文件快照；source、staging、live cache 和 archive 的 13 个产品文件完全一致且无禁留。此前已经丢失的 0.8.5 `.pyc` 没有被重建，也没有被误报为已恢复。下游精确验收提交及其 CI 另行通过。

## 0.8.6 - 2026-08-25

### 重点

- 如果调用方没有设置 `PYTHONDONTWRITEBYTECODE`，installed lifecycle smoke 也不会再向不可变插件根写入 `__pycache__` 或 `.pyc` 文件。
- Bytecode 禁写只覆盖 smoke 主进程的直接验证导入。Hook 子进程继续使用原有禁写环境；已安装 runtime、私有数据、缓存和归档契约均不改变。
- 原生平台验收现在可以同时要求 lifecycle smoke 通过和产品根字节级干净，不再依赖外层 `python -B` workaround。

### 变更

- Smoke 仅在加载已安装 runtime module 时临时设置 `sys.dont_write_bytecode`，随后恢复调用方的进程设置。
- 新增定向回归：移除外层 `PYTHONDONTWRITEBYTECODE`，针对一次性插件根运行完整 installed lifecycle smoke，并拒绝任何新生成的 `__pycache__`、`.pyc` 或 `.pyo`。
- Schema 7、各协议与 classifier 版本、八 Hook wire、marketplace 迁移及缓存/归档 manifest 均不变。

### 验证

- Windows 原生 0.8.5 已成功完成受管 0.8.3 到 0.8.5 迁移、严格 no-op、只读读回、八 Hook 自检、lifecycle assertions 和 manifest parity，但 smoke 直接导入向 live cache 写入一枚 `.pyc`，因此最终验收正确失败；Windows 随即停止，未删除该文件，也未更新下游状态。
- macOS 已通过公开仓库/隐私门、202 项测试（含 2 项能力相关 skip）、八 Hook 自检、Ruff、编译和精确候选 0.8.6 隔离安装。第二次 apply 是严格 no-op；移除外层 bytecode 环境保护后，完整 smoke 不改变全文件 SHA-256 快照；source、staging、live cache 和 archive 保持字节一致，且无 Git 或 bytecode 残留。
- Main/tag CI、注释 tag、GitHub Release 和下游 pin 已分别通过。随后 Windows 原生 0.8.6 在 no-op 与 lifecycle 验证前失败：受管升级整体替换 cache root，只恢复 trusted product files，导致保留作证据的 0.8.5 `.pyc` 被静默丢弃。0.8.7 修复的是这一独立的历史文件保全缺陷。

## 0.8.5 - 2026-08-25

### 重点

- 精确 pin 消费者现在可以从上一个不可变 checkout 或其消毒 staging 根迁移，即使新版本使用了不同的 commit 定址目录。
- 迁移仍严格限定在受管 `CODEX_HOME/upstreams/context-guard` 目录下，并且 manifest repository 必须与当前产品一致。位于其他目录的同身份路径仍会被拒绝。
- 只读检查会报告需要执行 `--apply`，但不会修改 marketplace、staging、插件、缓存、归档或私有任务数据。

### 变更

- 0.8.4 引入了消毒 staging，但只识别当前 checkout 路径。因此精确 pin 下游升级时，如果现有注册仍指向上一个 pinned commit，流程会在修改 marketplace 之前停止。
- 受管根识别器同时接受 40 位小写 commit 目录及其 `.marketplace` staging 同级目录，避免后续 pin 提升重复出现同类集成失败。
- Schema 7、所有协议与 classifier 版本、八 Hook wire 和缓存/归档信任模型均不变。

### 验证

- 定向回归覆盖旧 pinned checkout、旧受管 staging、只读 no-write、无关路径拒绝、当前 checkout 迁移、新注册、staging 一致性和临时目录清理。
- 公开仓库/隐私门、201 项测试（含 2 项能力相关 skip）、八 Hook 自检、Ruff 和编译均通过。精确 commit 隔离 pinned consumer 已从 0.8.3 迁移到 0.8.5，保留旧缓存/归档，通过 installed lifecycle 和自检，并以严格 no-op 及成功只读读回结束。
- 真实 default-home 迁移、main/tag CI、注释 tag 和 GitHub Release 是相互独立的验收面，不能替代上述隔离 consumer 证据。

## 0.8.4 - 2026-08-25

### 重点

- Context Guard 现在从经过消毒的 staging 副本注册 marketplace，不再直接使用不可变 Git checkout，因此 Codex 刷新插件缓存时不会把 `.git` 元数据复制到 live cache。
- 已经指向 checkout 的注册只需执行一次受管 `--apply` 就会迁移。同一次执行会从可信归档修复已受影响的 live cache，不删除历史版本或私有任务数据。
- 只读检查仍保持只读；需要迁移或修复时，它会给出可执行的 `--apply` 提示，不会静默改动安装状态。

### 变更

- staging 使用与缓存验证相同的产品树忽略规则和 manifest，拒绝内嵌 Git 元数据，原子替换过期 staging，并在成功或失败后清理临时目录。
- 新增注册或 checkout 迁移后都会验证最终 staging 路径；已经正确指向消毒 staging 的注册保持幂等。
- 本补丁只改变安装和缓存生命周期。Schema 7、execution protocol 1.0.0、Proof protocol 1.0.0、Stop protocol 1.1.0、classifier 2.3.0 和八 Hook wire 均不变。

### 验证

- Windows 原生复现和真实 CLI 端到端测试已验证新 staging、checkout 迁移、live-cache 修复、第二次执行严格 no-op、只读诊断，以及 staging/live cache 中没有 `.git` 和遗留临时目录。
- macOS 原生源码验收通过公开仓库/隐私门、197 项测试（含 2 项能力相关 skip）、八 Hook 自检、Ruff、编译，以及 0.8.4 候选版的隔离安装/no-op/生命周期链。
- PR 和合并后 main CI 的 12 项 OS/Python 矩阵及 HOL 扫描均已通过。Tag CI、注释 tag 和 GitHub Release 仍是需要分开验证的发布事实。

## 0.8.3 - 2026-08-24

### 重点

- 0.8.3 把不同来源的作用分开记录：用户要求决定任务目标和写入授权，`AGENTS.md` 与已选择的 Skill 规定工作流程，Codex Plan 记录可调整的执行安排，工具、文件、图片和公开读回只提供事实证据。后面三类来源都不能扩大用户授权。
- 例如，采用发布 Skill 时可以记录具体 Skill 及其版本、当前阶段和可选的 Codex Plan 绑定；Skill 或 Plan 后来变化，旧绑定会标为需要重新确认，而不是继续按旧内容执行。
- 只有发起根任务的用户才能显式采用这套项目契约。0.8.3 负责记录、恢复和完成检查，不会改写 Codex Plan，也没有加入工具调用前拦截、自动发布或其他新权限。

### 变更

- 内部的 state schema 7 只保存有界的标识、数量、状态和哈希。设计文档中的 `dormant` 表示“存储结构已经存在，但尚未采用任何契约”；`stale` 表示“已经采用的来源或计划与原来记录的摘要不再一致”。
- 已安装但未发布的 0.7.8–0.8.2 候选修复已经纳入本版本，同时保留这些历史安装版本的不可变身份。
- 公开仓库现在是唯一实现上游；下游配置仓库只消费明确版本和提交。

### 验证

- macOS 和 Windows 的原生源码检查、隐私审计、192 项测试、八个 Hook 自检、编译以及隔离安装和升级检查均已通过；平台相关的符号链接跳过项记录在验收文档中。
- 两个平台上的精确提交安装和源码/缓存/归档一致性检查均已通过。macOS 上一次正常受信、未使用 trust bypass、选用 Python 3.12.2 的 Codex CLI 0.149.0 全新任务成功采用 schema-7 契约并保持完整性：确定性候选被激活，自然语言候选仍不具权威性，且没有创建 action ticket。
- main 与 tag 的 CI/HOL、注释 tag 和 GitHub Release 仍是分别核验的发布事实，不能替代原生运行证据。

## 0.7.7 - 2026-08-18

### 修复

- 减少错误的验证要求：普通的斜杠文本和 URL 片段不再被误认为本地路径，中文里的普通“应用”也不再自动意味着必须检查 UI 结果。
- `view_image` 成功返回有效图片 data URL 时，现在可以作为视觉证据，不再停留在未知状态。

### 技术说明

- 本补丁没有改变 0.7 系列的证据模型，只把对象、结果位置和视觉结果分类器推进到 2.2.1。
- macOS 和 Windows 的源码、安装、归档、重复安装 no-op 和生命周期检查均已通过；精确平台范围见验收记录。

## 0.7.6 - 2026-08-17

### 修复

- Context Guard 现在能更可靠地区分真正的“任务已经完成”，以及疑问、引用、假设示例、尾随否定或对他人说法的转述。
- Python 低于 3.10 时会安全失败，不再静默运行于不支持的解释器。

### 技术说明

- 0.7.4–0.7.6 只改进完成声明和剩余工作识别，没有改变证据模型或 Hook 事件。
- macOS 和 Windows 的原生源码与隔离生命周期检查通过；CI 和真实 Hook 信任仍是不同证据范围。

## 0.7.3 - 2026-08-14

### 新增

- 一项工作只有在证据对应正确需求、对象、结果位置、要求范围和必要视觉回读时，才可以被视为完成。
- 图片等多模态输入只记录哈希和有界元数据；Context Guard 不会把图片字节复制到私有状态或恢复包中。

### 修复

- 只有用户明确授权修改时才要求视觉结果回读；用户明确给出的完整数量优先于附件数量。
- 无法确定性验证的情况会明确退回早期 checkpoint 行为，不会夸大已有证据的证明能力。

### 技术说明

- 这是 0.7 系列第一个正式发布版本，内部名称为 state schema 6 和 Proof protocol 1.0.0。
- macOS 和 Windows 的原生源码、安装、归档、no-op 和生命周期检查均已通过。

## 0.6.3 - 2026-08-12

### 修复

- “继续执行”现在只是建议，不能覆盖终止安全决策；只有已验证完成 checkpoint 或明确的持续执行请求才能要求再进行一个修正回合。
- 文档编辑和普通搜索不会再因为包含类似 shell 的文字而被误判成私有控制命令。
- 升级时会先用可信归档修复损坏的已安装缓存，再考虑没有索引的副本。

### 技术说明

- 本补丁完成了 0.6 系列的单向安全回合控制并加固缓存恢复；macOS 和 Windows 原生验收通过。

## 0.6.1 - 2026-08-11

### 新增

- 任务只有在存在已验证 checkpoint 时才能标记为完成；其他结束方式会明确记录为继续执行、等待用户、等待外部结果或延期处理。
- 原始命令输出现在可以像结构化工具结果一样提供可验证的成功回执。

### 发布说明

- 未发布的 0.6.0 候选首次加入这套回合控制，但它的原始输出回执不能证明成功。该版本号保持已占用且不可变，0.6.1 是这个系列第一个正式版本。

## 0.5.1 - 2026-08-10

### 修复

- 明确把控制权交给用户时，不再与助手承诺自行完成的后续工作混淆。
- 加载和保存状态时重新计算未完成项数量，避免旧数量在升级后继续存在。
- 同版本缓存只有在源码和归档完整性得到验证后才会被信任。

## 0.5.0 - 2026-08-09

### 新增

- `context-guard diagnose` 用有界且不保存原始回复的记录说明最近一次停止决策，不再要求维护者从任务全文猜测原因。
- 已安装 Hook 版本按哈希归档，让旧任务继续使用原运行时，并能从可信副本修复损坏缓存。

## 0.4.16 - 2026-08-09

### 修复

- 有界的审查、测试、本地提交或报告阶段可以在明确保留后续阶段后结束；如果用户要求继续、推送、发布、部署或运行 CI，整个任务的完成门仍会保持生效。
- “不要推送”等限制会被视为明确拒绝权限；提示历史缺失或不一致时安全失败。

## 0.4.13 - 2026-08-08

### 修复

- 只汇报外部审查、策略暂停、平台选择或仓库故意不变的状态时，可以安全结束当前回合，不会被误判为整个任务完成。

## 0.4.12 - 2026-08-08

### 修复

- 等待用户登录、配置发布者、批准部署或执行其他明确用户操作时，可以安全结束当前回合；仅仅列出助手自己仍需完成的工作则不可以。

## 0.4.10 - 2026-08-07

### 文档与分发

- 加入插件图标、固定版本的发布检查、双语生命周期图和完整的上下文压缩恢复示例。
- 除仓库检查外，还完成了 Windows 原生安装、Hook 信任和手动压缩恢复验证。

## 0.4.9 - 2026-08-06

### 修复

- 安装器现在会让所有 Codex 子进程使用指定的隔离 home，不再意外读写调用者的默认 Codex 目录。

### 平台范围

- macOS 完成原生 Hook 信任和手动压缩恢复。Windows 在发布时只有 CI，后续才补充原生验证；Linux 仍只有 CI 和隔离生命周期证据。

## 0.4.8 - 被取代的发布候选

### 包含内容

- 最初公开候选可以在上下文压缩和恢复后保留用户提示、需求、修正、委派工作、证据和未完成条件。
- 它还加入了有界恢复、只读 Codex Plan 镜像、安全本地安装和不可变的版本化 Hook 缓存。

该候选没有 tag。0.4.9 以安装隔离修复和完整独立运行门取代了它。
