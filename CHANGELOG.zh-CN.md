# 更新日志

[English](CHANGELOG.md)

这里按时间倒序记录所有重要公开版本。每个版本先列出按重要性降序排列的重点，
再说明其他变化与精简的验证边界。`0.7.7` 是最新公开版本。

## 0.8.3 - 未发布

### 重点

- Schema 7 加入 dormant、哈希绑定的执行契约 ledger，但不新增 Hook 事件、
  不拦截工具，也不修改 Codex 所有的 Plan 状态。
- 仅限根用户的 `context-guard adopt <project-relative-json>` 控制可以采用有界的
  确定性契约；自然语言候选仍不具权威性，也不能授予执行权限。
- 可选的原生计划绑定使用语义摘要。后续语义变化会将契约和相关记录标记为 stale，
  同时保持计划为只读的 Codex 原生表面。
- 公开仓库成为唯一实现上游；下游配置仓库固定不可变版本与提交，不再维护第二份
  产品实现树。

### 变化

- 0.7.9 完成真实 `Plan updated` receipt、Stop 控制文本隐私分类和桌面
  `input_image` content-block receipt 的兼容性修复；已使用的 0.7.8 保持不可变。
- 0.8.1 完成 dormant schema-7 Phase 2 模型；已使用的 0.8.0 保持不可变。
  0.8.3 在已使用的 0.8.2 包身份之后完成 Phase 3 契约采用。
- Status、diagnosis 与 recovery 仅暴露有界 ID、计数、状态与哈希。本候选仍不含
  `PreToolUse`、工具阻断、ticket 预留、提交/发布动作或未覆盖表面的授权。

### 验证

- macOS 原生源码门通过仓库契约、公开树隐私审计、192 项测试（2 项能力相关跳过）、
  八 Hook 自检、Ruff 0.16.1、编译和 `git diff --check`。
- Codex CLI 0.149.0 隔离 home 通过首次安装、源码/缓存一致性、严格第二次 no-op、
  已安装 schema-7 生命周期 smoke 和八 Hook 自检。下游配置消费者校验精确
  公开提交，完成默认 home 安装，启用公开身份并在不删除缓存的前提下禁用旧私有身份，
  且通过严格第二次 no-op 与自检。fresh-task Hook trust、远端 main、CI、tag 与 release
  仍是独立门。

## 0.7.7 - 2026-08-18

### 重点

- 对象发现不再把普通斜杠文本或其他 URL 中的路径片段误当成
  绝对路径验证义务。
- 有界的 `codex://threads/...` 仍是可检查对象，中文“应用”的通用用法
  不再单独触发 UI 表面。
- `view_image` 返回无错误且携带有效图像 data URL 时，会成为成功
  视觉证据，而不再标记为 unknown。
- Schema 6、Proof protocol 1.0.0、Stop protocol 1.1.0 和八个 Hook 的 wire
  contract 不变；分类器元数据推进到 2.2.1。

### 变化

- 按既定 shared-core 边界从私有 sibling 同步共享运行时与转换后的
  回归契约。
- 公开打包、校验常量、双语文档和安装生命周期 smoke 将 0.7.7
  标记为当前正式版本。

### 验证

- Windows 原生源码验收已通过公开仓库与隐私审计、sibling parity、170 项测试
  （1 项能力相关跳过）、八 Hook 自检、Ruff 0.16.1、编译和
  `git diff --check`。
- macOS 原生验收通过相同的公开源码门，其中有 2 项能力相关跳过。Codex CLI
  0.146.0 隔离安装在两个原生平台上均通过首次安装、源码/缓存一致性、严格第二次
  no-op、已安装八 Hook 自检和生命周期 smoke。本补丁没有重复正常信任的公开
  fresh-CLI Hook 任务；CI/HOL 与 tag 检查仍是独立的源码自动化门，不能替代
  原生运行证据。

## 0.7.6 - 2026-08-17

### 重点

- 分类器 2.2.0 修复 2.1.0 审查中发现的两类盲点：现在能够识别复数、量化和
  第一人称转述式完成声明，同时不会把疑问句、尾随否定、他人引语或假设表述
  当成当前助手的完成声明。
- Hook 入口在 Python 低于 3.10 时 fail closed，不再静默运行于不受支持的解释器。
- 清除运行时和安装器中的无引用正则、辅助函数与 `restore_tree` 路径；公开仓库
  168 项测试与 sibling parity 门保持通过。
- 0.7.6 与私有维护产品同步共享运行时和回归契约；schema 6、Proof protocol
  1.0.0、Stop protocol 1.1.0 与八个 Hook 的 wire contract 均未改变。

### 变化

- 0.7.4 将诊断分类器推进到 2.1.0，区分当前任务完成声明与假设、引语和示例。
- 0.7.5 将否定约束到最近的显式助手未来动作片段，并保留 review/configuration
  等可执行动词。
- 0.7.6 将诊断分类器推进到 2.2.0，并加入 Python 版本 fail-closed 门禁。

### 验证

- 公开 0.7.6 运行时通过限定的 Windows 与 macOS 源码、隔离安装和生命周期门；
  Windows 还验证了 sibling parity 与已安装八 Hook 自检。本补丁没有重复正常信任
  的公开 fresh-CLI Hook 任务。CI/HOL 与 tag 检查是独立的源码自动化证据，不能
  代替原生运行证据。

## 0.7.3 - 2026-08-14

### 重点

- Schema 6 加入只保留哈希的多模态资产与确定性的 Proof protocol 1.0.0；
  `register-proof` 将证据绑定到对象、表面、视觉回读和规范化范围集合。
- 只有肯定且已获授权的修改表述才会强制视觉结果回读；提示中明确的完整范围数量
  优先于附件数量。
- 修复 0.7.1 差分审查发现的控制文本误判、定性范围过度强制、无界 transcript
  重扫和恢复裁剪四类问题。

### 变化

- `register-proof --manifest` 拒绝错误表面、无关对象、复用输入图片和未解决的
  视觉事实。
- 无法确定性构造的边界会明确回退为 `legacy_fallback`，而不是夸大证明能力。
- 恢复包只保留有界资产元数据和待完成义务，不保存图片字节。

### 验证

- 冻结的 0.7.3 源码、安装、archive、严格 no-op 和已安装生命周期门在 macOS
  与 Windows 上通过；release 自动化不替代任何原生平台验收。

## 0.6.3 - 2026-08-12

### 重点

- 在 schema 5 与分类器 2.0.0 不变的前提下，将 Stop protocol 推进到 1.1.0：
  旧 `continue` 只作提示，终止控制保持单向安全。
- 私有控制意图检测限定到已知 shell 工具和引号外操作符，文档补丁与普通搜索
  不再被误判为控制写入。
- cache 升级先从可信 archive 修复已索引 live 版本，再处理未索引版本。

### 变化

- Schema 5 中未完成的 protocol-1.0.0 控制只会使本次临时尝试失效，不会丢失
  prompts、items、evidence 或 decisions。
- 0.6.2 已被真实安装消耗，因此保持不可变、无 tag、未发布。

### 验证

- 回归覆盖终止不匹配、显式持续执行、引号搜索、非 shell 边界和一万次控制状态
  转换。macOS 与 Windows 原生验收通过；CI/HOL 是独立源码门。

## 0.6.1 - 2026-08-11

### 重点

- Schema 5 引入 turn-bound 控制槽，可保存已验证 checkpoint，或 `continue`、
  `user_wait`、`external_wait`、`deferred` 之一；`complete` 只能由 checkpoint 推导。
- Stop protocol 1.0.0 与分类器 2.0.0 记录有界枚举和哈希，不保存原始回复文本。
- 成功私有预检最后输出独立的 `Script completed`，让 raw stdout 与结构化成功
  结果具有一致的可验证语义。

### 变化

- `PostToolUse` 是唯一权威的 staging writer；Stop 使用固定控制优先级。
- Schema 1–4 迁移保留持久 ledger，但会使未完成 token 和 staged control 失效。
- 公开发布验证会以脱敏方式审计 author 与 committer 身份。

### 验证状态

- 0.6.0 从未打 tag 或发布，已安装 cache 保持不可变。0.6.1 通过 macOS 与 Windows
  原生验收，并由精确 release commit 的 main/tag CI 与 HOL 约束发布。

## 0.5.1 - 2026-08-10

### 重点

- 分类器 1.0.1 将显式用户交接与助手仍需执行的未来动作分开。
- `open_items` 在加载和保存时重新计算，修复 schema 3/4 的陈旧派生状态。

### 修复

- 只有在安装锁内证明源码/cache parity 与 archive 完整性后，才允许同版本首次
  archive 采纳；漂移、损坏和未索引 archive 仍然 fail closed。

### 验证

- 新增双语交接/权限矩阵、陈旧状态迁移和首次采纳回归；macOS 与 Windows
  0.5.1 原生验收独立通过。

## 0.5.0 - 2026-08-09

### 重点

- Schema 4 加入有界、只保留哈希的 32 项 `decision_log`；分类器 1.0.0 提供稳定
  allow/gate/consume/fail-closed 结果。
- 引入带原子 SHA-256 索引、显式可信修复且不自动清理的版本 archive 生命周期。

### 变化

- 新增 `context-guard diagnose`、状态中的最新决策字段、版本策略和 sibling-product
  shared-core parity 门。
- 延后远程工作只有在明确被拒绝或超出范围时才安全；live 历史 cache 只能由完整
  可信 archive 修复。

### 验证

- 覆盖阶段边界、双语变形、schema 迁移/隐私/重建和 archive 生命周期回归；
  Windows 原生 0.5.0 验收随后完成，但该版本没有 tag 或 GitHub Release。

## 0.4.16 - 2026-08-09

0.4.14 与 0.4.15 是未发布本地候选；由于已安装版本 cache 不可原地覆盖，版本号
保持已消耗状态。

### 修复

- 结合当前用户提示解释延后阶段状态；有界 review/audit/test/verification/local
  commit/reporting 回合可在明确保留后续阶段时结束。
- 当前提示要求继续、完成、push、publish、deploy、promote、创建远端或运行 CI 时，
  完成门继续生效，并读取完整不可变提示记录。
- 明确的“不要 push 或运行 CI”属于权限拒绝；提示记录或摘要不匹配时 fail closed。

### 验证

- Ubuntu/macOS/Windows 与 Python 3.10/3.12/3.13 九 job 矩阵、仓库验证、公开树
  审计、91 项测试、Ruff、编译和 HOL Scanner 通过。

## 0.4.13 - 2026-08-08

### 修复

- 已提交外部 review、平台选择、显式策略暂停和故意不改仓库的状态回复可安全结束；
  相同整段非完成分类器同时用于完成检测与 Stop 处理。

## 0.4.12 - 2026-08-08

0.4.11 是未发布本地候选；其版本号已被安装消耗，cache 不可原地覆盖。

### 修复

- 登录、发布者配置、部署批准和行动后回复等显式用户交接可安全结束；仅列出剩余
  工作但没有交接控制权时，完成门仍然保留。

## 0.4.10 - 2026-08-07

### 分发

- 加入无文字盾牌/检查点 SVG 图标、固定 SHA 的 GitHub Actions、验证工具锁、
  强制 HOL Scanner 门与 release/license/CI 徽章。

### 文档

- 加入经过渲染检查的双语 Mermaid 流程图、生命周期序列和日常重构示例。

### 验证

- Windows 25H2/Python 3.12.10 通过 83 项测试、隔离安装 no-op/lifecycle 与正常
  Hook trust/manual compact；仓库验证、公开树审计和 Ruff 通过。

## 0.4.9 - 2026-08-06

### 修复

- 安装器所有 Codex 子进程都通过显式 `--codex-home` 路由，避免验证隔离目录时
  marketplace/plugin 命令误用调用者默认 home。

### 验证状态

- macOS 八个 Hook 均经单独信任并完成真实 manual compact；Windows 在发布时由
  Python 3.10/3.12/3.13 CI 覆盖，原生 fresh-runtime 验收仍待后续完成。

## 0.4.8 - superseded release candidate

这是基于已验证 0.4.8 lineage 的初始开源候选，没有打 tag；0.4.9 以安装隔离修复
和完整独立可信运行门取代它。

### 包含内容

- 不可变、哈希验证的提示 journaling 与需求/验收 ledger；显式 supersession；
  有界 compact 恢复；原生计划镜像；可追溯 delegated contract；结构化证据和
  私有完成门。
- 安全本地安装器、用户决策门优先级与 Windows lock-race 有界重试。

### 验证状态

- macOS 源码 lineage、公开仓库 80 项测试加一个 Windows-only skip、plugin
  validation、隐私审计、parity、幂等安装和隔离生命周期通过；Windows 原生
  runtime 当时仍待验收，Linux 仅有 CI 证据。
