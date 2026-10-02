# 会话锁与状态所有权子设计（修订 3：显式静止迁移或明示不支持）

状态：WP-01 交付稿 v3，供协调者有界审查。修订 1（共置互操作）被 R1 否决；
修订 2 的**隔离方向被 R2 接受**，但其在线迁移证明被否决（O_CREAT 检查窗口、
迁移暂停超 30s 的 marker 老化、崩溃残留 marker、钩子间隙≠会话退出）。修订 3
按 R2 的具体裁决重写：**取消首次写自动迁移与 30 秒 marker 证明**，不以第二次
stat 或刷新 mtime 补丁化。日期：2026-10-02。不变量：N05、N06、N07、N09、N10。

## 1. 会话命名空间与解析（R2 已接受方向的落定）

- protocol-2 运行时：`<data_root>/sessions-v2/<id>/`；protocol-1 运行时：
  `<data_root>/sessions/<id>/`，原样保留。
- 唯一推导 `resolve_session_dir(root, session_id, *, for_write)`：
  1. `sessions-v2/<id>` 存在 → v2。
  2. 否则 `sessions/<id>` 存在 → **legacy 绑定**：
     - 读路径（status/diagnose/recovery-page/profile hint）：返回 legacy 树，
       **只读**——不修复损坏、不创建 prompt 记录、不执行清理、不写任何文件。
     - 写路径（全部九个 Hook 事件与显式私有命令）：抛
       `LegacySessionWriteRefused`，按事件 fail 策略呈现
       （PreCompact→systemMessage、Stop→stopReason、UserPromptSubmit/
       Subagent→systemMessage 警告、PreToolUse 保持既有 fail-open 普通工具
       契约——**记录被拒但不阻止用户工作**，警告明示"本会话属于先前
       Context Guard 运行时：结束旧任务后用显式迁移命令转移，或继续用原
       运行时完成"）。**绝不空起步、绝不静默替换历史。**
  3. 两者都不存在 → 新会话，直接 v2（无历史可掩盖）。
- v2 内单 writer：内核锁（fcntl/msvcrt）跨整个事件事务，稳定锁文件，
  writer 永不 unlink；竞争按事件 fail 策略 fail closed；SessionEnd 1.2s 有界。

## 2. 提交边界（R2 第 6 点的证明义务重述）

v2 内**受支持的产品 writer 与 cleanup 都不可能替换锁 inode**：所有 writer
经同一 `session_lock` 打开既有 inode（`O_RDWR`，创建仅发生在目录首次建立且
在持进程内锁下进行），没有任何代码路径 unlink/重建 `.lock`；cleanup 删除
的是 ended+过保留期的整树（该状态下不存在任何 writer）。因此锁 inode 在
writer 生命周期内不变是**产品代码的结构性质**；`verify_ownership`
（fd vs path 的 `(st_dev, st_ino)`）保留为对外部篡改的诊断硬化，`st_ino==0`
fail closed。对外部同权限敌意进程的"检查后替换"明确列为威胁模型排除项
（与能直接删除 state.json 的敌意进程同级），**不把该排除写成通过**。

## 3. 迁移：显式操作，静默性来自旧运行时的持久终态（非锁窗口）

### 3.1 谁建立并维持静默

**旧运行时自己。** protocol-1 的 `handle_session_end` 在自身锁内把
`session.ended_at` 持久化为该会话的终态转换；对已结束的会话，宿主不再产生
任何 Hook 事件，protocol-1 writer 对该树的存在性写入为**零**。迁移不依赖
"锁文件缺失"推断（R2 第 4 点），而是消费这一**持久化终态声明**。

### 3.2 迁移操作（显式 CLI，非 Hook 路径）

`context-guard migrate-legacy-session --session-id <id> [--data-dir D]`：

1. **源验证**（对 legacy 树只读）：
   - `state.json` 完整性验证通过（`validate_state_integrity` + content_hash）；
   - `session.ended_at` 非空——未结束会话**拒绝迁移**（"任务仍在旧运行时上
     进行；结束后再迁移"），不做任何写入；
   - 源树枚举：发现 symlink/junction/reparse point → **拒绝**并列出路径
     （Windows reparse 检测用 `st_file_attributes`/`os.path.islink` 组合，
     双平台实现一致拒绝，不做安全物化）。
2. **转移**（对 legacy 树零写入——没有 O_CREAT 窗口、没有 marker、没有
   可老化的锁文件；R2 的四个调度在结构上不存在）：
   - 排除 `.lock` 与一切瞬态所有权记录后，逐文件复制到
     `sessions-v2/.staging/<id>-<uuid>/`，复制即校验：每个文件写后重读并
     与源字节 sha256 比对，汇总文件清单摘要；
   - 复制后重放完整性验证（copied state 与源 `content_hash` 相等）；
   - 写 `migration.json`：`{schema: "session-migration/v1", source_namespace,
     source_state_sha256, source_inventory_sha256, source_ended_at,
     migrated_at, runtime_tree_digest, status: "complete"}`；
   - `os.rename(staging, sessions-v2/<id>)`——唯一发布点，rename 原子；
   - **消费验证**：rename 后立即重新加载 v2 状态并跑完整性与迁移记录校验；
     失败 → 报错并指示回退（v2 树删除，legacy 树从未被修改，旧运行时继续
     可用——回滚边界完整）。
3. **崩溃重启（每个崩溃点）**：
   - 验证/复制中途崩溃：staging 残留；来源完好。重跑命令时先清扫**本会话**
     的 staging 再重来；staging 永不成为权威。
   - rename 后、消费验证前崩溃：v2 树带 `status: "complete"` 记录存在；
     下次命令检测到已迁移即报告成功并执行消费验证；Hook 路径按 v2 树运行。
   - 迁移后旧树保留为只读历史（新 cleanup 按 §4 处理）。
   - 并发迁移者：对**目标** v2 路径的内核锁（`sessions-v2/<id>/.lock` 父级
     迁移锁或对 staging 的独占 rename 目标检查）互斥；第二者要么等待要么
     得到"已迁移"结果。legacy 树上不创建任何锁。

### 3.3 无法证明时的行为

未结束的会话：迁移命令拒绝并明示；新运行时对未迁移 legacy 会话拒绝写入
（§1.2）；旧任务**保留在旧运行时上**直至结束。不存在空起步路径。

### 3.4 对原规划承诺的变更（请协调者裁决）

| 原承诺 | 修订 3 | 影响 |
| --- | --- | --- |
| "需要恢复旧会话时……迁入独立目标"（未限定已结束） | 迁移仅限**已结束**会话；进行中任务不迁移，留在旧运行时完成 | 未结束任务不能热迁移到新运行时；升级后继续未完成任务的路径 = 旧运行时完成 → 显式迁移 → v2 继续 |
| N09 "任何迁移都能保留未完成需求" | 已结束会话的完整账本（含未完成项）随全树复制保留；"未完成"约束从迁移时刻转为从 v2 恢复继续 | 语义保持：迁移后未完成需求不丢失；变化在"迁移前会话必须已结束" |
| 升级即用新 Hook | 升级后未迁移的旧会话在新 Hook 下**只读警告**（记录拒止、完成门控不激活） | 用户需显式运行一次迁移命令（或继续用旧运行时结束任务） |

## 4. 跨树 cleanup 与身份

- v2 清扫沿用既有规则（ended_at + 保留期 + 完整性有效 + 跳过当前会话）。
- legacy 树：新运行时仅在**同一规则满足**时删除（ended+过期+完整性有效
  ——该状态下无任何 writer 可存在，删除不违反排他）；活跃/未结束 legacy
  树绝不触碰；不删除其他迁移者的 staging（staging 仅由同会话迁移命令清扫）。
- `.lock` 与瞬态记录不进入导入；导入后验证精确文件清单
  （migration.json 记录 inventory sha256）。

## 5. 双平台与测试族（设计通过后实现）

- fcntl/msvcrt 内核锁沿用；symlink/junction/reparse 双平台拒绝；终止测试
  平台感知（POSIX SIGKILL / Windows terminate()）；msvcrt 字节范围语义仍是
  Windows 原生 pending 门禁。
- 正例：新会话 v2 直建；已结束会话显式迁移全链（验证→复制校验→rename→
  消费验证）；迁移后 v2 事件正常、legacy 树字节不变。
- 反例（转不变量断言）：未结束会话迁移被拒；未迁移 legacy 会话的九事件写
  路径全部拒止且普通 PreToolUse 工具保持放行；源树含 symlink 拒绝；
  每个崩溃点重启语义（staging 清扫/已迁移报告/回退）；cleanup 不触活跃
  legacy 树与他者 staging；pass 翻转与 marker 删除不能绕过例外强制（F3）。
- R2 的四个迁移探针调度在设计层面逐一关闭：检查-创建窗口（对源零创建）、
  老化 marker（无 marker）、崩溃残留（无 marker/仅目标侧 staging 可清扫）、
  钩子间隙（ended_at 持久终态，非锁缺失推断）。
