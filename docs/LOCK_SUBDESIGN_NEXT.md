# 会话锁与状态所有权子设计（修订 2：命名空间隔离与迁移）

状态：WP-01 交付稿 v2，供协调者有界审查；**修订 1（方案 A，共置互操作）已被
R1 复核否决**（CGR-L1/CGR-L2），本文按否决意见重写。日期：2026-10-02。
对应缺陷：CGN-01/CGN-08、CGR-L1、CGR-L2。不变量：N05、N06、N07、N09、N10。
规划版本仍为 0.15.0，本设计通过并实现前不冻结任何版本契约。

## 0. R1 否决的结构性结论

R1 证明的三件事使"同一状态树上的跨版本互斥"不可实现：

1. 年龄不能证明退出（活的 legacy writer 持锁 31s 后被新 writer 接管，同 inode
   使所有权复核无法区分两者）。
2. 空的/畸形的 owner 记录不能证明 writer 缺席（legacy 在 O_EXCL 创建与写入
   owner 之间被暂停时，新 writer 把空文件当作无主锁）。
3. 提交前 inode 复核与实际落盘之间存在抢占窗口（复核后、`os.replace` 前被
   legacy 替换并成功落盘，candidate 恢复后覆盖其状态并成功返回）。

protocol-1 不认识任何新内核锁原语；不读新 marker；换锁文件名只影响新 writer。
因此**任何让新旧 writer 打开同一批状态文件的设计都无法给出可行的互斥证明**。
修订 2 放弃共置互操作，改为结构隔离：新旧 writer 从推导上就不可能打开同一
可变状态；互斥只在各自命名空间内部由本方原语保证。

## 1. 命名空间选择与推导

- protocol-2 运行时（本候选）：`<data_root>/sessions-v2/<session_id>/`。
- protocol-1 运行时（0.14.3 及更早）：`<data_root>/sessions/<session_id>/`，原样保留。
- 推导是**唯一函数** `resolve_session_dir(root, session_id, *, for_write)`：

  1. `sessions-v2/<id>` 存在 → 返回 v2（已迁移或新会话）。
  2. `sessions/<id>` 不存在 → 返回 v2（全新会话；首次写时创建。无 legacy
     历史，直接空起步不违反"禁止静默空历史"——本来就没有历史可掩盖）。
  3. `sessions/<id>` 存在且 v2 不存在（升级后恢复旧会话）：
     - `for_write=False`（status/diagnose/recovery-page/profile hint 等只读
       路径）→ 返回 legacy 树（只读视图）。
     - `for_write=True` → 执行 §2 迁移；被阻断时抛
       `SessionLockedByLegacyError`，事件按各自 fail 策略失败，**不写任何树**。

- 写入口审计（实现时逐点核对，全部经推导函数或显式双命名空间清扫）：
  `state.json`、`release-required` latch、`action-profile.json`、
  `recovery.json/md`、`prompts/` 记录、commentary 快照、corrupt 备份、
  decision log（state 内）全部位于 session_dir 之下；`cleanup_old_sessions`
  与 `find_latest_state` 扫描两个命名空间；export/successor pack 写入项目根
  （私有树之外），不属于本边界。Host transcript（`CODEX_HOME/sessions`）是
  宿主自有目录，不在本设计范围。

## 2. 旧会话恢复：显式迁移（禁止静默空历史）

触发：legacy 树存在、v2 树不存在、写上下文。

### 2.1 阻断条件（先于一切写入）

若 `sessions/<id>/.lock` **存在**——无论内容为 legacy 记录、protocol-2 记录、
空字节还是畸形数据——**立即拒绝**：抛 `SessionLockedByLegacyError`，事件
fail closed（PreCompact→systemMessage、Stop→stopReason、PreToolUse 保持
既有策略、显式命令→stderr [FAIL]），迁移不开始、不写任何树。
理由：文件存在即无法证明 writer 缺席（CGR-L1a/1b）；本设计**从不解析、
从不以年龄或内容推断 legacy writer 的生死**。

### 2.2 排他窗口（可行证明）

`.lock` 不存在时：以 `O_RDWR|O_CREAT` 创建它并取**本方内核锁**
（fcntl/msvcrt，即 §3 原语），持有至迁移完成。窗口内对 legacy writer 的
排除由 **protocol-1 自身的公开获取算法**给出，不依赖对方读任何新协议：

- legacy 获取 = `O_EXCL` 创建；文件已存在 → 失败进入竞争路径；
- 竞争路径仅在 `mtime > 30s` 时 unlink 偷取；窗口标记文件的 mtime 是新鲜的；
- legacy 的锁预算是 5s（`session_lock(timeout=5.0)`）< 30s；
- 因此窗口内每个 legacy 竞争者都在 5s 内超时 fail closed，不能进入、
  不能偷取、不能写 legacy 树。
- 并发的新 writer（同候选版本）由同一内核锁互斥；第二个迁移者在获锁后
  **复查 v2 树**：已被第一个迁移者 rename 发布 → 跳过迁移，释放窗口，
  正常进入 v2。

该证明只用对方的既有语义（O_EXCL、新鲜 mtime 不偷、5s 预算），不需要
对方配合、不读任何 marker、不用年龄断言对方生死。

### 2.3 快照与原子发布

- 窗口内把整个 legacy 树复制到
  `sessions-v2/.migrate-<id>-<uniq>/`（`copytree(symlinks=True)`；
  legacy 树在此期间只读——本设计不修改来源）。
- 写入 `migration.json`：`{schema: "session-migration/v1", source_namespace,
  source_state_sha256（content_hash）, source_prompts_sha256,
  window_acquired_at, migrated_at, runtime_tree_digest}`——**权威状态身份**：
  v2 树以自身 content_hash 链继续，migration.json 绑定分叉点；两个分支是
  不同身份，永不合并。
- `fsync` 后 `os.rename(staging, sessions-v2/<id>)`——目标是**唯一发布点**，
  rename 原子；发布前 v2 树对外不存在。
- 窗口锁文件**保留**（不 unlink）：迁移后 ~30s 内继续阻断 legacy writer；
  超时老化后 legacy 可按自身语义偷回旧树继续其历史分支。

### 2.4 回滚边界

- 迁移中途崩溃：staging 目录残留；来源树完好（全程只读）。下一事件重试
  迁移；迁移开始时先清扫本会话的陈旧 staging（>1 天或 pid 不存在）。
  staging 永不成为权威（唯一发布点是 rename）。
- 阻断路径无写入 → 无需回滚。
- 迁移成功后旧树保持原样：旧任务（旧版本 Hook）继续在 `sessions/<id>` 上
  工作直至结束，其写入留在旧树，由 migration.json 的分叉身份记录为历史
  分支；v2 树不受影响，也不回迁。

### 2.5 降级与旧任务

- 降级到 0.14.3：旧运行时推导 `sessions/<id>`——若迁移已发生，它继续使用
  旧树（≤30s 的 marker 延迟后按自身语义接管），v2 树对它不可见，成为
  历史分支。双向都不产生同树并发写。
- 同一会话的旧任务仍活着时升级恢复：§2.1 阻断（旧 writer 持锁）或 §2.2
  窗口期失败 fail closed（旧 writer 在窗口内竞争）；旧任务完成后重试迁移。
  网络文件系统/多主机共享 HOME 仍明确不支持。

## 3. v2 命名空间内的单 writer

- 原语：`fcntl.flock`/`msvcrt.locking`（偏移 0，1 字节，非阻塞重试 +
  monotonic deadline），`<session>/.lock` 稳定文件，writer 永不 unlink。
- 持有覆盖整个事件事务（load → 变更 → save）；owner 记录（protocol 2 JSON）
  仅诊断用，在新 writer 之间内核锁是权威，记录缺失/畸形无妨——**新命名
  空间内不存在需要从记录推断生死的对象**。
- 竞争超时按事件 fail 策略 fail closed；SessionEnd 保持 1.2s 有界预算。

## 4. 提交边界与所有权复核（CGR-L2 关闭）

- `save_state` 在构建内容前验证 `(st_dev, st_ino)`（fd vs path）；
- **第二次验证移入原子写内部、紧贴 `os.replace` 之前执行**，把检查-写入
  窗口压缩到相邻 syscall 级。残余窗口只剩"能进入私有目录的外部敌意进程"，
  与"能直接删除 state.json 的敌意进程"同级，超出威胁模型并如实记录。
- `st_ino == 0` 或身份原语不可用（FAT/exFAT 类）→ 抛 `LockOwnershipError`
  fail closed；**不再静默豁免**（CGR-L2b）。
- 失去所有权者不能提交成功、不能 unlink 后继者的锁文件、没有任何删除
  v2 状态的代码路径。

## 5. 双平台实现

- 内核锁与窗口锁共用 §3 抽象（POSIX fcntl / Windows msvcrt）；路径全程
  pathlib，长/CJK/空白路径行为与现状一致；staging 与 rename 在 Windows 上
  用 `os.rename`（目标不存在时原子）；`msvcrt.locking` 的字节范围/继承语义
  留待 Windows 原生批次确认（pending，不算通过）。终止测试平台感知：
  POSIX `SIGKILL`，Windows `terminate()`。

## 6. 全族回归（设计通过后实现，映射 R1 清单）

1. new/new 竞争（真实子进程，互斥 + 状态一致）。
2. old/new 双向：活 legacy holder（含人工老化 >30s）→ 候选**拒绝**（替代
   被 R1 点名的 aged-takeover 测试）；legacy 在 O_EXCL/写 owner 间暂停
   （空文件）→ 候选拒绝。
3. 窗口期 legacy 竞争者 fail closed（≤5s）；窗口后 legacy 按自身语义接管
   旧树，v2 树不受影响。
4. 提交检查后抢占（R1 CGR-L2 调度）：新命名空间内由内核锁排除；外部替换
   v2 锁文件 → 提交前/replace 前双重验证拦截，断言 state.json 未写、无
   成功返回。
5. 空/部分/畸形记录（legacy 树 → 拒绝；v2 树 → 内核锁权威，正常竞争）。
6. 获取/复制/rename 各阶段崩溃注入：staging 清扫、来源完好、无部分发布。
7. 排队 deadline；后继清理跨两命名空间；`st_ino=0` 注入 → 拒绝。
8. 写入口矩阵（state/latch/action-profile/recovery/prompts/decision log）
   全部落于解析后命名空间；断言**最终状态一致性**（content_hash 链、prompt
   计数、无丢失更新），不仅进程标记。
9. 真实 production API 驱动（R1 independent_probes.py 的三个调度转成
   断言：aged→refuse、empty-window→refuse、after-check→no-commit）。

## 7. 明确的非目标

- 不阻止旧任务在旧树上完成；不合并历史分支；不做后台守护或网络锁；
  不把 `sessions-v2` 出现当作已发布契约（Unreleased 标签保持到发布）。
- 本设计不改变默认 PreToolUse 快路径（零状态 I/O）与普通工具零审批。
