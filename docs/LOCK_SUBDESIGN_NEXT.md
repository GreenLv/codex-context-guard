# 会话锁与状态所有权子设计（下一版本候选）

状态：WP-01 交付稿，供协调者有界审查；不是已冻结的运行契约。日期：2026-10-02。
源码 subject：基线 `d24899d8202a58d7426208541c58d193464e93de`，候选分支
`candidate/next-gpt6-perf`（实现提交见回交）。对应缺陷：CGN-01（已复现，P1）、
CGN-08（故障注入核实中）。不变量：N07（单 writer）、N05（fail closed）、N09
（旧缓存/旧任务不可变）。

## 1. 缺陷与目标

基线 `filesystem_session_lock` 有两类已证实缺陷：

1. **mtime 租约**：锁文件 mtime 超过 30 秒即被竞争者 unlink。持锁进程被暂停、
   遇到慢 I/O 或时钟变化时可被第二个进程夺锁，两个真实进程同时进入临界区
   （合成反例已重放）。finally 还按路径无条件 unlink，旧 owner 退出时可以删除
   新 owner 的锁文件。
2. **所有权无提交校验（CGN-08）**：owner 内容写在进入 try/finally 之前，写失败
   会遗留 descriptor/文件；进程内 `threading.Lock.acquire()` 无界等待，而宿主给
   SessionEnd 只有 3 秒。

目标：把"同一私有状态最多一个 writer"从"路径排他存在"升级为内核锁 +
提交时所有权复核，使任何一方的锁文件被删除、替换或偷取都不能变成一次成功
的状态写入。不引入后台进程、网络锁或分布式语义；网络/多主机共享 HOME 仍明确
不支持。

## 2. 协议（lock protocol 2）

- **原语**：稳定的 `<session>/.lock` 文件上的内核咨询锁。
  - POSIX：`fcntl.flock(fd, LOCK_EX | LOCK_NB)`，非阻塞重试。
  - Windows：`msvcrt.locking(fd, LK_NBLCK, 1)`，先 `os.lseek(fd, 0, SEEK_SET)`，
    锁偏移 0 的 1 个字节；字节范围锁允许超出文件末尾。
  - 两者都只在标准库内；fd 以 `O_RDWR | O_CREAT`、0o600 打开，默认不可被子
    进程继承（PEP 446）。
- **线性化点**：内核锁获取成功的那次系统调用。protocol 2 writer 之间，互斥
  由内核保证，与文件内容、mtime、PID 无关。
- **持有者身份**：获取内核锁后，writer 在文件偏移 0 写入一条 advisory owner
  记录（JSON：`lock_protocol=2`、`pid`、`token`（`secrets.token_hex(16)`）、
  `created_at`）。记录仅用于诊断与 legacy 判别，不是锁本体；新 writer 获锁后
  直接覆写。
- **等待**：25ms 重试间隔 + monotonic deadline（沿用 `timeout` 参数，默认 5s；
  SessionEnd 路径由调用方传入 ≤3s 预算）。超时抛 `TimeoutError`，fail closed，
  与现状一致。进程内 `threading.Lock.acquire()` 改为带剩余时间的有界等待
  （修复 CGN-08 的无界排队）。
- **文件生命周期**：protocol 2 **永不 unlink** `.lock`。文件随会话目录生命周期
  存亡（`cleanup_old_sessions` 清理整个会话目录；其必须跳过活跃会话，见 §6）。
- **退出/崩溃**：进程死亡时内核自动释放锁；遗留的 owner 记录是过时数据，下个
  writer 获锁后覆写。不存在"崩溃遗留永久不可恢复锁"的状态：获取只依赖内核
  锁，不依赖文件内容。
- **提交时所有权复核**：`session_lock` 把当前 guard 登记到线程局部；
  `save_state`（及经由它的 `atomic_write_json` 路径）在写 state.json 前调用
  `verify_lock_ownership()`：`os.fstat(lock_fd)` 与 `os.stat(lock_path)` 的
  `(st_dev, st_ino)` 必须一致，否则抛 `LockOwnershipError`，本次事务不落任何
  私有状态（fail closed）。这是对"失去所有权者不能提交成功"（N07）的直接
  承接：即使本进程的锁文件被外部 unlink/替换，状态也不会被偷写。`st_ino` 为 0
  的文件系统无法核验，复核跳过并在日志层记录（不视为失败）。
- **CGN-08 打开序列**：`open → flock → (try: 写 owner 记录) → yield → 释放`。
  owner 写失败时关闭 fd 并抛错；因文件不会被 unlink，无需清理路径，下一 writer
  直接对同一文件获锁。

## 3. 旧版本（protocol 1）互操作

protocol 1 = 现状算法：`O_EXCL` 创建 + mtime>30s 即偷取 + finally 按路径
unlink；它不认识内核锁。**在同一会话目录上，protocol 1 与 protocol 2 无法
互相提供硬互斥**——这是旧算法自身缺陷的推论，不是新协议可以单方面修复的。

已实现的防御规则（保守方向，全部 fail closed）：

| 发现的 `.lock` | protocol 2 行为 |
| --- | --- |
| 不存在 | `O_CREAT` 创建并获内核锁（与 protocol 1 的 O_EXCL 竞争在同一 syscall 线性化） |
| 内容为 protocol 2 owner 记录（或不可解析） | 直接对当前 inode 获内核锁；内核锁是权威 |
| 内容为 protocol 1 记录（`<pid> <epoch>`）且 mtime 年龄 < 30s | **拒绝获锁**（TimeoutError，带诊断）。无法证明旧 writer 已死，不得接管（P07"无法独占必须不写"） |
| 内容为 protocol 1 记录且年龄 ≥ 30s | 按旧协议自身语义判定为已崩溃的旧 writer，获内核锁接管并覆写记录（与旧代码对 30s 陈锁的处置一致，不引入更差行为） |

边界（如实声明，不以经验判断替代）：

- **旧 → 新**：一个仍在运行的 protocol 1 进程可以在 POSIX 上 unlink protocol 2
  的锁文件并进入临界区（mtime 偷取）。protocol 2 writer 的提交时复核会把这次
  干扰转为自身 fail closed（不写状态、不提交成功），但**不能阻止旧进程写**。
  旧进程的写入保持原子替换（整文件），不会与 protocol 2 的写入字节交错。
- **新 → 旧**：protocol 2 从不 unlink、从不按年龄偷取，因此 protocol 2 不会
  破坏一个活的 protocol 1 持有者。回滚到旧版本时，遗留的 protocol 2 锁文件会让
  旧 writer 在首个事件上经历一次 30s 偷取等待（SessionEnd 3s 预算下表现为
  fail closed 超时）；旧 writer 完成该事件后会 unlink，其后恢复正常。此为
  回滚场景的已知降级，不产生状态损坏。
- **部署边界**：一个会话在受支持的操作模型下绑定一个已安装插件版本（不可变
  缓存；一个宿主持有一个会话）。跨版本并发写同一会话目录不在支持范围内；
  上述规则只是把该越界情形的后果收敛为"新 writer fail closed + 原子替换不
  交错"，而不是宣称双向硬互斥。

### 备选方案 B（未实施，需协调者决定）

数据目录命名空间隔离（例如 `sessions-v2/` + 迁移）可以把旧→新方向也变为硬
互斥，但改变安装/恢复契约，需要真实停写/独占证明与不可变源快照迁移。本候选
保留现有存储（方案 A），不切换私有数据目录；若协调者要求硬隔离，方案 B 的
迁移设计在此子设计审查通过后另行提交。

## 4. 与默认路径的关系

锁变更只影响需要写私有状态的事件路径（`dispatch` 及显式命令的
`session_lock`）。PreToolUse SAFE 快路径本来就不加锁、不读私有状态，保持
零变化。普通工具不因锁失败新增审批或阻止；锁超时/所有权失败按各事件既有
fail 策略呈现（PreCompact systemMessage、Stop stopReason、PreToolUse fail-open
除非显式 release 契约生效）。

## 5. 测试矩阵（P06/P07 映射）

`tests/test_session_lock_protocol.py`（真实子进程 + 确定性屏障，无 monkeypatch
理想状态；可移植测试在 POSIX/macOS 上执行，Windows 字节范围锁语义留待
Windows 原生批次确认）：

1. 两个真实进程竞争：同一时刻至多一个持有者（共享 state append 计数验证）。
2. **CGN-01 回归（旧代码失败）**：持锁者存活、锁文件 mtime 被人工老化 31s，
   竞争者必须超时失败而不是偷取。
3. 释放不删后来者的锁：释放后 `.lock` 仍在，后续获锁成功（替代旧的
   "释放后文件不存在"断言——这是有意的行为变更）。
4. **提交复核（旧代码失败）**：事务中外部 unlink+替换锁文件 → `save_state`
   抛 `LockOwnershipError`，state.json 未被写入。
5. 崩溃注入：`SIGKILL` 持锁子进程 → 竞争者在 deadline 内获锁，owner 记录被
   覆写，状态可用。
6. legacy 双向：新鲜 legacy 记录 → 快速拒绝；≥30s legacy 记录 → 接管并覆写；
   protocol 2 记录 → 正常竞争。
7. 旧算法模拟器（按 protocol 1 步骤逐步执行的真实子进程）与 protocol 2 持有者
   并发：protocol 2 提交复核拦截自身写入（POSIX 观察点），旧模拟器的写入落地；
   断言无字节交错。
8. 进程内有界等待：`threading` 队列在 deadline 内得到 `TimeoutError`；既有
   `test_process_queue_wait_does_not_consume_filesystem_lock_timeout` 语义保留
   （更新文件存活断言）。
9. SessionEnd 预算：竞争下 `session_lock(timeout=2.5)` 在 3s 内失败，无状态
   破坏。
10. 各边界崩溃注入（acquire/write/save/release）：`save_state` 失败不留成功
    状态（N08）。

## 6. 复核项（交协调者确认）

1. 方案 A（保留现有存储 + 上述互操作边界）是否接受，或要求方案 B 命名空间
   隔离另行设计。
2. "释放后锁文件不存在" → "稳定锁文件" 的可观察行为变更，以及随之而来的
   版本处理（建议按新 writer 生命周期记 0.15.0，Unreleased 标签保持到发布）。
3. 提交时复核跳过 `st_ino == 0` 文件系统的可接受性（主流 macOS/Windows 本地
   文件系统均提供 inode 等价物；FAT/exFAT 类不支持）。
4. Windows `msvcrt.locking` 字节范围语义、关闭/继承行为需 Windows 原生批次
   确认（本批次无法原生验证，已标 pending，不算通过）。
