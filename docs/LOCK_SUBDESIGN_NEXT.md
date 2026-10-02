# 会话锁与状态所有权子设计（修订 4：隔离、只读、不迁移）

状态：R3 裁决批准的 source candidate 实现边界，2026-10-02；尚未冻结或发布。
本修订取代修订 1–3 的在线、首次写和 ended-only 迁移设计。否决依据见
[NEXT_CANDIDATE_REVIEW_R3.md](NEXT_CANDIDATE_REVIEW_R3.md)。

## 1. 所有权与升级

新会话写入 `<data_root>/sessions-v2/<id>/`；旧会话与旧缓存原样保留。
解析优先既有 v2，再 legacy，均不存在才创建 v2。新运行时遇到 legacy
严格只读：不修复、不记录提示、不保存恢复、不迁移、不清扫，不空起步。
status、diagnose、recovery-page 可以读取旧记录；全部写命令拒绝。
普通 PreToolUse 保持无审批路径；明确采用的 release 状态不可验证时拒绝。
Stop/PreCompact 返回有界诊断，不能把无法验证的历史要求当成完成。

本版没有迁移命令。`ended_at` 记录 SessionEnd，不是不可再写的终态屏障。
实测旧运行时在 SessionEnd 后仍接受提示且标记保留，所以时间戳、mtime、
锁缺失、marker 老化、钩子间隙都不能证明旧 writer 静默。N09 不削弱。

旧任务应在原运行时继续。旧缓存存在只证明磁盘保留，不能证明 Codex
加载了它；宿主续跑必须核对原 session、实际 Hook 路径/摘要和保留的未完成
要求，再观察正常 trust 下的提示、工具、Stop、恢复。源码子进程续跑可证明
旧 API 仍可写，不能代签宿主加载。该原生门槛在集成复核后执行。

## 2. v2 生命周期锁与提交

每个受支持 writer 经 `session_lock`，持锁后创建/加载会话并贯穿事务。
锁位于 `sessions-v2/.locks/<id>.lock`，在可删除会话子树外；释放、cleanup
均不 unlink。进程队列与内核锁共享同一总等待预算，SessionEnd 总锁预算
1.2 秒，受宿主 3 秒期限约束。POSIX 用 fcntl，Windows 用 msvcrt；运行时
仅标准库。所有权校验包含 fd/path 身份；零 inode 不可证明所有权，fail closed。
外部同权限篡改不属于排他证明，身份检查仅是硬化，不能取代生命周期锁。

cleanup 只扫 v2；先取得同一个生命周期锁，再读取完整有效状态和保留期，
删除会话子树但保留锁文件。v2 在结束后恢复写入时清除旧 ended_at，
避免旧保留标记在另一事件中删除已恢复的任务；legacy 标记不改。并发 writer 使 cleanup 超时跳过；排队 writer
只能在 cleanup 释放后创建/读取。legacy 永不加入扫描。结束时间仅是持锁内
的保留资格，不是无 writer 证明。

## 3. 验证与边界

`test_session_namespace` 验证新会话、旧树只读、普通工具/release 边界、
cleanup 持锁重读与 ended_at 反例；`test_session_lock_protocol` 验证真实子进程
互斥、暂停/终止、锁替换和旧/新隔离。CLI 与九事件必须使用同一写路由。
原生 Windows、宿主旧任务续跑与安装证据单独验收。

冻结 0.12 测试字节不改。transition harness 仅把独立导入的测试运行时
v2 命名空间定位到冻结 fixture 硬编码的 synthetic `sessions` 根，保留全部
语义断言和既有 manifest；这不是产品迁移，也不证明双命名空间行为。
生产双命名空间由当前测试单独验证，不能把路径失败直接归为语义通过。
