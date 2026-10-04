# 来源互异的只读 ACL 矩阵夹具 v3

这是尚未发布的 0.15.1 源码候选，采用新 profile `distinct-source32`、报告 schema `incident-acl-mechanism-matrix/v3` 和构造契约 `distinct-read-source-retention/v3`。它验证受保护夹具的构造，并避免人为制造重复显式 ACE。v3 原生验收尚未运行；源模型不能证明 Windows 行为，也不能替代真实受限子进程 token。

例如，受保护文件目标保留四条显式管理权限和三条来自不同主体的继承来源只读权限。只清除 I 后，七条均保留，后三条不会成为前三条的副本。三个来源均为既有 well-known 主体：Everyone（`S-1-1-0`）、Authenticated Users（`S-1-5-11`）、Builtin Users（`S-1-5-32-545`）；specific mask 为 `0x1200a9`，提供读、列举、遍历权限而不提供写权限，来源标志为 OI|CI。这是有明确含义的新夹具覆盖，不与旧 full-control 来源推断权限等价。

## 覆盖范围和旧失败

collector、System、Administrators、OWNER_RIGHTS 的显式管理权限保留。独占根目录保留不带继承标志的管理条目，再增加三条可继承的只读来源。actor 来源形态仍为 missing、显式 allow、继承来源 allow、显式 deny。missing 只表示无直接 actor 条目，不代表没有经组获得的有效读权限。创建夹具和写 ACL 前，actor、collector 必须彼此不同且不与任何固定角色重合。未知主体、mask、ACE 类型、标志、control，以及非 canonical 或重复的构造条目均关闭失败。

旧 32 格身份全部逐一映射保留，新来源统一用于全部格。文件目标和所有受保护目录格的叶子一并检查；只改首个文件仍会留下八个目录叶子的重复条目问题。v1/v2 报告保留各自身份和失败。setter 返回成功但把计划七条改成四条，仍然是失败；v3 成功不能改写此观察，也不能证明 Windows 普遍去重。

未保护格继续使用真正的 I ACE。受保护目标统一称为 `inherited_source_retained_as_explicit`：只清除 I，保留 SID、类型、mask、顺序和其余标志。描述符 AI 与 ACE I 不同，`1004` 和 `1404` 仍分别验证。所有受保护目录格在 S1 前，按先深后浅顺序把目标的独占后代明确构造为 `1404`，并保留其受控继承来源 allow 为显式条目。这些格不证明受保护真实 I 覆盖，也不与 v1/v2 的权限声明相等。

## 构造与 setter 观测

collector 独占新建夹具，首次写入前持久化全族原始 S0。目标、后代描述符、传播状态和处理顺序均从声明来源预先计算，在新增步骤前保存并逐步核验。link/reparse、身份或库存变化、外部 guard 变化仍判失败；原始 S0、S1 和观测 ACL 从不去重或归一化。

Named 构造写入使用夹具侧有界包装，观察已有的 `GetSecurityDescriptorDacl` 调用，并验证返回 PACL 指向精确计划描述符的活跃 buffer。包装从该已绑定 buffer 捕获完整 ACL，不解引用未知指针；原始 ACL 随原始私有快照保存（平台支持时请求 mode0600），并在调用原 setter 一次前，持久化条目有序 hash、大小/数量、选定 API 和 flags。提取不新增 API 调用。指针、buffer、路径、flags、调用次数或证据存储不匹配时停止构造，不回退、不重试。原生结果继续传递；后续证据保存也失败时，仍保留先发生的主失败。

观测只覆盖 Named 夹具构造，包括建立 `1004` 所用的 `1404` 中间步；不覆盖原始 `SetFileSecurityW` 赋值、业务 grant/deny 或恢复，它们继续使用已有严格核验。原始 ACL 文件只保留在预先核验的私有输出目录；POSIX mode 本身不能证明 Windows ACL 边界。传输只能包含 hash、结构及绑定的附件索引。产品 Hook 运行时和原始 ACL helper 未改。SDK mock 验证 Python 传递和拒绝行为，不证明真实 Windows ABI 或内部归并。

构造成功后，以一致的全族观测冻结 S1。目标上的业务变更不能改变其余家族和外部 guard，S1/S0 精确完整恢复仍是必需条件。`specific-write-deny/v2`、原始/授读/拒写三个 baseline、真实受限子进程可读与写拒绝、零私有写入、正常 Hook 信任及原始 host 门槛均不放宽，矩阵不能替代这些观察。

## 调用与验收

使用 `python -B -m tests.test_incident_acl_family --mechanism-matrix --cell-profile distinct-source32`，提供完整源码 commit、helper/runner SHA-256、不同的真实 actor/collector SID、独占输出及 fixture-parent 参数。先用实际参数运行 `--preflight`。输出位置不能与源码重叠，也不能是源码祖先。预检核验全部 32 格计划，不调用 API、token 或模型，不能证明原生可构造性。

实际执行在首个失败后先保存证据并尝试完整恢复，再停止；剩余格明确为未运行。协调方批准的前置条件未满足时，原始 Windows full host profile 必须保持未运行；矩阵通过也不能单独证明该 profile。原生预算和授权由 CLI 外的协调流程控制，此源码候选本身不授权新原生运行。

## 与 v1/v2 逐格对应

顺序仍为失败优先；每格保留 v1/v2 的对象、目标 control 和 actor 来源形态。全部 v3 格采用三条来源互异的只读权限，并保留显式管理权限。E 表示继承来源保留为显式，I 表示真实继承；文件无目标后代。

| 编号 | 对象 | 目标 control | actor 来源形态 | v3 目标含义 | 目标后代 |
| --- | --- | --- | --- | --- | --- |
| 1 | file | 1404 | missing | E | — |
| 2 | file | 0004 | missing | I | — |
| 3 | file | 0004 | explicit | I | — |
| 4 | file | 0004 | inherited | I | — |
| 5 | file | 0004 | deny | I | — |
| 6 | file | 0404 | missing | I | — |
| 7 | file | 0404 | explicit | I | — |
| 8 | file | 0404 | inherited | I | — |
| 9 | file | 0404 | deny | I | — |
| 10 | file | 1004 | missing | E | — |
| 11 | file | 1004 | explicit | E | — |
| 12 | file | 1004 | inherited | E | — |
| 13 | file | 1004 | deny | E | — |
| 14 | file | 1404 | explicit | E | — |
| 15 | file | 1404 | inherited | E | — |
| 16 | file | 1404 | deny | E | — |
| 17 | directory | 0004 | missing | I | I |
| 18 | directory | 0004 | explicit | I | I |
| 19 | directory | 0004 | inherited | I | I |
| 20 | directory | 0004 | deny | I | I |
| 21 | directory | 0404 | missing | I | I |
| 22 | directory | 0404 | explicit | I | I |
| 23 | directory | 0404 | inherited | I | I |
| 24 | directory | 0404 | deny | I | I |
| 25 | directory | 1004 | missing | E | 1404 / E |
| 26 | directory | 1004 | explicit | E | 1404 / E |
| 27 | directory | 1004 | inherited | E | 1404 / E |
| 28 | directory | 1004 | deny | E | 1404 / E |
| 29 | directory | 1404 | missing | E | 1404 / E |
| 30 | directory | 1404 | explicit | E | 1404 / E |
| 31 | directory | 1404 | inherited | E | 1404 / E |
| 32 | directory | 1404 | deny | E | 1404 / E |

[旧 v2 契约](ACL_MATRIX_FIXTURE_V2.zh-CN.md) · [English](ACL_MATRIX_FIXTURE_V3.md)
