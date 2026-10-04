# 受保护 ACL 矩阵夹具构造 v2

这是尚未发布的 0.15.1 验证契约：为测试对象设置保护时，明确保留受控继承来源提供的权限。新 profile 为 `explicit-retained32`，报告 schema 为 `incident-acl-mechanism-matrix/v2`，构造契约为 `protected-explicit-retention/v2`。此修订仅作用于验证夹具，不改变产品运行时，也不自动转换用户 ACL。

例如，一个受保护文件原计划有四条显式 allow ACE 和三条继承来源 allow ACE。新构造保留全部七条，只清除后三条 ACE 的 `INHERITED_ACE` 标志（`I`，`0x10`），结果为七条显式 ACE；读回只有四条仍判失败。描述符的 `AUTO_INHERITED`（`AI`，`0x400`）是另一个控制位，`1004` 与 `1404` 仍须分别验证。

## 新契约的覆盖范围

未保护目标（`0004`、`0404`）保留真正的继承 ACE。受保护目标（`1004`、`1404`）统一命名为 `inherited_source_retained_as_explicit`，包括 actor 条目来自继承源的情况；这些格不证明受保护目标保留真实 `I` ACE。actor shape 描述构造来源，不能把转换后的磁盘条目称为继承条目。

所有受保护目录格还会在 S1 前，将目标的独占后代构造为 `1404`，并把每条声明的继承来源 allow ACE 保留为显式条目。这使目标上的 grant/deny 不会传播到后代；条目的 OI/CI/IO/NP 等其他标志保持原值。这些目录格与旧格含义不同，不证明受保护后代的真实继承，也不推断一般权限等价。未保护目录格继续真实继承，全族检查仍然严格：出现未声明传播就保留失败。

只允许转换精确声明的普通 allow 继承尾部。条目数量、顺序、SID、类型、权限掩码和其他标志必须匹配。继承 deny、creator 替换、object/conditional ACE、generic 权限、未知标志或版本、非 canonical 顺序均关闭失败。原有显式 deny 仍在 allow 前，构造器不会通过排序修补输入。

## 构造和恢复

collector 独占新建夹具，固定全族清单、验证对象身份，并拒绝 link/reparse 对象。第一次 ACL 写入前，必须持久化全族原始状态 S0。新增目标和后代步骤前，必须先保存从受控来源计算的完整计划，包含每个最终描述符及各中间全族状态；意外原生读回不能成为计划。

后代按先深后浅顺序设置保护，每一步精确验证全族、对象身份和只读外部 guard。步骤失败时先保存观测，再完整恢复 S0，不能建立已接受的 S1。构造成功后，从一致的全族读回建立 S1。原有 target-only 业务检查、S1/S0 完整恢复、`specific-write-deny/v2`、真实受限子进程读写核验及零私有写入要求均不放宽。

## 执行与证据含义

使用 `tests/test_incident_acl_family.py` 既有 `--mechanism-matrix` 入口，选择 `--cell-profile explicit-retained32`。提供完整源码 commit、helper 和 runner 的 SHA-256、不同的 collector/普通 actor SID、独占输出位置及 fixture parent；先用实际参数运行 `--preflight`。预检输出全部 32 格映射及描述符计划，不调用 Windows API、token 或模型；它核验输入，不证明原生可构造性。

v2 成功只能证明新构造契约。旧 `full32`、`protected8` 仍使用 v1 含义，旧失败不改判为通过。原始 DACL 写入丢失 AI、保护调用未产生 P、保护后删除继承尾部，仍保留为负例。v2 矩阵不调用模型，不能替代真实受限子进程 token 或完整 Windows host 验收。本源码候选的 v2 原生验收仍待执行。

## 与旧 32 格逐一对应

编号沿用旧的失败优先执行顺序；每一旧格均保留，不删除失败格。E 表示继承来源条目保留为显式，I 表示真实继承 ACE。受保护目录同时把目标后代构造为 `1404`、E；文件没有目标后代。

| 编号 | 对象 | 目标控制 | actor 来源形态 | v2 目标含义 | 目标后代 |
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

[English](ACL_MATRIX_FIXTURE_V2.md) · [既有 host 验收契约](INCIDENT_HOST_ACCEPTANCE.md)
