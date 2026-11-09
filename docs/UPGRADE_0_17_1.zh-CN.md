# 升级到 0.17.1

先确认当前 Codex 安装使用哪个 Context Guard 入口，并结束仍依赖旧运行时的任务。再按下面对应的路线升级。从发布附件下载正式 ZIP。[GitHub Release](https://github.com/GreenLv/codex-context-guard/releases/tag/v0.17.1)

[English](UPGRADE_0_17_1.md)

## 谁需要关注本次升级

- **0.16.1 用户**。公开 ZIP 使用 `context-guard@codex-context-guard-v016`。如果你通过本地市场包装安装同一个 ZIP，入口可能是 `context-guard@codex-context-guard-v0161`。先核对你当前启用的入口。两条路线均切换到 0.17.1 的稳定身份 `context-guard@codex-context-guard`。
- **0.17.0 稳定身份用户**：0.17.1 是同一身份下的原地升级。
- **0.15.1 用户**：历史路线继续按已声明合同覆盖；步骤相同，起点为 0.15.1 发布物。

## 你的日常入口

日常 Codex Desktop/CLI 的 HOME 保留自己的配置。升级只改变该 HOME 加载的插件版本，且只通过官方 Codex 市场操作完成；不改动项目、登录或模型设置，也绝不手改任何版本化插件缓存。

## 先处理旧任务

改动某个 HOME 的插件之前：

1. 先完成仍依赖旧运行时的任务，或把它们保留在单独配置、仍指向旧版本的 HOME 里。不要为了"保住"旧运行时而删除或手改版本化缓存。
2. 官方的同名或换身份操作可能移除旧缓存。缓存字节还在磁盘上并不能证明旧任务加载的是它；保留缓存不等于迁移。
3. 0.15.0 之前的旧版 `sessions` 目录本产品永不迁移；这类任务继续在原加载运行时下完成。

## 私有任务状态迁移

安装 0.17.1 后，私有会话仍留在原身份的数据目录。0.16.1 包装身份的目录是
`plugins/data/context-guard-codex-context-guard-v0161/`。稳定身份使用另一个目录，切换后需要按下文迁移才能在新入口找到这些状态。

如果希望旧会话在稳定身份的数据根下可见（例如日常切换后恢复与状态查询能直接找到它们），使用仓库迁移工具（[说明](https://github.com/GreenLv/codex-context-guard/blob/v0.17.1/tools/GUARD_STATE_MIGRATION.md)）：

- 默认只读：`inventory` 与 `plan` 不写任何状态。
- `apply` 在运行时自己的生命周期锁保护下按字节精确复制会话到目标数据根；已存在的目标会话绝不覆盖。两侧同 ID 但内容不同的会话隔离到数据根之外等待人工决定——时间戳永远不会决定覆盖。
- `verify` 复核每个复制摘要；`restore` 只撤销单次 apply 创建的路径，复制之后发生变化的路径一律拒绝删除。
- 0.15.0 之前的旧版会话、不可读或不支持的状态文件只报告、原地保留。

用显式 HOME 在仓库之外运行该工具，工作区与结果留在本机；私有状态不进 Git、不进附件。

## 在当前 HOME 中升级

1. 从发布附件下载 `context-guard-0.17.1.zip`，按发布页公布的 SHA-256 校验。将 ZIP 解压到自己控制的目录，并保留该目录作为市场来源。
2. 运行 `codex plugin list --json` 核对当前入口，确认依赖旧运行时的任务已结束。若已使用稳定入口，保留旧市场来源及其 ZIP，再运行 `codex plugin marketplace remove codex-context-guard` 移除原注册。这个操作可能移除旧版本缓存。若旧市场使用不同名称，保留旧注册。
3. 从新解压目录运行以下命令。保存 add 的返回结果，下一步用其中的 `installedPath` 核对缓存。

   ```shell
   codex plugin marketplace add .
   codex plugin add context-guard@codex-context-guard --json
   codex plugin list --json
   ```

4. 确认稳定入口已安装、已启用，版本为 `0.17.1`。运行 `python3 scripts/artifact_identity.py --compare-to "<installedPath>"` 逐文件核对，Windows 上用 `py -3`。若从不同身份切换，先在官方插件界面停用旧入口，再信任新版 Hook。
5. 新开一个 Codex CLI 会话，在 `/hooks` 中审核来自新缓存的九项 Hook。回到实际使用的入口，用一个会触发 Hook 的新任务验证它加载了新版。切换后如果 Desktop 仍显示旧插件，重启 Desktop 再核对。

## 预期结果

- 0.14–0.17.0 写入的 schema 13 状态无需迁移即可读取；未完成要求、等待、证据与恢复行为不变。
- 默认业务工具路径继续无执行审批；升级不引入新审批。
- 会话保留维护仍为显式开启：默认只预览，策略显式启用后才会删除。

## 恢复方法

- 日常切换前，保留已核验的旧插件制品（ZIP 及摘要）和原有注册/入口记录。同身份升级可能已删除旧缓存，恢复意味着用旧制品重新执行官方安装——不能假设按名字重新 add 就能找回。
- 迁移工具的 `restore` 只撤销本次迁移创建且内容仍相同的副本。
- 任何一步失败都保留原始失败记录；绝不就地修复已消费缓存。

## 实现说明

[原生升级工具](https://github.com/GreenLv/codex-context-guard/blob/v0.17.1/tools/validation/NATIVE_UPGRADE_ACCEPTANCE.md)记录每台主机使用的版本、包摘要和工具提交。[状态迁移工具说明](https://github.com/GreenLv/codex-context-guard/blob/v0.17.1/tools/GUARD_STATE_MIGRATION.md)列出复制、冲突和恢复检查。原生检查、制品、CI 和发布结果分别记录。[验收记录](LOCAL_ACCEPTANCE.md)
