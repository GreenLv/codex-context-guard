# 升级到 Context Guard 0.17.1

先用 `codex plugin list --json` 看自己正在用哪个入口。更换入口前，请完成仍依赖旧插件的任务。如果暂时做不完，可以把它们留在另一个仍加载旧版的 Codex 环境里。磁盘上还留着旧缓存，不能据此判断任务下一轮会加载哪个版本。

[English](UPGRADE_0_17_1.md) · [发布附件](https://github.com/GreenLv/codex-context-guard/releases/tag/v0.17.1)

## 选一条升级路线

| 当前安装 | 怎么升级 |
| --- | --- |
| **0.17.0**，`context-guard@codex-context-guard` | 在原入口升级。移除旧市场注册前，保存旧市场来源和 ZIP。 |
| **0.16.1**，公开 ZIP（`…@codex-context-guard-v016`）或本地包装（`…@codex-context-guard-v0161`） | 切换到 `context-guard@codex-context-guard`。保留名称不同的旧市场注册，在信任新版 Hook 前停用旧入口。 |
| **0.15.1**，`context-guard@codex-context-guard` | 也按同名入口升级。保留原版 0.15.1 的发行来源，以便需要时重装。 |

项目、登录和模型设置仍在原来的 Codex 配置目录。官方市场操作可能移除旧插件缓存。有回退需要时，先留好已核验的旧发行包。

## 安装并核对

1. 从发布附件下载 `context-guard-0.17.1.zip`，核对公布的 SHA-256。把 ZIP 解压到自己管理的目录，并保留这个目录作为市场来源。
2. 如果旧市场也叫 `codex-context-guard`，在保存旧来源后运行 `codex plugin marketplace remove codex-context-guard`。这一步可能移除旧缓存。旧市场名称不同时，保留它的注册。
3. 在新解压的目录里运行：

   ```shell
   codex plugin marketplace add .
   codex plugin add context-guard@codex-context-guard --json
   codex plugin list --json
   ```

4. 保存安装命令返回的 `installedPath`。核对列表中只有一个稳定入口，版本是 `0.17.1`，已安装且已启用。在解压目录里用 `python3 scripts/artifact_identity.py --compare-to "<installedPath>"` 核对所有已安装文件。Windows 用 `py -3` 代替 `python3`。如果这次换了入口，请在官方插件界面停用旧入口，再信任新版 Hook。
5. 新开一个 Codex CLI 会话，输入 `/hooks`。逐项查看九个 Context Guard Hook，确认来源是 `<installedPath>/hooks/hooks.json` 后，在正常界面中信任它们。然后回到日常使用的客户端，新开一个会触发 Hook 的任务，确认加载的是新版。如果 Desktop 仍显示旧版，重启后再核对。

## 换入口后查看旧任务

升级不会搬动 Context Guard 保存的记录。同一入口升级时，新版可以直接读取已有的状态格式 13。换入口时，新旧插件的数据目录不同。例如 0.16.1 包装入口的记录放在其 Codex 配置目录下的 `plugins/data/context-guard-codex-context-guard-v0161/`。

如果希望在新入口查到旧任务进度，可以使用[迁移工具](https://github.com/GreenLv/codex-context-guard/blob/v0.17.1/tools/GUARD_STATE_MIGRATION.md)，在同一台机器上预览并复制 `sessions-v2` 格式的记录。同一会话在两边内容不同时，工具保留新入口已有的记录，把旧记录的副本单独存放。撤销只移除选定迁移操作创建、且内容未变的副本。旧版 `sessions` 记录和无法读取或不受支持的记录都留在原处。

运行工具时请明确指定要用的 Codex 配置目录。迁移工作目录和结果留在本机，放在 Git 和共享附件之外。复制记录不会转移 Hook 的信任状态，也不会把正在运行的任务搬到新环境。

## 回退与验证范围

- 要重装旧版本，请用原先核验过的发行来源走官方安装流程。只按插件名重新添加，不一定能找到原版本。遇到失败，先保留错误信息、核对实际安装结果。
- 平时修改文件和调用工具仍使用 Codex 权限。清理命令默认只预览，开启保留策略和定时维护是两件事。见[会话存储与清理](SESSION_STORAGE.md)。
- macOS 和 Windows 的隔离 Codex CLI 环境都用正式 ZIP 测过 0.16.1 本地包装、0.17.0 原地升级和 0.15.1 三条路线。[验收记录](LOCAL_ACCEPTANCE.md)将这些结果与日常使用、真实任务数据迁移分开记录。
