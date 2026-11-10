# 升级到 Context Guard 0.17.2

先运行 `codex plugin list --json`，确认自己安装的入口。更换入口前，请完成仍依赖旧插件的任务，或者把它们留在另一个仍加载旧版的 Codex 环境。磁盘上留有旧缓存，并不能说明现有任务下一轮会加载哪个 Hook。

[English](UPGRADE_0_17_2.md) · [发布附件](https://github.com/GreenLv/codex-context-guard/releases/tag/v0.17.2)

## 升级前先了解清理变化

从 0.17.2 起，结束会话后会自动维护符合条件的 Context Guard 记录。没有配置保留策略时，结束超过 30 天的会话可以进入可恢复隔离区。隔离至少 7 天后，后续普通使用可以触发永久删除。活动、未完成、仍需恢复和无法核实身份的会话仍受保护。

已禁用的策略、自定义保留时间、仅隔离设置和持久关闭记录继续生效。策略损坏或无法读取时，不会授权删除。策略缺失时则使用自动默认值。如果仅隔离策略丢失，且没有持久关闭记录，默认策略允许隔离期后永久删除。

在 0.17.1 中，`--maintenance-disable` 移除定时任务时不会留下持久关闭记录。如果此前仅以这种方式关闭维护，且没有保留策略，0.17.2 会采用自动默认值。如果希望升级期间始终关闭维护，请先在 0.17.1 发行包解压目录运行以下命令，将路径替换成目标入口的数据目录。命令会写入禁用策略。升级后再在 0.17.2 解压目录运行同一命令，写入持久关闭记录。后续升级会遵守这条记录。

```shell
python3 scripts/context_guard.py cleanup --data-dir "/path/to/plugin-data" --policy disable
```

Windows 上用 `py -3` 代替 `python3`。数据目录的确认方法和策略查看命令见[会话存储与清理](SESSION_STORAGE.md#inspect-customize-or-turn-off-automatic-maintenance)。如果有多个入口或 Codex 配置目录，请先确认目标再运行。

切换版本前，把命令中的 `--policy disable` 换成 `--policy show`，确认 `enabled` 为 `false`。用 0.17.2 再次关闭后，运行 `--policy show`，在 `automatic_maintenance` 中核对持久关闭记录。

## 原地升级稳定入口

以下步骤适用于已启用的 `context-guard@codex-context-guard` **0.17.1**。如果你使用其他入口或更早版本，先按 [0.17.1 升级指南](UPGRADE_0_17_1.zh-CN.md)切换，核对稳定入口及其数据目录，再回到这里升级到 0.17.2。这套步骤会启用新安装的插件。如果想让插件继续保持禁用，请暂缓执行。

1. 保存现有 0.17.1 市场来源和已核验的发行 ZIP。从发布附件下载 `context-guard-0.17.2.zip`，核对发布页公布的 SHA-256，然后解压到自己管理的目录，作为新的市场来源保留。
2. 保存旧来源后，运行 `codex plugin marketplace remove codex-context-guard`。这一步可能移除旧插件缓存。
3. 在新版解压目录运行：

   ```shell
   codex plugin marketplace add .
   codex plugin add context-guard@codex-context-guard --json
   codex plugin list --json
   ```

4. 保存安装命令返回的 `installedPath`。确认列表中只有一个已启用的稳定入口，版本为 `0.17.2`，市场来源指向新目录。在解压目录用 `python3 scripts/artifact_identity.py --compare-to "<installedPath>"` 核对已安装文件。Windows 用 `py -3` 代替 `python3`。
5. 新开一个 Codex CLI 任务，输入 `/hooks`，检查九个 Context Guard Hook 的来源。确认来源与 `<installedPath>/hooks/hooks.json` 一致后，通过正常界面审核并信任。再在日常使用的客户端新开任务，确认实际加载的版本。Desktop 可能需要重启后才会加载新入口。

同一入口升级后，已有任务记录仍在原数据目录。正在运行的旧任务是否继续使用旧 Hook，需要在实际客户端核对。需要重装旧版时，请使用已核验的旧发行来源和官方市场命令。如果操作失败，保留结果并先核对实际安装状态。详情见[会话存储](SESSION_STORAGE.md)和[兼容性说明](COMPATIBILITY.md)。
