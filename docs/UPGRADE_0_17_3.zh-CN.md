# 升级到 Context Guard 0.17.3

[English](UPGRADE_0_17_3.md) · [发布附件](https://github.com/GreenLv/codex-context-guard/releases/tag/v0.17.3)

0.17.3 为维护者提供统一维护的日常升级工具。Hook 行为与清理设置沿用 0.17.2。该工具位于本版源码仓库，不安装到插件缓存。

## 准备稳定入口升级

以下流程适用于已启用的 0.17.2 稳定入口 `context-guard@codex-context-guard`。如果使用更早版本或其他入口，请先按 [0.17.2 指南](UPGRADE_0_17_2.zh-CN.md)处理，包括其中的清理设置说明。如果希望插件保持禁用，请保持原状态，待决定启用时再执行此流程。

保存上一版经核验的 ZIP 和市场来源目录。下载并核验 `context-guard-0.17.3.zip`，解压到长期保留的目录，作为新市场来源。操作工具另从标签 `v0.17.3` 对应的源码仓库取得。

按[日常升级工具说明](https://github.com/GreenLv/codex-context-guard/blob/v0.17.3/tools/validation/DAILY_UPGRADE.md)填写私有计划，明确发行包目录、CLI 和 Desktop 可执行文件。退出 Desktop 前先完成命令预检与准备阶段。结果保存在源码仓库和日用配置目录以外。

先运行 `--preflight-commands`，再对同一个待创建批次运行 `--prepare`。单独的 `--preflight` 会创建自己的输出目录，需与升级批次分开。如果准备结果是 `already_current`（已是目标版本），跳过 `--apply` 安装阶段，直接运行 `--verify` 核验；不要为核验重复安装。两种壳层的完整命令见工具说明。

## 切换与核验

先完成或安全交接仍需旧 Hook 的任务。官方市场操作可能删除旧缓存，因此替换已有安装前需要退出 Desktop，再从外部终端执行准备好的 apply 命令。中断后沿用同一计划和批次继续，重试前先检查已保存的结果。

重新打开客户端，在 CLI 的 `/hooks` 界面，或 Desktop 的 **Review hooks**（审核 Hook）／**Settings > Hooks**（设置中的 Hook 页）审核来自新安装路径的九个 Hook，再用同一计划和批次执行 `--verify`。通过表示官方安装记录、发行文件和新客户端的九个 Hook 一致；它不能证明已有 Desktop 进程内存中使用的版本，请在下一次 Desktop 任务中确认。

升级保留稳定身份和现有数据根。禁用策略、自定义保留期、仅隔离设置和持久关闭记录继续生效。无策略时仍采用结束超过 30 天后才可隔离、至少隔离 7 天后由后续自动维护永久删除的默认规则。检查、关闭和恢复命令见[会话存储](SESSION_STORAGE.md)。

保留上一版核验过的 ZIP、源码和本批结果以便恢复。降级需另行使用官方安装操作，不要向已消费缓存手动复制文件。
