# 升级到 Context Guard 0.18.0

[English](UPGRADE_0_18_0.md) · [发布附件](https://github.com/GreenLv/codex-context-guard/releases/tag/v0.18.0)

对于已安装 0.17.3 稳定入口 `context-guard@codex-context-guard` 的用户，如果工具确认新旧运行时兼容，可以选择在回合间升级。操作工具从 `v0.18.0` 对应的源码仓库取得，不包含在发行 ZIP 或插件缓存中。

## 准备

保留已核验的上一版 ZIP 和市场来源目录。下载 `context-guard-0.18.0.zip`，核对发布页公布的 SHA-256，解压到自己管理并长期保留的目录作为市场来源。操作工具另从 `v0.18.0` 对应的源码仓库取得。按[日常升级说明](https://github.com/GreenLv/codex-context-guard/blob/v0.18.0/tools/validation/DAILY_UPGRADE.md)创建私有计划和结果目录，将它们放在源码仓库及日用配置目录以外。回合间升级计划需要同时指定保留的已核验旧版和新版目录。先运行命令预检与准备。

工具会将已安装旧文件与保留的旧版对照，并检查新版运行时。如果无法确认兼容性、所有权或其他前提，请按拒绝提示处理，不要使用回合间方式。如果插件原本有意保持禁用，请继续保持，直到决定启用。更早版本或其他入口请先阅读 [0.17.3 升级指南](UPGRADE_0_17_3.zh-CN.md)及其链接的更早指南，包括清理设置说明。

## 编写回合间升级计划

在源码仓库和日用 Codex 配置目录以外创建私有计划文件。把下面每个示例路径替换为本机绝对路径：新版和保留的旧版发行包目录、已存在的工作目录、实际 Desktop 宿主可执行文件，以及所选 Codex CLI 可执行文件。macOS 上实际宿主可能位于 ChatGPT.app 内，须指定真正的可执行文件，不能只填应用目录。不要照搬其他机器的路径。新旧目录都须包含完整且已核验的发行文件。

macOS/POSIX 的完整计划示例如下：

```json
{
  "schema": "cg-daily-upgrade-plan/v2",
  "transition_strategy": "between-turns",
  "entry": "context-guard@codex-context-guard",
  "marketplace": "codex-context-guard",
  "target_version": "0.18.0",
  "artifact_dir": "/absolute/path/to/extracted-0.18.0",
  "old_artifact_dir": "/absolute/path/to/verified-0.17.3",
  "cwd": "/absolute/path/to/existing/work-directory",
  "desktop_executable": "/absolute/path/to/actual/Codex-Desktop-executable",
  "cli": "/absolute/path/to/codex",
  "sandbox_markers": [],
  "drain_seconds": 120
}
```

Windows 使用本机绝对路径；JSON 中可以使用正斜杠：

```json
{
  "schema": "cg-daily-upgrade-plan/v2",
  "transition_strategy": "between-turns",
  "entry": "context-guard@codex-context-guard",
  "marketplace": "codex-context-guard",
  "target_version": "0.18.0",
  "artifact_dir": "C:/Path/To/extracted-0.18.0",
  "old_artifact_dir": "C:/Path/To/verified-0.17.3",
  "cwd": "C:/Path/To/existing-work-directory",
  "desktop_executable": "C:/Path/To/actual/Codex-Desktop.exe",
  "cli": "C:/Path/To/codex.exe",
  "sandbox_markers": [],
  "drain_seconds": 120
}
```

没有核实过沙箱辅助程序身份时，`sandbox_markers` 可以留空。`drain_seconds` 是等待旧运行时活动结束的秒数，范围为 1 至 900，默认 120。可选的 `data_dir` 可以用绝对路径指定已有插件数据目录，供工具只读查看清理策略；省略不会更改策略。不要把计划中的设置或路径提交到公开仓库。

选择一个已存在、仅所有者可访问的结果**父目录**，放在源码仓库、日用 Codex 配置目录和新版发行目录以外。下方命令中的 `batch-0180` 是该父目录下**尚不存在的新子目录**，不要自行创建。`--preflight-commands` 检查父目录，不创建批次；`--prepare` 创建批次并保存准备结果。整个过程使用同一份私有计划和同一个批次。将示例路径替换为自己选定的路径，并从 `v0.18.0` 源码仓库运行启动脚本。每一步成功后再执行下一步。

### macOS/POSIX shell

```sh
cd "/absolute/path/to/source-checkout"
plan="/absolute/path/to/private-plan.json"
batch="/absolute/path/to/private-results/batch-0180"
tools/validation/run_daily_upgrade.sh daily --plan "$plan" --output "$batch" --preflight-commands &&
tools/validation/run_daily_upgrade.sh daily --plan "$plan" --output "$batch" --prepare
```

准备成功后，等当前 Codex 回合结束。暂停开始新操作，并在切换完成前保持暂停。然后运行：

```sh
tools/validation/run_daily_upgrade.sh daily --plan "$plan" --output "$batch" --resume
```

### Windows PowerShell 5.1 或 7

```powershell
Set-Location -LiteralPath 'C:\Path\To\SourceCheckout'
$plan = 'C:\Path\To\PrivatePlan.json'
$batch = 'C:\Path\To\PrivateResults\batch-0180'
$entry = '.\tools\validation\run_daily_upgrade.ps1'
& $entry -Target daily -Arguments @('--plan', $plan, '--output', $batch, '--preflight-commands')
if ($LASTEXITCODE -ne 0) { throw '命令预检未成功' }
& $entry -Target daily -Arguments @('--plan', $plan, '--output', $batch, '--prepare')
if ($LASTEXITCODE -ne 0) { throw '准备未成功' }
```

准备成功后，等当前 Codex 回合结束。暂停开始新操作，并在切换完成前保持暂停。然后运行：

```powershell
& $entry -Target daily -Arguments @('--plan', $plan, '--output', $batch, '--resume')
```

`--resume` 会在需要时执行已准备的切换并运行核验。如果提示等待 Hook 审核，请在 CLI 输入 `/hooks`，或打开 Desktop 的 **Review hooks** / **Settings > Hooks** 审核新 Hook，然后用同一份计划和批次再次运行相同的 `--resume` 命令。如果活动仍在执行、状态未知，或出现其他等待或拒绝，请先查看提示和保存的记录再决定如何重试；退出码为 1 或 2 不代表安装步骤一定没有发生。切换尚未完成时不要开始新回合。只有核验报告 `passed` 且命令以 0 退出后，才继续旧任务。v2 回合间方式不使用 `--wait`，该选项属于退出宿主的 v1 方式。

## 在回合间切换

等当前回合结束后，暂停开始新操作。保持 Codex 打开，等待已准备的工具确认旧运行时已结束并完成官方市场和插件操作。切换完成前不要开始新回合。官方添加插件可能删除旧缓存；工具不会向已消费缓存复制文件或修复缓存。批次中断时保留同一份计划和记录，按接续提示处理。

原有的退出后升级方式仍可使用。它的 `--resume --wait` 选项可以限时等待宿主退出，不适用于回合间升级计划。无需切换时，直接继续核验，不要重复安装。

## 审核与核验

如有提示，通过官方界面审核新 Hook，再继续核验；核验通过后恢复原任务。新 CLI 客户端的列表只说明该客户端看到哪些 Hook 定义，不能单独证明旧任务已经继续，也不能证明 Desktop 图形界面已经加载这些 Hook。任务实际执行和图形界面行为需要分别观察。

稳定插件身份和原有数据目录继续使用。已禁用的清理策略、自定义保留期、仅隔离设置和持久关闭记录仍然生效。没有策略时，符合条件的会话在结束 30 天后可进入隔离区，至少隔离 7 天后，后续自动维护才可永久删除。查看、关闭和恢复方法见[会话存储](SESSION_STORAGE.md)。保留已核验旧版与批次记录以备恢复；降级是另一次独立的官方安装操作。
