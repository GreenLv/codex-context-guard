# Windows scheduler definition observations

The Windows scheduler batch now produces `cg-retention-scheduler-native/v2`.
Its definition observations use `cg-windows-task-definition/v1`. Earlier
Windows v1 receipts remain historical evidence and are not promoted by the new
consumer. This tooling change does not alter the installed product's schedule,
enable, disable, or cleanup implementation. The macOS observation path is separate.

The collector preserves omitted XML values as `null`. It reads Settings.Enabled,
Principal.RunLevel and the unique trigger's Enabled at their exact namespaced
locations; a trigger's Enabled cannot substitute for Settings.Enabled. Empty,
duplicate, misplaced or wrong-namespace fields are refused.

For the same validated task label, COM independently supplies the registered
task's Enabled, Definition.Settings.Enabled, Principal.RunLevel, and the unique
trigger's count, type and Enabled. Booleans and integers retain their actual
types. No PowerShell conversion supplies a missing value. Registered-task XML
from COM must match the exported XML under canonical XML comparison, and the
raw export must remain byte-identical across the COM read. Only digests and
selected facts enter the result; COM XML is not retained in the receipt.

The owned task requires three true Enabled observations, integer run level 0,
and one daily trigger. The controlled foreign task requires false Enabled
observations, integer run level 0, and one time trigger. Explicit XML values must
agree with COM. Omitted XML fields require the independent COM observations;
omission alone proves nothing. Security digests and exact second-operation
definition/manifest comparisons remain mandatory. Unknown task or process state
is not absence and does not authorize guessed cleanup.

These observations do not independently prove the precise StartBoundary or
DaysInterval, an elapsed scheduled run, or a successful native batch. Pure
controls and an unregistered in-memory COM definition probe are not registered
task acceptance. A new real batch requires a reviewed, frozen toolkit.

Microsoft's [Task Scheduler schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema),
[Trigger.Enabled](https://learn.microsoft.com/en-us/windows/win32/taskschd/trigger-enabled)
and [Principal.RunLevel](https://learn.microsoft.com/en-us/windows/win32/taskschd/principal-runlevel)
describe the distinct fields. The native observations, rather than assumed
defaults, determine the recorded values.
