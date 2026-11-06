#!/usr/bin/env python3
"""Native scheduled-retention acceptance, using only task-owned fixtures.

The entrypoint is ``native_acceptance.py --scheduler-batch``. It never
installs a plugin, logs in, calls a model or edits a daily data root. The
actual system scheduler runs the installed plugin's existing cleanup CLI.
The independent consumer derives its verdict from the captured facts.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

SCHEMA = "cg-retention-scheduler-native/v1"
LABEL = re.compile(r"cg-ccg0170-[A-Za-z0-9][A-Za-z0-9._-]{0,70}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
JOB_BUDGET_SECONDS = 45.0


class SchedulerBatchError(RuntimeError):
    """The planned scene cannot be proved or safely executed."""


class ProcessStateUnknown(SchedulerBatchError):
    """A command's owned process tree could not be proved stopped."""


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()


def _exclusive_json(path: Path, value: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _command(native: Any, root: Path, argv: list[str], *,
             env: dict[str, str] | None = None, timeout: float = 30.0
             ) -> subprocess.CompletedProcess[bytes]:
    """Capture an owned subprocess, including expected nonzero refusals."""
    tree = native.load_process_tree()
    try:
        owner = tree.OwnedProcess.spawn(argv, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except BaseException as exc:
        cleanup = getattr(exc, "cleanup", None)
        if not isinstance(cleanup, dict) or cleanup.get("cleanup_complete") is not True:
            raise ProcessStateUnknown("owned command startup cleanup unknown") from exc
        raise SchedulerBatchError("owned command could not start") from exc
    failure = None
    natural = False
    try:
        stdout, stderr = owner.process.communicate(timeout=timeout)
        natural = native.load_natural_observer()(owner).get("no_running_members") is True
    except BaseException as exc:
        failure = exc
        stdout, stderr = b"", b""
    finally:
        try:
            cleanup = owner.close(5)
        except BaseException as exc:
            raise ProcessStateUnknown("owned command cleanup failed") from exc
        for stream in (owner.process.stdout, owner.process.stderr):
            if stream is not None:
                stream.close()
    if (cleanup.get("owned_process_exited") is not True
            or cleanup.get("owned_tree_no_running_members") is not True
            or cleanup.get("process_group_cleanup_error") is not None):
        raise ProcessStateUnknown("owned command cleanup unknown") from failure
    if failure is not None or not natural:
        raise SchedulerBatchError("owned command did not finish naturally") from failure
    return subprocess.CompletedProcess(argv, owner.process.returncode, stdout, stderr)


def _parse_json_command(result: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    try:
        value = json.loads(result.stdout.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SchedulerBatchError("command did not return valid JSON") from exc
    if not isinstance(value, dict):
        raise SchedulerBatchError("command JSON is not an object")
    return {"exit_code": result.returncode, "json": value}


def _cli(native: Any, source: Path, installed_script: Path, data: Path,
         label: str, operation: str, env: dict[str, str]) -> dict[str, Any]:
    argv = [sys.executable, "-B", str(installed_script), "cleanup", "--data-dir",
            str(data), "--maintenance-label", label, "--maintenance-" + operation]
    result = _command(native, source, argv, env=env)
    try:
        parsed = _parse_json_command(result)
    except SchedulerBatchError:
        parsed = {"exit_code": result.returncode, "json": None,
                  "protocol_error": "stdout_not_json_object"}
    parsed["stderr"] = result.stderr.decode("utf-8", errors="replace")[-4000:]
    return parsed


def _source_zip(installed: Path, archive: Path, expected: str, manager: Any,
                source: Path) -> dict[str, Any]:
    if not HEX64.fullmatch(expected or ""):
        raise SchedulerBatchError("canonical ZIP SHA-256 is required")
    if archive.is_symlink() or not archive.is_file() or _sha(archive) != expected:
        raise SchedulerBatchError("canonical ZIP is unavailable or has another digest")
    reviewed = manager.distribution_manifest(source)
    manager.compare_artifact(source, installed)
    with zipfile.ZipFile(io.BytesIO(archive.read_bytes())) as packaged:
        names = packaged.namelist()
        if len(names) != len(reviewed) or set(names) != set(reviewed):
            raise SchedulerBatchError("canonical ZIP file set differs from source")
        for name, value in reviewed.items():
            if hashlib.sha256(packaged.read(name)).hexdigest() != value:
                raise SchedulerBatchError("canonical ZIP file bytes differ from source")
    return {"filename": archive.name, "sha256": expected,
            "size_bytes": archive.stat().st_size, "file_count": len(reviewed)}


def _outside(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
    except ValueError:
        return True
    return False


def _safe_new_path(path: Path, roots: list[Path]) -> None:
    if not path.is_absolute() or path.is_symlink() or path.exists():
        raise SchedulerBatchError("output and fixture must be new absolute paths")
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir() or not os.access(parent, os.W_OK):
        raise SchedulerBatchError("output or fixture parent is not writable")
    if any(not _outside(parent / path.name, root) for root in roots):
        raise SchedulerBatchError("output or fixture overlaps a protected root")


def _private_parent(path: Path, driver: Any) -> None:
    if isinstance(driver, _Windows):
        if not driver.private_parent(path):
            raise SchedulerBatchError("Windows output or fixture parent is not private")
    else:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or path.is_symlink()
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise SchedulerBatchError("output or fixture parent is not private")


def _safe_time(now: dt.datetime | None = None) -> bool:
    # The product's automatic 03:17 local trigger must not race the one
    # explicitly initiated by this 45-second scene.
    local = now or dt.datetime.now().astimezone()
    minute = local.hour * 60 + local.minute
    return not (3 * 60 + 13 <= minute <= 3 * 60 + 20)


def _mac_fields(raw: bytes) -> dict[str, Any]:
    # launchctl output is not a stable API. Never retain its environment.
    result: dict[str, Any] = {"runs": None, "state": None,
                              "pid": None, "last_exit_code": None}
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        return result
    for line in text.splitlines():
        match = re.fullmatch(r"\s*(runs|state|pid|last exit code)\s*=\s*(.*?)\s*", line)
        if match:
            key = {"last exit code": "last_exit_code"}.get(match.group(1), match.group(1))
            val = match.group(2)
            result[key] = int(val) if key != "state" and val.isdecimal() else (
                val if key == "state" else None)
    return result


class _Mac:
    def __init__(self, native: Any, source: Path, env: dict[str, str]):
        self.native, self.source, self.env = native, source, env
        self.binary = shutil.which("launchctl")
        if not self.binary or not hasattr(os, "getuid"):
            raise SchedulerBatchError("launchctl capability unavailable")
        self.domain = f"gui/{os.getuid()}"

    def call(self, *argv: str, timeout: float = 30.0) -> subprocess.CompletedProcess[bytes]:
        return _command(self.native, self.source, [self.binary, *argv], env=self.env, timeout=timeout)

    def target(self, label: str) -> str:
        return self.domain + "/" + label

    def definition_path(self, label: str) -> Path:
        return Path.home() / "Library" / "LaunchAgents" / (label + ".plist")

    def absent(self, label: str) -> bool:
        domain = self.call("print", self.domain)
        if domain.returncode != 0:
            raise SchedulerBatchError("launchd GUI domain is not inspectable")
        path = self.definition_path(label)
        queried = self.call("print", self.target(label))
        if queried.returncode == 0 or path.exists() or path.is_symlink():
            return False
        if queried.returncode != 113:
            raise SchedulerBatchError("launchd service absence is not established")
        return True

    def inventory(self, ignore: set[str]) -> dict[str, Any]:
        parent = self.definition_path("x").parent
        rows = []
        for path in sorted(parent.iterdir(), key=lambda p: p.name):
            if path.name in {name + ".plist" for name in ignore}:
                continue
            info = path.lstat()
            rows.append([path.name, info.st_mode, info.st_ino, info.st_size, info.st_mtime_ns])
        return {"count": len(rows), "sha256": _digest(rows),
                "scope": "other LaunchAgents filename and lstat metadata"}

    def definition(self, label: str) -> dict[str, Any]:
        import plistlib
        path = self.definition_path(label)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            raise SchedulerBatchError("service definition is not a regular file")
        body = plistlib.loads(path.read_bytes())
        return {"sha256": _sha(path), "inode": info.st_ino,
                "mode": stat.S_IMODE(info.st_mode), "mtime_ns": info.st_mtime_ns,
                "program_arguments": body.get("ProgramArguments"),
                "run_at_load": body.get("RunAtLoad"),
                "calendar": body.get("StartCalendarInterval")}

    def job(self, label: str, *, timeout: float = 30.0) -> dict[str, Any]:
        result = self.call("print", self.target(label), timeout=timeout)
        if result.returncode != 0:
            raise SchedulerBatchError("launchd service status unavailable")
        return _mac_fields(result.stdout)

    def foreign_create(self, label: str, scratch: Path) -> dict[str, Any]:
        import plistlib
        del scratch
        path = self.definition_path(label)
        data = plistlib.dumps({"Label": label, "ProgramArguments": ["/usr/bin/true"],
                               "RunAtLoad": False})
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        return {"definition": self.definition(label), "kind": "unloaded_foreign_plist"}

    def foreign_remove(self, label: str, before: dict[str, Any]) -> bool:
        path = self.definition_path(label)
        if self.definition(label) != before["definition"]:
            return False
        loaded = self.call("print", self.target(label))
        if loaded.returncode != 113:
            return False
        path.unlink()
        return self.absent(label)

    def trigger(self, label: str, scratch: Path) -> dict[str, Any]:
        stdout, stderr = scratch / "launchd-stdout.txt", scratch / "launchd-stderr.txt"
        for path in (stdout, stderr):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        debug = self.call("debug", self.target(label), "--stdout", str(stdout),
                          "--stderr", str(stderr))
        if debug.returncode != 0:
            return {"exit_code": None, "debug_exit_code": debug.returncode,
                    "trigger_attempted": False,
                    "debug_stderr": debug.stderr.decode("utf-8", errors="replace")[-4000:]}
        result = self.call("kickstart", "-p", self.target(label))
        try:
            pid = int(result.stdout.strip())
        except ValueError:
            pid = None
        return {"exit_code": result.returncode, "pid": pid, "debug_exit_code": 0,
                "trigger_attempted": True,
                "trigger_stderr": result.stderr.decode("utf-8", errors="replace")[-4000:],
                "stdout_path": str(stdout), "stderr_path": str(stderr),
                "observation": "one-run launchctl debug redirects streams only"}

    def stop(self, label: str) -> dict[str, Any]:
        result = self.call("kill", "SIGTERM", self.target(label))
        return {"exit_code": result.returncode, "method": "launchctl kill SIGTERM"}


class _Windows:
    def __init__(self, native: Any, source: Path, env: dict[str, str]):
        self.native, self.source, self.env = native, source, env
        self.binary = shutil.which("schtasks.exe")
        self.powershell = shutil.which("powershell.exe")
        if not self.binary or not self.powershell:
            raise SchedulerBatchError("Windows scheduler capability unavailable")

    def call(self, *argv: str) -> subprocess.CompletedProcess[bytes]:
        return _command(self.native, self.source, [self.binary, *argv], env=self.env)

    def ps(self, source: str, *, timeout: float = 30.0) -> subprocess.CompletedProcess[bytes]:
        command = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);" + source
        return _command(self.native, self.source,
                        [self.powershell, "-NoProfile", "-NonInteractive", "-Command", command],
                        env=self.env, timeout=timeout)

    def exists(self, label: str) -> bool:
        # COM HRESULT distinguishes an absent task from denied/unknown query.
        code = ("$ErrorActionPreference='Stop';try{$s=New-Object -ComObject Schedule.Service;"
                "$s.Connect();$null=$s.GetFolder('\\').GetTask('" + label + "');"
                "Write-Output 'EXISTS'}catch{$e=$_.Exception;"
                "if($e.HResult -eq -2147024894 -or ($e.InnerException -and "
                "$e.InnerException.HResult -eq -2147024894)){Write-Output 'ABSENT'}else{exit 2}}")
        result = self.ps(code)
        value = result.stdout.decode("utf-8-sig", errors="replace").strip()
        if result.returncode != 0 or value not in {"EXISTS", "ABSENT"}:
            raise SchedulerBatchError("Windows task presence could not be established")
        return value == "EXISTS"

    def absent(self, label: str) -> bool:
        return not self.exists(label)

    def private_parent(self, path: Path) -> bool:
        escaped = str(path).replace("'", "''")
        code = ("$ErrorActionPreference='Stop';$a=Get-Acl -LiteralPath '" + escaped + "';"
                "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;"
                "$owner=([Security.Principal.NTAccount]$a.Owner).Translate("
                "[Security.Principal.SecurityIdentifier]).Value;"
                "$allowed=@($a.Access | Where-Object {$_.AccessControlType -eq 'Allow'} | "
                "ForEach-Object {$_.IdentityReference.Translate("
                "[Security.Principal.SecurityIdentifier]).Value});"
                "if($owner -ne $sid -or @($allowed | Where-Object {$_ -ne $sid -and "
                "$_ -ne 'S-1-5-18'}).Count -ne 0 -or $allowed -notcontains $sid -or "
                "$allowed -notcontains 'S-1-5-18'){exit 2};Write-Output 'PRIVATE'")
        result = self.ps(code)
        return result.returncode == 0 and result.stdout.decode("utf-8-sig").strip() == "PRIVATE"

    def _sddl_digest(self, assignment: str) -> str:
        # Only the digest crosses the process boundary. The raw descriptor and
        # SIDs remain inside PowerShell and are never written to the receipt.
        code = ("$ErrorActionPreference='Stop';" + assignment + ";"
                "if([string]::IsNullOrEmpty($sddl)){exit 2};"
                "$h=[Security.Cryptography.SHA256]::Create();try{"
                "$bytes=[Text.Encoding]::UTF8.GetBytes($sddl);"
                "[BitConverter]::ToString($h.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()"
                "}finally{$h.Dispose()}")
        result = self.ps(code)
        digest = result.stdout.decode("utf-8-sig", errors="replace").strip()
        if result.returncode != 0 or not HEX64.fullmatch(digest):
            raise SchedulerBatchError("Windows security descriptor digest unavailable")
        return digest

    def manifest_security(self, path: Path) -> str:
        escaped = str(path).replace("'", "''")
        return self._sddl_digest("$sddl=(Get-Acl -LiteralPath '" + escaped + "').Sddl")

    def task_security(self, label: str) -> str:
        if not (LABEL.fullmatch(label) or (label.endswith("-foreign")
                                          and LABEL.fullmatch(label[:-len("-foreign")]))):
            raise SchedulerBatchError("invalid task label")
        return self._sddl_digest(
            "$s=New-Object -ComObject Schedule.Service;$s.Connect();"
            "$t=$s.GetFolder('\\').GetTask('" + label + "');"
            "$sddl=$t.GetSecurityDescriptor(7)")

    def inventory(self, ignore: set[str]) -> dict[str, Any]:
        code = ("$ErrorActionPreference='Stop';Import-Module ScheduledTasks;"
                "$tasks=@(Get-ScheduledTask -TaskPath '\\' | Select-Object -ExpandProperty TaskName);"
                "ConvertTo-Json -InputObject $tasks -Compress")
        result = self.ps(code)
        if result.returncode != 0:
            raise SchedulerBatchError("Windows root task inventory unavailable")
        try:
            names = json.loads(result.stdout.decode("utf-8-sig"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise SchedulerBatchError("Windows task inventory unreadable") from exc
        if isinstance(names, str):
            names = [names]
        if not isinstance(names, list) or any(not isinstance(x, str) for x in names):
            raise SchedulerBatchError("Windows task inventory shape unavailable")
        names = sorted(x for x in names if x not in ignore)
        return {"count": len(names), "sha256": _digest(names),
                "scope": "visible root task names only; other definitions not read"}

    def definition(self, label: str) -> dict[str, Any]:
        import xml.etree.ElementTree as ET
        result = self.call("/Query", "/TN", label, "/XML")
        if result.returncode != 0 or not result.stdout:
            raise SchedulerBatchError("Windows task definition unavailable")
        text = None
        for encoding in ("utf-16", "utf-8-sig", "utf-8"):
            try:
                candidate = result.stdout.decode(encoding)
                if "<" in candidate:
                    text = candidate
                    break
            except UnicodeError:
                pass
        if text is None:
            raise SchedulerBatchError("Windows task XML encoding unavailable")
        try:
            root = ET.fromstring(text.lstrip("\ufeff").strip())
        except ET.ParseError as exc:
            raise SchedulerBatchError("Windows task XML is malformed") from exc

        def field(name: str) -> str | None:
            for node in root.iter():
                if node.tag.rsplit("}", 1)[-1] == name:
                    return (node.text or "").strip()
            return None
        return {"sha256": hashlib.sha256(result.stdout).hexdigest(),
                "command": field("Command"), "arguments": field("Arguments"),
                "description": field("Description"), "enabled": field("Enabled"),
                "logon_type": field("LogonType"), "run_level": field("RunLevel"),
                "security_sha256": self.task_security(label)}

    def job(self, label: str, *, timeout: float = 30.0) -> dict[str, Any]:
        code = ("$ErrorActionPreference='Stop';Import-Module ScheduledTasks;"
                "$t=Get-ScheduledTask -TaskName '" + label + "' -TaskPath '\\';"
                "$i=Get-ScheduledTaskInfo -TaskName '" + label + "' -TaskPath '\\';"
                "@{state=$t.State.ToString();last_run_ticks=$i.LastRunTime.ToUniversalTime().Ticks;"
                "last_result=[int64]$i.LastTaskResult}|ConvertTo-Json -Compress")
        result = self.ps(code, timeout=timeout)
        if result.returncode != 0:
            raise SchedulerBatchError("Windows task run facts unavailable")
        return _parse_json_command(result)["json"]

    def foreign_create(self, label: str, scratch: Path) -> dict[str, Any]:
        shell = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe")
        body = _windows_foreign_xml(label, shell)
        xml = scratch / "foreign-fixture.xml"
        with xml.open("x", encoding="utf-16") as stream:
            stream.write(body)
        result = self.call("/Create", "/TN", label, "/XML", str(xml))
        if result.returncode != 0:
            raise SchedulerBatchError("controlled disabled foreign task could not be created")
        return {"definition": self.definition(label), "kind": "disabled_foreign_task",
                "creation_exit": result.returncode}

    def foreign_remove(self, label: str, before: dict[str, Any]) -> bool:
        if self.definition(label) != before["definition"]:
            return False
        result = self.call("/Delete", "/TN", label, "/F")
        return result.returncode == 0 and self.absent(label)

    def trigger(self, label: str, scratch: Path) -> dict[str, Any]:
        del scratch
        result = self.call("/Run", "/TN", label)
        return {"exit_code": result.returncode, "pid": None,
                "trigger_attempted": True,
                "trigger_stderr": result.stderr.decode("utf-8", errors="replace")[-4000:],
                "observation": "product task definition not modified; stdout unavailable"}

    def stop(self, label: str) -> dict[str, Any]:
        result = self.call("/End", "/TN", label)
        return {"exit_code": result.returncode, "method": "schtasks /End"}


def _windows_foreign_xml(label: str, shell: str) -> str:
    from xml.sax.saxutils import escape
    marker = "ccg0170-owned-foreign-fixture-" + label
    # Principal and action context match the product's scheduled-task XML;
    # Windows acceptance of the unspecified UserId remains a native gate.
    return ("<?xml version='1.0' encoding='UTF-16'?>"
            "<Task version='1.2' xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>"
            f"<RegistrationInfo><Description>{escape(marker)}</Description></RegistrationInfo>"
            "<Triggers><TimeTrigger><StartBoundary>2099-01-01T03:17:00</StartBoundary>"
            "<Enabled>false</Enabled></TimeTrigger></Triggers>"
            "<Principals><Principal id='Author'><LogonType>InteractiveToken</LogonType>"
            "<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>"
            "<Settings><Enabled>false</Enabled></Settings>"
            "<Actions Context='Author'><Exec><Command>" + escape(shell) + "</Command>"
            "<Arguments>/d /c exit 0</Arguments></Exec></Actions></Task>")


def _driver(native: Any, source: Path, env: dict[str, str], system: str | None = None):
    system = system or platform.system()
    if system == "Darwin":
        return _Mac(native, source, env)
    if system == "Windows":
        return _Windows(native, source, env)
    raise SchedulerBatchError("native scheduler platform is unsupported")


def subject_identity(native: Any, source: Path, commit: str, tool_commit: str,
                     installed: Path, archive: Path, archive_sha256: str) -> dict[str, Any]:
    """Recompute both trusted source identities and the full artifact parity."""
    if not native.HEX40.fullmatch(commit or ""):
        raise SchedulerBatchError("product commit must be a full SHA-1")
    native.verify_exact_source(source, commit)
    source = source.resolve(strict=True)
    if installed.is_symlink():
        raise SchedulerBatchError("installed plugin root may not be a link")
    installed = installed.resolve(strict=True)
    tool_root = Path(__file__).resolve().parents[2]
    if not native.HEX40.fullmatch(tool_commit or ""):
        raise SchedulerBatchError("toolkit commit must be a full SHA-1")
    native.verify_exact_source(tool_root, tool_commit)
    manager = native.load_artifacts(source)
    artifact = _source_zip(installed, archive, archive_sha256, manager, source)
    digest = native.runtime_digest(manager, source)
    return {"source_commit": commit, "runtime_tree_sha256": digest,
            "toolkit_commit": tool_commit,
            "toolkit_root": str(tool_root), "product_root": str(source),
            "installed_plugin_root": str(installed),
            "installed_script_sha256": _sha(installed / "scripts/context_guard.py"),
            "tool_sha256": _sha(Path(__file__)),
            "entrypoint_sha256": _sha(tool_root / "tools/validation/native_acceptance.py"),
            "host_behavior_sha256": _sha(tool_root / "tools/validation/host_behavior.py"),
            "process_tree_sha256": _sha(tool_root / "scripts/cg_process_tree.py"),
            "natural_observer_sha256": _sha(tool_root / "tools/validation/perf_ab.py"),
            "fixture_helper_sha256": _sha(source / "tests/test_cg0170_retention_restored.py"),
            "artifact_identity_sha256": _sha(source / "scripts/artifact_identity.py"),
            "python": str(Path(sys.executable).absolute()),
            "python_version": platform.python_version(),
            "python_sha256": _sha(Path(sys.executable)), "artifact": artifact}


def preflight(native: Any, source: Path, commit: str, tool_commit: str, installed: Path,
              archive: Path, archive_sha256: str, output: Path,
              fixture: Path, label: str) -> dict[str, Any]:
    """Read-only input and capability checks; never register or start a job."""
    if not LABEL.fullmatch(label or ""):
        raise SchedulerBatchError("a unique ccg-ccg0170 label is required")
    if installed.is_symlink():
        raise SchedulerBatchError("installed plugin root may not be a link")
    source, installed = source.resolve(strict=True), installed.resolve(strict=True)
    tool_root = Path(__file__).resolve().parents[2]
    roots = [source, installed, tool_root]
    codex_home = os.environ.get("CODEX_HOME")
    fixture_roots = list(roots)
    fixture_roots.append((Path.home() / ".codex").resolve())
    if codex_home:
        fixture_roots.append(Path(codex_home).resolve())
    _safe_new_path(output, fixture_roots)
    _safe_new_path(fixture, fixture_roots + [output.parent.resolve()])
    progress = output.with_name(output.name + ".progress")
    _safe_new_path(progress, fixture_roots)
    if not _safe_time():
        raise SchedulerBatchError("automatic 03:17 trigger is too close")
    env = _fixture_env(fixture)
    driver = _driver(native, source, env)
    _private_parent(output.parent.resolve(strict=True), driver)
    _private_parent(fixture.parent.resolve(strict=True), driver)
    if isinstance(driver, _Mac):
        parent = driver.definition_path(label).parent
        if parent.is_symlink() or not parent.is_dir() or not os.access(parent, os.W_OK):
            raise SchedulerBatchError("LaunchAgents directory is not a writable real directory")
    if not driver.absent(label) or not driver.absent(label + "-foreign"):
        raise SchedulerBatchError("requested or foreign-control label already exists")
    # The existing retention preflight probes writability and can create its
    # parent. Run it only after the non-creating protected-root checks above.
    native.check_retention_batch_inputs(source, commit, output)
    return subject_identity(native, source, commit, tool_commit, installed,
                            archive, archive_sha256)


def _fixture_env(fixture: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["CONTEXT_GUARD_DATA_DIR"] = str(fixture / "guard-data")
    env["CODEX_HOME"] = str(fixture / "empty-codex-home")
    for key in list(env):
        if (key in {"PLUGIN_DATA", "CLAUDE_PLUGIN_DATA", "PLUGIN_ROOT"}
                or re.search(r"TOKEN|PASSWORD|SECRET|API_KEY|CREDENTIAL", key, re.I)):
            env.pop(key, None)
    return env


@contextlib.contextmanager
def _environment(values: dict[str, str]):
    old = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update(values)
        yield
    finally:
        os.environ.clear()
        os.environ.update(old)


@contextlib.contextmanager
def _installed_imports(installed: Path):
    old_path = list(sys.path)
    previous_dont_write = sys.dont_write_bytecode
    try:
        sys.path.insert(0, str(installed / "scripts"))
        sys.dont_write_bytecode = True
        yield
    finally:
        sys.path[:] = old_path
        sys.dont_write_bytecode = previous_dont_write


def _load_fixture(source: Path, installed: Path, fixture: Path):
    # Fixture generation uses the maintained test helper against source bytes;
    # full source/installed parity was checked before entering this function.
    prior_path = list(sys.path)
    tests = str(source / "tests")
    scripts = str(installed / "scripts")
    sys.path.insert(0, tests)
    sys.path.insert(0, scripts)
    previous_dont_write = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        import test_cg0170_retention_restored as fixture_module
        path = installed / "scripts/context_guard.py"
        # The source fixture helper may alter sys.path during import.
        sys.path.insert(0, scripts)
        spec = importlib.util.spec_from_file_location("scheduler_installed_product", path)
        if spec is None or spec.loader is None:
            raise SchedulerBatchError("installed runtime cannot be loaded")
        installed_cg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installed_cg)
        obj = fixture_module.RetentionFixtureBase()
        obj.root = fixture
        obj.data_dir = fixture / "guard-data"
        obj.project = fixture / "project"
        obj.project.mkdir()
        # The versioned test helper itself imports cg from its source checkout
        # using __file__. Inject the separately loaded, parity-verified installed
        # runtime while it constructs data, then restore its prior global.
        previous_cg = fixture_module.cg
        fixture_module.cg = installed_cg
        try:
            eligible = obj.make_session("scheduler-eligible", ended_days_ago=45)
            protected = obj.make_session("scheduler-pending", ended_days_ago=45, finished=False)
            obj.enable_policy()
        finally:
            fixture_module.cg = previous_cg
        return obj, installed_cg, eligible, protected
    finally:
        sys.path[:] = prior_path
        sys.dont_write_bytecode = previous_dont_write


def _file_snapshot(path: Path) -> dict[str, Any]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise SchedulerBatchError("expected owned regular file unavailable")
    return {"sha256": _sha(path), "inode": info.st_ino,
            "mode": stat.S_IMODE(info.st_mode), "mtime_ns": info.st_mtime_ns}


def _progress(output: Path, phase: str, facts: dict[str, Any]) -> None:
    directory = output.with_name(output.name + ".progress")
    _exclusive_json(directory / (phase + ".json"), facts)


def _json_exit(report: dict[str, Any], key: str) -> tuple[Any, Any, Any]:
    item = _dict(report.get(key))
    payload = _dict(item.get("json"))
    code = item.get("exit_code")
    return code if type(code) is int else None, payload.get("status"), payload.get("state")


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _valid_sha(value: Any) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _file_facts_valid(value: Any) -> bool:
    row = _dict(value)
    return (_valid_sha(row.get("sha256"))
            and type(row.get("inode")) is int and row["inode"] >= 0
            and type(row.get("mode")) is int and 0 <= row["mode"] <= 0o7777
            and type(row.get("mtime_ns")) is int and row["mtime_ns"] >= 0)


def _snapshot_valid(value: Any, system: str) -> bool:
    row = _dict(value)
    definition = _dict(row.get("definition"))
    manifest = _dict(row.get("ownership_manifest"))
    definition_valid = (_file_facts_valid(definition) if system == "Darwin"
                        else (_valid_sha(definition.get("sha256"))
                              and _valid_sha(definition.get("security_sha256"))))
    return (definition_valid and _file_facts_valid(manifest)
            and (system != "Windows" or _valid_sha(manifest.get("security_sha256"))))


def _foreign_valid(value: Any, system: str, label: Any) -> bool:
    row = _dict(value)
    if system == "Darwin":
        return (_file_facts_valid(row) and row.get("program_arguments") == ["/usr/bin/true"]
                and row.get("run_at_load") is False and row.get("calendar") is None)
    return (system == "Windows" and _valid_sha(row.get("sha256"))
            and _valid_sha(row.get("security_sha256"))
            and isinstance(label, str)
            and row.get("description") == "ccg0170-owned-foreign-fixture-" + label
            and str(row.get("enabled") or "").lower() == "false"
            and row.get("logon_type") == "InteractiveToken"
            and row.get("run_level") == "LeastPrivilege")


def _inventory_valid(value: Any) -> bool:
    row = _dict(value)
    return (type(row.get("count")) is int and row["count"] >= 0
            and _valid_sha(row.get("sha256")) and isinstance(row.get("scope"), str)
            and bool(row["scope"]))


def _definition_matches(actual: dict[str, Any], expected: dict[str, Any], system: str) -> bool:
    if system == "Darwin":
        return (actual.get("program_arguments") == expected.get("program_arguments")
                and actual.get("run_at_load") is False
                and actual.get("calendar") == {"Hour": 3, "Minute": 17})
    if system == "Windows":
        return (actual.get("command") == expected.get("command")
                and actual.get("arguments") == expected.get("arguments")
                and actual.get("description") == expected.get("description")
                and str(actual.get("enabled") or "").lower() == "true"
                and actual.get("logon_type") == "InteractiveToken"
                and actual.get("run_level") == "LeastPrivilege")
    return False


def consume(report: Any, *, expected_subject: dict[str, Any], fixture: Path,
            system: str) -> list[str]:
    """Independent verdict from facts; a claimed passed flag is insufficient."""
    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        return ["schema"]
    errors = []
    subject = _dict(report.get("subject"))
    if (not isinstance(subject, dict)
            or any(subject.get(key) != value for key, value in expected_subject.items())):
        errors.append("subject")
    expected_platform = {"Darwin": "macos", "Windows": "windows"}.get(system)
    if report.get("platform") != expected_platform or report.get("fixture_root") != str(fixture):
        errors.append("platform_or_fixture")
    if report.get("status") not in ("running", "passed"):
        errors.append("producer_reported_failure")
    foreign = _dict(report.get("foreign"))
    for op in ("enable", "disable"):
        item = _dict(foreign.get(op))
        payload = _dict(item.get("json"))
        if (type(item.get("exit_code")) is not int or item.get("exit_code") != 2
                or payload.get("reason") != "foreign_entry"
                or payload.get("owned") is not False):
            errors.append("foreign_" + op)
    if (not _foreign_valid(foreign.get("before"), system, report.get("foreign_label"))
            or not _foreign_valid(foreign.get("after"), system, report.get("foreign_label"))
            or foreign.get("before") != foreign.get("after")
            or foreign.get("removed") is not True):
        errors.append("foreign_preservation")
    scene = _dict(report.get("scene"))
    expected = _expected_definition(expected_subject, fixture / "guard-data", system)
    actual = _dict(_dict(scene.get("before_second")).get("definition"))
    if subject.get("expected_definition") != expected:
        errors.append("expected_definition")
    if not _definition_matches(actual, expected, system):
        errors.append("registered_definition")
    if _json_exit(scene, "initial_status") != (0, "read_back", "disabled"):
        errors.append("initial_status")
    if (_json_exit(scene, "enable") != (0, "enabled", "enabled")
            or _dict(_dict(scene.get("enable")).get("json")).get("owned") is not True
            or _dict(_dict(scene.get("enable")).get("json")).get("current") is not True):
        errors.append("enable")
    if _json_exit(scene, "status") != (0, "read_back", "enabled"):
        errors.append("status")
    second = _dict(scene.get("second_enable"))
    if (type(second.get("exit_code")) is not int or second.get("exit_code") != 0
            or _dict(second.get("json")).get("status") != "already_enabled"
            or _dict(second.get("json")).get("no_op") is not True
            or scene.get("before_second") != scene.get("after_second")
            or not _snapshot_valid(scene.get("before_second"), system)
            or not _snapshot_valid(scene.get("after_second"), system)):
        errors.append("strict_noop")
    before, after = _dict(scene.get("job_before")), _dict(scene.get("job_after"))
    if report.get("platform") == "macos":
        if (type(before.get("runs")) is not int or before.get("runs") != 0
                or type(after.get("runs")) is not int
                or after["runs"] != before["runs"] + 1
                or type(after.get("last_exit_code")) is not int or after.get("last_exit_code") != 0
                or after.get("state") not in ("waiting", "exited", "not running")
                or type(_dict(scene.get("trigger")).get("pid")) is not int
                or _dict(scene.get("trigger")).get("pid", 0) <= 0):
            errors.append("native_execution")
        result = _dict(scene.get("job_report"))
        counts = _dict(result.get("counts"))
        entries = result.get("entries") if isinstance(result.get("entries"), list) else []
        protected_count = counts.get("protected")
        if (result.get("mode") != "apply" or type(counts.get("quarantined")) is not int
                or counts.get("quarantined") != 1
                or type(protected_count) is not int or protected_count < 1
                or not any(entry.get("name") == "scheduler-pending"
                           and entry.get("reason") == "unfinished_work"
                           for entry in entries if isinstance(entry, dict))
                or result.get("refused") or result.get("capacity_exceeded")):
            errors.append("job_report")
    elif report.get("platform") == "windows":
        try:
            started = dt.datetime.fromisoformat(report["started_at"]).astimezone(dt.timezone.utc)
            delta = started - dt.datetime(1, 1, 1, tzinfo=dt.timezone.utc)
            started_ticks = ((delta.days * 86400 + delta.seconds) * 10_000_000
                             + delta.microseconds * 10)
        except (KeyError, ValueError, TypeError):
            started_ticks = 0
        if (type(before.get("last_run_ticks")) is not int
                or type(after.get("last_run_ticks")) is not int
                or before.get("last_run_ticks", 0) >= started_ticks
                or after["last_run_ticks"] <= before["last_run_ticks"]
                or after["last_run_ticks"] < started_ticks - 10_000_000
                or type(after.get("last_result")) is not int or after.get("last_result") != 0
                or after.get("state") != "Ready"):
            errors.append("native_execution")
    else:
        errors.append("platform")
    if (type(_dict(scene.get("trigger")).get("exit_code")) is not int
            or _dict(scene.get("trigger")).get("exit_code") != 0):
        errors.append("trigger")
    observation_seconds = scene.get("observation_seconds")
    if (type(observation_seconds) not in (int, float)
            or not 0 <= observation_seconds <= JOB_BUDGET_SECONDS):
        errors.append("observation_budget")
    pre, post, reader = (_dict(scene.get("fixture_before")), _dict(scene.get("fixture_after_job")),
                         _dict(scene.get("reader")))
    if any(not _valid_sha(pre.get(key))
           for key in ("eligible_state_sha256", "protected_state_sha256")):
        errors.append("fixture_digest")
    if (pre.get("policy_enabled") is not True or pre.get("eligible_exists") is not True
            or type(pre.get("protected_unfinished")) is not int
            or pre.get("protected_unfinished", 0) < 1
            or post.get("eligible_exists") is not False
            or type(post.get("record_count")) is not int or post.get("record_count") != 1
            or post.get("record_state") != "quarantined"
            or post.get("record_original") != "scheduler-eligible"
            or post.get("quarantine_state_sha256") != pre.get("eligible_state_sha256")
            or post.get("protected_state_sha256") != pre.get("protected_state_sha256")):
        errors.append("fixture")
    if (reader.get("eligible_state_sha256") != pre.get("eligible_state_sha256")
            or reader.get("protected_state_sha256") != pre.get("protected_state_sha256")
            or reader.get("protected_unfinished") != pre.get("protected_unfinished")
            or reader.get("quarantine_record_exists") is not False):
        errors.append("official_reader")
    if _json_exit(scene, "disable") != (0, "disabled", "disabled"):
        errors.append("disable")
    if (_json_exit(scene, "second_disable") != (0, "already_disabled", "disabled")
            or _dict(_dict(scene.get("second_disable")).get("json")).get("no_op") is not True):
        errors.append("second_disable")
    if _json_exit(scene, "final_status") != (0, "read_back", "disabled"):
        errors.append("final_status")
    cleanup = _dict(report.get("cleanup"))
    if (cleanup.get("job_absent") is not True or cleanup.get("foreign_absent") is not True
            or cleanup.get("command_process_unknown") is not False
            or cleanup.get("job_process_unknown") is not False
            or "stop" in cleanup
            or not _same_completed_job(after, _dict(cleanup.get("job_before_disable")), system)
            or cleanup.get("unrelated_before") != cleanup.get("unrelated_after")
            or not _inventory_valid(cleanup.get("unrelated_before"))
            or not _inventory_valid(cleanup.get("unrelated_after"))):
        errors.append("cleanup")
    return errors


def _unfinished(state: dict[str, Any]) -> int:
    return sum(1 for item in state.get("requirements", [])
               if isinstance(item, dict) and item.get("status") != "pass")


def _expected_definition(subject: dict[str, Any], data: Path, system: str) -> dict[str, Any]:
    root = Path(subject["installed_plugin_root"])
    argv = [subject["python"], "-B", str(root / "scripts/context_guard.py"),
            "cleanup", "--data-dir", str(data), "--apply", "--json"]
    if system == "Darwin":
        return {"program_arguments": argv}
    return {"command": argv[0], "arguments": subprocess.list2cmdline(argv[1:]),
            "description": "Context Guard retention maintenance; data root "
                           + hashlib.sha256(str(data).encode()).hexdigest()[:16]}


def _scene_snapshot(driver: Any, cg: Any, data: Path, label: str) -> dict[str, Any]:
    path = cg._retention_schedule_manifest_path(data)
    manifest = _file_snapshot(path)
    if isinstance(driver, _Windows):
        manifest["security_sha256"] = driver.manifest_security(path)
    return {"definition": driver.definition(label), "ownership_manifest": manifest}


def _completed_job(before: dict[str, Any], after: dict[str, Any], system: str) -> bool:
    if system == "Darwin":
        return (type(before.get("runs")) is int and type(after.get("runs")) is int
                and after["runs"] > before["runs"] and after.get("last_exit_code") is not None
                and after.get("state") in ("waiting", "exited", "not running"))
    return (type(before.get("last_run_ticks")) is int
            and type(after.get("last_run_ticks")) is int
            and after["last_run_ticks"] > before["last_run_ticks"]
            and after.get("last_result") is not None and after.get("state") == "Ready")


def _job_nonrunning(job: dict[str, Any], system: str) -> bool:
    if system == "Darwin":
        runs = job.get("runs")
        return (type(runs) is int and runs >= 0
                and job.get("state") in ("waiting", "exited", "not running")
                and job.get("pid") is None
                and (runs == 0 or type(job.get("last_exit_code")) is int))
    return (system == "Windows" and job.get("state") == "Ready"
            and type(job.get("last_run_ticks")) is int
            and type(job.get("last_result")) is int)


def _same_completed_job(observed: dict[str, Any], before_disable: dict[str, Any],
                        system: str) -> bool:
    if not _job_nonrunning(observed, system) or not _job_nonrunning(before_disable, system):
        return False
    fields = ("runs", "last_exit_code") if system == "Darwin" else ("last_run_ticks", "last_result")
    return all(observed.get(field) == before_disable.get(field) for field in fields)


def _require_command(observation: dict[str, Any], code: int, status: str,
                     state: str | None = None) -> None:
    payload = observation.get("json")
    if (observation.get("exit_code") != code or not isinstance(payload, dict)
            or payload.get("status") != status
            or (state is not None and payload.get("state") != state)):
        raise SchedulerBatchError("product scheduler command returned unexpected facts")


def execute(native: Any, source: Path, commit: str, tool_commit: str,
            installed: Path, archive: Path, archive_sha256: str,
            output: Path, fixture: Path, label: str) -> dict[str, Any]:
    """Run one native job after preflight; never overwrite prior evidence."""
    fixture = fixture.parent.resolve(strict=True) / fixture.name
    output = output.parent.resolve(strict=True) / output.name
    subject = preflight(native, source, commit, tool_commit, installed, archive,
                        archive_sha256, output, fixture, label)
    source, installed = source.resolve(strict=True), installed.resolve(strict=True)
    system = platform.system()
    env = _fixture_env(fixture)
    driver = _driver(native, source, env, system)
    result: dict[str, Any] = {
        "schema": SCHEMA, "status": "running", "subject": dict(subject),
        "platform": {"Darwin": "macos", "Windows": "windows"}[system],
        "label": label, "foreign_label": label + "-foreign",
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "fixture_root": str(fixture), "foreign": {}, "scene": {}, "cleanup": {},
        "limitations": ["synthetic data and a single task-owned scheduler job",
                        "fixture and observation files retained for review",
                        "no model, login, trust, daily HOME, installation or publication",
                        "unrelated inventory checks metadata/names only, not job content"],
    }
    if system == "Darwin":
        result["limitations"].append("launchctl debug redirects stdout/stderr for this invocation")
    else:
        result["limitations"].append("Windows task stdout/stderr are unavailable; definition was not changed")
    progress = output.with_name(output.name + ".progress")
    progress.mkdir(mode=0o700)
    _progress(output, "00-preflight", {"subject": subject, "label": label,
                                        "fixture_root": str(fixture)})
    foreign_owner: dict[str, Any] | None = None
    own_started = False
    data = fixture / "guard-data"
    script = installed / "scripts/context_guard.py"
    foreign_label = label + "-foreign"
    original_error: str | None = None
    process_unknown = False
    try:
        fixture.mkdir(mode=0o700)
        with _environment(env), _installed_imports(installed):
            fixture_obj, cg, eligible, protected = _load_fixture(source, installed, fixture)
            result["subject"]["expected_definition"] = _expected_definition(subject, data, system)
            protected_payload = fixture_obj.payload("SessionStart", "scheduler-pending")
            eligible_payload = fixture_obj.payload("SessionStart", "scheduler-eligible")
            protected_state = cg.load_state(protected, protected_payload)
            result["scene"]["fixture_before"] = {
                "policy_enabled": cg.read_retention_policy(data)["enabled"],
                "eligible_exists": eligible.is_dir(),
                "eligible_state_sha256": _sha(eligible / "state.json"),
                "protected_state_sha256": _sha(protected / "state.json"),
                "protected_unfinished": _unfinished(protected_state),
            }
            before = result["scene"]["fixture_before"]
            if (not before["policy_enabled"] or not before["eligible_exists"]
                    or before["protected_unfinished"] < 1):
                raise SchedulerBatchError("synthetic fixture is not eligible and protected")
            result["cleanup"]["unrelated_before"] = driver.inventory({label, foreign_label})
            _progress(output, "01-fixture", {"before": before,
                                             "inventory": result["cleanup"]["unrelated_before"]})

            foreign_owner = driver.foreign_create(foreign_label, fixture)
            result["foreign"]["before"] = foreign_owner["definition"]
            for op in ("enable", "disable"):
                observed = _cli(native, source, script, data, foreign_label, op, env)
                result["foreign"][op] = observed
                if (observed.get("exit_code") != 2
                        or not isinstance(observed.get("json"), dict)
                        or observed["json"].get("reason") != "foreign_entry"
                        or observed["json"].get("owned") is not False):
                    raise SchedulerBatchError("foreign task refusal was not established")
            result["foreign"]["after"] = driver.definition(foreign_label)
            if result["foreign"]["before"] != result["foreign"]["after"]:
                raise SchedulerBatchError("controlled foreign definition changed")
            _progress(output, "02-foreign", result["foreign"])

            initial = _cli(native, source, script, data, label, "status", env)
            result["scene"]["initial_status"] = initial
            _require_command(initial, 0, "read_back", "disabled")
            if not _safe_time():
                raise SchedulerBatchError("automatic 03:17 trigger became too close")
            own_started = True  # set before invocation: an uncertain reply may follow a mutation
            enabled = _cli(native, source, script, data, label, "enable", env)
            result["scene"]["enable"] = enabled
            _progress(output, "03-enable", {"initial": initial, "enable": enabled})
            _require_command(enabled, 0, "enabled", "enabled")
            if enabled["json"].get("owned") is not True or enabled["json"].get("current") is not True:
                raise SchedulerBatchError("registered task ownership is not established")
            result["scene"]["before_second"] = _scene_snapshot(driver, cg, data, label)
            if not _definition_matches(result["scene"]["before_second"]["definition"],
                                       _expected_definition(subject, data, system), system):
                raise SchedulerBatchError("registered task does not match installed executor")
            second = _cli(native, source, script, data, label, "enable", env)
            result["scene"]["second_enable"] = second
            result["scene"]["after_second"] = _scene_snapshot(driver, cg, data, label)
            _require_command(second, 0, "already_enabled", "enabled")
            if (second["json"].get("no_op") is not True
                    or result["scene"]["before_second"] != result["scene"]["after_second"]):
                raise SchedulerBatchError("second enable changed the owned definition or manifest")
            current = _cli(native, source, script, data, label, "status", env)
            result["scene"]["status"] = current
            _require_command(current, 0, "read_back", "enabled")
            job_before = driver.job(label)
            result["scene"]["job_before"] = job_before
            if not _job_nonrunning(job_before, system):
                raise SchedulerBatchError("initial job run state is unavailable or already running")
            _progress(output, "04-before-trigger", {"scene": result["scene"]})
            trigger = driver.trigger(label, fixture)
            result["scene"]["trigger"] = trigger
            _progress(output, "05-trigger", {"trigger": trigger})
            if trigger.get("exit_code") != 0:
                raise SchedulerBatchError("native trigger was refused")
            observation_start = time.monotonic()
            deadline = observation_start + JOB_BUDGET_SECONDS
            job_after: dict[str, Any] = {}
            observed_in_budget = False
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                job_after = driver.job(label, timeout=min(5.0, remaining))
                if time.monotonic() > deadline:
                    break
                if _completed_job(job_before, job_after, system):
                    observed_in_budget = True
                    break
                time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
            result["scene"]["job_after"] = job_after
            result["scene"]["observation_seconds"] = time.monotonic() - observation_start
            if not observed_in_budget:
                raise SchedulerBatchError("job completion not observed within 45 seconds")
            if system == "Darwin":
                try:
                    job_report = json.loads(Path(trigger["stdout_path"]).read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                    raise SchedulerBatchError("launchd job output is not valid JSON") from exc
                if not isinstance(job_report, dict):
                    raise SchedulerBatchError("launchd job output is not an object")
                result["scene"]["job_report"] = job_report
                result["scene"]["job_stderr_sha256"] = _sha(Path(trigger["stderr_path"]))
            qdir = cg._retention_quarantine_dir(data)
            records = list(cg._retention_iter_records(qdir))
            row: dict[str, Any] = {
                "eligible_exists": eligible.exists(), "record_count": len(records),
                "protected_state_sha256": _sha(protected / "state.json"),
            }
            if len(records) == 1:
                record_path, record = records[0]
                target = qdir / record["quarantine_object"]
                row.update(record_state=record.get("state"), record_original=record.get("original_name"),
                           quarantine_state_sha256=_sha(target / "state.json"))
            result["scene"]["fixture_after_job"] = row
            _progress(output, "06-after-job", {"job": job_after, "fixture": row,
                                                "job_report": result["scene"].get("job_report")})
            if len(records) != 1 or eligible.exists():
                raise SchedulerBatchError("real scheduler did not quarantine the intended object")
            # Use the actual installed module's official reader. It restores
            # the complete eligible record, then reads the untouched unfinished one.
            eligible_state = cg.load_state(eligible, eligible_payload)
            protected_after = cg.load_state(protected, protected_payload)
            if not isinstance(eligible_state, dict) or not isinstance(protected_after, dict):
                raise SchedulerBatchError("official reader did not reopen synthetic states")
            result["scene"]["reader"] = {
                "eligible_state_sha256": _sha(eligible / "state.json"),
                "protected_state_sha256": _sha(protected / "state.json"),
                "protected_unfinished": _unfinished(protected_after),
                "quarantine_record_exists": record_path.exists(),
            }
            _progress(output, "07-reader", result["scene"]["reader"])
    except BaseException as exc:  # preserve failure and cleanup on every path
        original_error = type(exc).__name__ + ": " + str(exc)[:500]
        process_unknown = isinstance(exc, ProcessStateUnknown)
        result["error"] = original_error
    finally:
        result["cleanup"]["command_process_unknown"] = process_unknown
        result["cleanup"]["job_process_unknown"] = own_started
        if own_started and not process_unknown:
            try:
                status = _cli(native, source, script, data, label, "status", env)
                result["cleanup"]["ownership_readback"] = status
                payload = _dict(status.get("json"))
                definition = driver.definition(label) if payload.get("owned") is True else {}
                if (payload.get("owned") is True
                        and _definition_matches(definition,
                                                _expected_definition(subject, data, system), system)):
                    observed = driver.job(label)
                    result["cleanup"]["job_before_cleanup"] = observed
                    running = observed.get("state") == ("running" if system == "Darwin" else "Running")
                    if running:
                        result["cleanup"]["stop"] = driver.stop(label)
                        stop_deadline = time.monotonic() + 10.0
                        while time.monotonic() < stop_deadline:
                            remaining = stop_deadline - time.monotonic()
                            observed = driver.job(label, timeout=min(5.0, remaining))
                            if _job_nonrunning(observed, system):
                                break
                            time.sleep(min(0.5, max(0.0, stop_deadline - time.monotonic())))
                    result["cleanup"]["job_before_disable"] = observed
                    if not _job_nonrunning(observed, system):
                        raise SchedulerBatchError("owned job exit could not be established; retained")
                    result["cleanup"]["job_process_unknown"] = False
                    first = _cli(native, source, script, data, label, "disable", env)
                    result["scene"]["disable"] = first
                    if first.get("exit_code") == 0:
                        result["scene"]["second_disable"] = _cli(
                            native, source, script, data, label, "disable", env)
                        result["scene"]["final_status"] = _cli(
                            native, source, script, data, label, "status", env)
            except BaseException as exc:
                result["cleanup"]["owned_cleanup_error"] = type(exc).__name__
                if isinstance(exc, ProcessStateUnknown):
                    process_unknown = True
                    result["cleanup"]["command_process_unknown"] = True
        try:
            result["cleanup"]["job_absent"] = driver.absent(label)
        except BaseException as exc:
            result["cleanup"]["job_absent"] = None
            result["cleanup"]["job_absence_error"] = type(exc).__name__
        if foreign_owner is not None and not process_unknown:
            try:
                result["foreign"]["after"] = driver.definition(foreign_label)
                result["foreign"]["removed"] = driver.foreign_remove(foreign_label, foreign_owner)
            except BaseException as exc:
                result["foreign"]["removed"] = False
                result["cleanup"]["foreign_cleanup_error"] = type(exc).__name__
                if isinstance(exc, ProcessStateUnknown):
                    process_unknown = True
                    result["cleanup"]["command_process_unknown"] = True
        try:
            result["cleanup"]["foreign_absent"] = driver.absent(foreign_label)
            result["cleanup"]["unrelated_after"] = driver.inventory({label, foreign_label})
        except BaseException as exc:
            result["cleanup"]["foreign_absent"] = None
            result["cleanup"]["inventory_error"] = type(exc).__name__
        result["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        errors = consume(result, expected_subject=subject, fixture=fixture, system=system)
        if original_error is not None:
            errors.append("execution_error")
        result["consumer_errors"] = errors
        result["status"] = "passed" if not errors else "failed"
        _progress(output, "08-cleanup", {"cleanup": result["cleanup"],
                                         "status": result["status"], "errors": errors})
        _exclusive_json(output, result)
    return result


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--tool-commit", required=True)
    parser.add_argument("--installed-plugin-root", type=Path, required=True)
    parser.add_argument("--release-zip", type=Path, required=True)
    parser.add_argument("--release-zip-sha256", required=True)
    parser.add_argument("--scheduler-fixture-dir", type=Path, required=True)
    parser.add_argument("--scheduler-label", required=True)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path)
    destination.add_argument("--verify-result", type=Path)
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args(argv)
    if args.preflight and args.verify_result is not None:
        parser.error("--preflight requires --output")
    if not LABEL.fullmatch(args.scheduler_label or ""):
        parser.error("invalid scheduler label")
    entry = Path(__file__).with_name("native_acceptance.py")
    spec = importlib.util.spec_from_file_location("scheduler_native_entrypoint", entry)
    if spec is None or spec.loader is None:
        parser.error("native entrypoint unavailable")
    native = importlib.util.module_from_spec(spec)
    previous_dont_write = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(native)
    finally:
        sys.dont_write_bytecode = previous_dont_write
    try:
        if args.verify_result is not None:
            subject = subject_identity(native, args.repo_root, args.source_commit, args.tool_commit,
                                       args.installed_plugin_root, args.release_zip,
                                       args.release_zip_sha256)
            report = json.loads(args.verify_result.read_text(encoding="utf-8"))
            fixture = args.scheduler_fixture_dir.resolve(strict=True)
            errors = consume(report, expected_subject=subject, fixture=fixture,
                             system=platform.system())
            if not isinstance(report, dict) or report.get("label") != args.scheduler_label:
                errors.append("label")
            if (not isinstance(report, dict)
                    or report.get("foreign_label") != args.scheduler_label + "-foreign"):
                errors.append("foreign_label")
            if not isinstance(report, dict) or report.get("status") != "passed":
                errors.append("status")
            print(json.dumps({"status": "failed" if errors else "passed", "errors": errors}))
            return 1 if errors else 0
        if args.preflight:
            preflight(native, args.repo_root, args.source_commit, args.tool_commit,
                      args.installed_plugin_root, args.release_zip,
                      args.release_zip_sha256, args.output,
                      args.scheduler_fixture_dir, args.scheduler_label)
            print("scheduler_preflight=passed; registration_or_acceptance_not_run")
            return 0
        report = execute(native, args.repo_root, args.source_commit, args.tool_commit,
                         args.installed_plugin_root, args.release_zip, args.release_zip_sha256,
                         args.output, args.scheduler_fixture_dir, args.scheduler_label)
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        print("scheduler_batch=refused; " + str(exc)[:300], file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "consumer_errors": report["consumer_errors"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
