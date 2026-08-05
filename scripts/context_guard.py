#!/usr/bin/env python3
"""Context Guard: local Codex hook runtime with no third-party dependencies."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator

SCHEMA_VERSION = 3
RECOVERY_CHAR_LIMIT = 15000
EVIDENCE_LIMIT = 200
AGENT_RECORD_LIMIT = 64
PLAN_STEP_LIMIT = 32
SUBAGENT_CONTEXT_CHAR_LIMIT = 3000
RETENTION_DAYS = 30
SUCCESSOR_INPUT_FILENAME = "SUCCESSOR_INPUT.json"
SUCCESSOR_HANDOFF_FILENAME = "CONTEXT_HANDOFF.md"
SUCCESSOR_MANIFEST_FILENAME = "CONTEXT_MANIFEST.json"
MAX_SUCCESSOR_INPUT_BYTES = 64 * 1024
MAX_SUCCESSOR_CURRENT_READS = 12
MAX_SUCCESSOR_FULL_READ_BYTES = 96 * 1024
MAX_SUCCESSOR_TARGETED_LINES = 1200
MAX_SUCCESSOR_HASH_BYTES = 256 * 1024 * 1024
MAX_SUCCESSOR_AUDIT_FILES = 80
MAX_SUCCESSOR_AUDIT_BYTES = 256 * 1024 * 1024
TRANSCRIPT_TAIL_BYTES = 2 * 1024 * 1024
STATE_REQUIRED_KEYS = {
    "schema_version",
    "session",
    "mode",
    "prompts",
    "requirements",
    "acceptance_items",
    "supersedes",
    "evidence",
    "evidence_sequence",
    "work_state",
    "agents",
    "open_items",
    "compactions",
    "completion_attempt",
    "completion_checkpoint",
    "continuation_attempts",
    "integrity",
    "content_hash",
}
CHECKPOINT_RE = re.compile(
    r"<!--\s*context-guard-checkpoint\s*(\{.*?\})\s*-->",
    re.IGNORECASE | re.DOTALL,
)
COMPLETION_RE = re.compile(
    r"\b(done|complete[dn]?|finished|implemented|resolved|fixed|shipped|"
    r"deployed|verified|committed|pushed|ready|all tests pass|"
    r"tests?\s+(?:all\s+)?pass(?:ed)?)\b|"
    r"(已完成|已经完成|全部完成|任务完成|实现完毕|验收通过|已经解决|"
    r"已修复|已经修复|修复完成|已处理|处理完毕|处理好了|已交付|可以交付|"
    r"已部署|已更新|已提交|已推送|已验证|修好了|搞定了|可以使用了|"
    r"(?:测试|校验|验证|检查|回归|技能).{0,12}(?:已)?(?:全部|全量|均)?通过)",
    re.IGNORECASE,
)
NON_COMPLETION_RE = re.compile(
    r"\b(not\s+(?:(?:yet|fully|safely)\s+)*(?:done|complete[dn]?|finished|implemented)|"
    r"unfinished|incomplete|remaining|still\s+need|could(?:n't| not)\s+complete|"
    r"(?:await(?:ing)?|wait(?:ing)?\s+for)\s+"
    r"(?:(?:your|user(?:'s)?)\s+)?(?:approval|authorization|confirmation|"
    r"decision|choice|input|response|acceptance)|"
    r"(?:can(?:not|'t)|unable\s+to)\s+(?:safely\s+)?(?:continue|proceed|act)|"
    r"(?:need|require)\s+(?:your|user(?:'s)?)\s+(?:explicit\s+)?"
    r"(?:approval|authorization|confirmation|decision|choice|input|response|acceptance)|"
    r"(?:can(?:not|'t)|should(?:not|n't)|unable\s+to)\s+"
    r"(?:claim|declare|report|say).{0,40}\b(?:done|complete[dn]?|finished))\b|"
    r"(未(?:全部|完全|整体)?完成|尚未(?:全部|完全|整体)?(?:完成|结束)|"
    r"还未(?:全部|完全|整体)?完成|未实现|无法完成|未能完成|"
    r"(?:不能|无法|不可|不应|尚不能).{0,24}(?:宣告|声明|声称).{0,16}完成|"
    r"(?:原始|整个|整体|当前)?任务.{0,16}(?:仍|尚|还)(?:待|需)|"
    r"(?:尚未|还未).{0,20}(?:导入|下载|写入|执行|开始)|"
    r"(?:等待|待)(?:你|您|用户)?(?:的)?(?:明确)?"
    r"(?:验收|确认|授权|决定|选择|回复|输入)|"
    r"(?:你|您|用户).{0,8}(?:需要|请).{0,8}"
    r"(?:验收|确认|授权|决定|选择|回复|输入)|"
    r"(?:必须|需要)(?:先)?(?:得到|获得|收到|等待).{0,16}"
    r"(?:验收|确认|授权|决定|选择|回复|输入)|"
    r"(?:无法|不能|不可|尚不能)(?:安全)?(?:继续|推进|执行|操作)|"
    r"仍待处理|仍需继续|还需要|被阻塞|阻塞[：:])",
    re.IGNORECASE,
)
INTERNAL_CONTINUATION_PREFIX = "[Context Guard continuation]"
EVIDENCE_ID_RE = re.compile(r"^E\d{4,}$")
STAGE_REQUEST_MARKER = "CONTEXT_GUARD_STAGE_REQUEST"
PRIVATE_METADATA_RE = re.compile(
    r"context-guard-checkpoint|checkpoint-status|stage-checkpoint|"
    r"CONTEXT_GUARD_DATA_DIR|CLAUDE_PLUGIN_DATA",
    re.IGNORECASE,
)
FAILED_TOOL_RESPONSE_RE = re.compile(
    r"(?im)^\s*(?:script (?:failed|error)|command failed|"
    r"(?:script|command) completed with (?:errors?|failures?)|"
    r"fatal:|error:|\[fail\]|"
    r"traceback \(most recent call last\)|"
    r".*(?:operation not permitted|permission denied|command not found|"
    r"no such file or directory))"
)
AUTHORITATIVE_SUCCESS_TOOL_RESPONSE_RE = re.compile(
    r"(?im)^\s*(?:script completed|command completed)\s*$"
)
WEAK_SUCCESS_TOOL_RESPONSE_RE = re.compile(
    r"(?im)^\s*(?:\[ok\]|smoke_pass\b|pass\b|done!\s*$|plan updated\s*$)"
)
SUPERSESSION_INTENT_RE = re.compile(
    r"(?:改为|改成|取消|不再|以此为准|替代|覆盖|修正|"
    r"\breplace\b|\bsupersede\b|\bcancel\b)",
    re.I,
)
SUPERSESSION_NEGATION_PREFIX_RE = re.compile(
    r"(?:不要|不得|不能|不应|无需|并非|不是|切勿|勿|别|"
    r"do\s+not|don't|must\s+not|should\s+not|never|without)\s*"
    r"(?:(?:再|擅自|直接|随意|轻易|ever|again|silently|automatically)\s*)*$",
    re.I,
)
DATA_URL_RE = re.compile(
    r"^data:(?P<mime>[^;,]+)?(?P<parameters>(?:;[^,]*)*?),(?P<body>.*)$",
    re.IGNORECASE | re.DOTALL,
)
BASE64_TEXT_RE = re.compile(r"^[A-Za-z0-9+/=_\-\s]+$")
BINARY_VALUE_KEYS = {
    "audio_url",
    "base64",
    "blob",
    "bytes",
    "encrypted_content",
    "image_url",
}
BINARY_CONTAINER_TYPES = {"audio", "binary", "blob", "image", "video"}
DELEGATION_RE = re.compile(
    r"^\s*<codex_delegation>.*?</codex_delegation>\s*$",
    re.I | re.S,
)
AGENT_RESULT_FIELDS = {
    "outcome": ("outcome", "结果", "结论"),
    "evidence": ("evidence", "证据"),
    "validation": ("validation", "verification", "校验", "验证", "测试"),
    "limitations": ("limitations", "limitation", "限制", "局限", "未覆盖"),
    "next": ("next", "next steps", "下一步", "后续"),
}
SECRET_PATTERNS = (
    (re.compile(r"\b(sk-[A-Za-z0-9_-]{12,})\b"), "[REDACTED]"),
    (
        re.compile(r"(?i)\b(authorization\s*:\s*)(?:bearer\s+)?[^\s,;]+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|secret|password)"
            r"(\s*[:=]\s*)[^\s,;]+"
        ),
        r"\1\2[REDACTED]",
    ),
    (
        re.compile(r"([?&](?:token|key|secret|signature|auth)=)[^&#\s]+", re.I),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(https?://[^\s?#]+)\?[^\s#]*(?:#[^\s]*)?", re.I),
        r"\1?[QUERY_REDACTED]",
    ),
    (
        re.compile(
            r"(?i)(--token\s+)(?:\"[^\"]+\"|'[^']+'|[^\s,;]+)"
        ),
        r"\1[REDACTED]",
    ),
)
SURROGATE_RE = re.compile(r"[\uD800-\uDFFF]")


class StateIntegrityError(RuntimeError):
    """Raised when private session state cannot be trusted."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def redact_text(value: str) -> str:
    redacted = value
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def repair_unicode_scalars(value: Any) -> tuple[Any, int]:
    if isinstance(value, str):
        return SURROGATE_RE.subn("\ufffd", value)
    if isinstance(value, list):
        repaired_items: list[Any] = []
        repairs = 0
        for item in value:
            repaired, count = repair_unicode_scalars(item)
            repaired_items.append(repaired)
            repairs += count
        return repaired_items, repairs
    if isinstance(value, dict):
        repaired_items: dict[Any, Any] = {}
        repairs = 0
        for key, item in value.items():
            repaired_key, key_count = repair_unicode_scalars(key)
            repaired, count = repair_unicode_scalars(item)
            repaired_items[repaired_key] = repaired
            repairs += key_count + count
        return repaired_items, repairs
    return value, 0


def bounded(value: Any, limit: int = 1200) -> str:
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            text = repr(value)
    text = redact_text(text.replace("\x00", ""))
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n…[truncated {len(text) - limit} chars]"


def binary_placeholder(value: str, *, mime: str | None = None) -> str:
    kind = mime or "base64"
    digest = sha256_text(value)
    return f"[binary omitted: type={kind}, chars={len(value)}, sha256={digest}]"


def sanitize_evidence_value(
    value: Any,
    *,
    key: str | None = None,
    binary_context: bool = False,
    depth: int = 0,
) -> Any:
    """Remove binary payloads before serializing bounded tool evidence."""
    if depth >= 8:
        return "[nested value omitted]"
    if isinstance(value, str):
        match = DATA_URL_RE.match(value)
        if match:
            return binary_placeholder(value, mime=match.group("mime") or "data-url")
        normalized_key = (key or "").lower()
        compact = re.sub(r"\s+", "", value)
        if (
            (
                normalized_key in BINARY_VALUE_KEYS
                or (binary_context and normalized_key in {"", "data"})
            )
            and len(compact) >= 512
            and BASE64_TEXT_RE.fullmatch(compact)
        ):
            return binary_placeholder(value)
        return value
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        items = list(value.items())
        container_type = str(value.get("type") or value.get("kind") or "").lower()
        container_mime = str(
            value.get("mimeType")
            or value.get("mime_type")
            or value.get("mime")
            or ""
        ).lower()
        declares_binary = (
            container_type in BINARY_CONTAINER_TYPES
            or container_mime.startswith(("image/", "audio/", "video/"))
            or container_mime
            in {
                "application/octet-stream",
                "application/pdf",
                "application/zip",
            }
        )
        for raw_key, item in items[:64]:
            text_key = str(raw_key)
            result[text_key] = sanitize_evidence_value(
                item,
                key=text_key,
                binary_context=declares_binary,
                depth=depth + 1,
            )
        if len(items) > 64:
            result["_context_guard_omitted_keys"] = len(items) - 64
        return result
    if isinstance(value, (list, tuple)):
        items = list(value)
        result = [
            sanitize_evidence_value(
                item,
                binary_context=binary_context,
                depth=depth + 1,
            )
            for item in items[:64]
        ]
        if len(items) > 64:
            result.append(f"[omitted {len(items) - 64} items]")
        return result
    return value


def bounded_evidence(value: Any, limit: int) -> str:
    return bounded(sanitize_evidence_value(value), limit)


def console_write(value: Any, *, stream: Any = None) -> None:
    target = stream or sys.stdout
    text = str(value)
    try:
        target.write(text + "\n")
    except UnicodeEncodeError:
        encoding = getattr(target, "encoding", None) or "ascii"
        safe = text.encode(encoding, errors="backslashreplace").decode(encoding)
        target.write(safe + "\n")


def safe_session_id(value: Any) -> str:
    raw = str(value or "unknown-session")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", raw)[:160]
    return safe or "unknown-session"


def data_root() -> Path:
    configured = (
        os.environ.get("CONTEXT_GUARD_DATA_DIR")
        or os.environ.get("PLUGIN_DATA")
        or os.environ.get("CLAUDE_PLUGIN_DATA")
    )
    return Path(configured).expanduser() if configured else Path.home() / ".codex" / "context-guard"


def secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass


def secure_file(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass


def atomic_write_text(path: Path, content: str) -> None:
    secure_directory(path.parent)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False, prefix=f".{path.name}."
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        secure_file(temp_path)
        os.replace(temp_path, path)
        secure_file(path)
    except BaseException:
        with contextlib.suppress(OSError):
            temp_path.unlink()
        raise


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def read_json(path: Path, default: Any = None) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def state_content_hash(state: dict[str, Any]) -> str:
    hashable = dict(state)
    hashable.pop("content_hash", None)
    return sha256_text(canonical_json(hashable))


def prompt_record_hash(record: dict[str, Any]) -> str:
    hashable = dict(record)
    hashable.pop("record_sha256", None)
    return sha256_text(canonical_json(hashable))


def validate_state_integrity(state: dict[str, Any]) -> None:
    version = state.get("schema_version")
    if version not in {1, 2, SCHEMA_VERSION}:
        raise StateIntegrityError(f"unsupported private state schema {version!r}")
    stored_hash = state.get("content_hash")
    if not isinstance(stored_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", stored_hash):
        raise StateIntegrityError("private state has no valid content hash")
    expected_hash = state_content_hash(state)
    if not hmac.compare_digest(stored_hash, expected_hash):
        raise StateIntegrityError("private state content hash mismatch")
    if version == 1:
        required = STATE_REQUIRED_KEYS - {
            "integrity",
            "evidence_sequence",
            "completion_attempt",
            "work_state",
            "agents",
        }
    elif version == 2:
        required = STATE_REQUIRED_KEYS - {"integrity", "work_state", "agents"}
    else:
        required = STATE_REQUIRED_KEYS
    missing = sorted(required - set(state))
    if missing:
        raise StateIntegrityError(
            "private state is missing required fields: " + ", ".join(missing)
        )
    for key in (
        "session",
        "mode",
    ):
        if not isinstance(state.get(key), dict):
            raise StateIntegrityError(f"private state field {key} must be an object")
    if version >= 3 and not isinstance(state.get("work_state"), dict):
        raise StateIntegrityError("private state field work_state must be an object")
    for key in (
        "prompts",
        "requirements",
        "acceptance_items",
        "supersedes",
        "evidence",
        "agents",
        "open_items",
        "compactions",
    ):
        if key in state and not isinstance(state.get(key), list):
            raise StateIntegrityError(f"private state field {key} must be a list")


def preserve_corrupt_state(path: Path) -> Path | None:
    if not path.exists() or not path.is_file():
        return None
    timestamp = f"{int(time.time() * 1000)}-{os.getpid()}"
    backup = path.with_name(f"state.corrupt.{timestamp}.json")
    try:
        shutil.copy2(path, backup)
        secure_file(backup)
        return backup
    except OSError:
        return None


@contextlib.contextmanager
def session_lock(session_dir: Path, timeout: float = 5.0) -> Iterator[None]:
    secure_directory(session_dir)
    lock_path = session_dir / ".lock"
    deadline = time.monotonic() + timeout
    descriptor: int | None = None
    while descriptor is None:
        try:
            descriptor = os.open(
                str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
            )
            os.write(descriptor, f"{os.getpid()} {time.time()}".encode("ascii"))
        except (FileExistsError, PermissionError) as exc:
            # Windows can report an existing, still-open O_EXCL lock as
            # ERROR_ACCESS_DENIED instead of ERROR_FILE_EXISTS.
            if isinstance(exc, PermissionError) and not lock_path.exists():
                raise
            try:
                if time.time() - lock_path.stat().st_mtime > 30:
                    lock_path.unlink()
                    continue
            except FileNotFoundError:
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError(f"timed out waiting for {lock_path}")
            time.sleep(0.025)
    try:
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            lock_path.unlink()


def session_dir_for(payload: dict[str, Any]) -> Path:
    return data_root() / "sessions" / safe_session_id(payload.get("session_id"))


def new_state(payload: dict[str, Any]) -> dict[str, Any]:
    now = utc_now()
    return {
        "schema_version": SCHEMA_VERSION,
        "session": {
            "id": str(payload.get("session_id") or "unknown-session"),
            "cwd": str(payload.get("cwd") or os.getcwd()),
            "model": payload.get("model"),
            "permission_mode": payload.get("permission_mode"),
            "transcript_path": payload.get("transcript_path"),
            "created_at": now,
            "updated_at": now,
            "ended_at": None,
        },
        "mode": {
            "active": False,
            "manual_off": False,
            "complexity_score": 0,
            "activation_reasons": [],
        },
        "prompts": [],
        "requirements": [],
        "acceptance_items": [],
        "supersedes": [],
        "evidence": [],
        "evidence_sequence": 0,
        "work_state": {
            "plan_snapshot": None,
        },
        "agents": [],
        "open_items": [],
        "compactions": [],
        "completion_attempt": None,
        "completion_checkpoint": None,
        "continuation_attempts": 0,
        "integrity": {
            "status": "ok",
            "issue": None,
            "recovered_at": None,
            "backup_file": None,
        },
        "content_hash": "",
    }


def migrate_state(state: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    version = state.get("schema_version")
    if version == 1:
        evidence_sequence = 0
        for item in state.get("evidence", []):
            match = re.fullmatch(r"E(\d+)", str(item.get("id") or ""))
            if match:
                evidence_sequence = max(evidence_sequence, int(match.group(1)))
        for collection in ("requirements", "acceptance_items"):
            for item in state.get(collection, []):
                evidence = item.get("evidence", [])
                if item.get("status") == "pass" and (
                    not isinstance(evidence, list)
                    or not evidence
                    or any(
                        not isinstance(value, str)
                        or not EVIDENCE_ID_RE.fullmatch(value)
                        for value in evidence
                    )
                ):
                    item["status"] = "pending"
                    item["evidence"] = []
        state["evidence_sequence"] = evidence_sequence
        state["completion_attempt"] = None
    elif version not in {2, SCHEMA_VERSION}:
        raise StateIntegrityError(f"unsupported private state schema {version!r}")
    if version in {1, 2}:
        state["work_state"] = {"plan_snapshot": None}
        state["agents"] = []
        state["schema_version"] = SCHEMA_VERSION
    if not isinstance(state.get("integrity"), dict):
        state["integrity"] = {
            "status": "ok",
            "issue": None,
            "recovered_at": None,
            "backup_file": None,
        }
    state.setdefault("evidence_sequence", 0)
    work_state = state.setdefault("work_state", {"plan_snapshot": None})
    if isinstance(work_state, dict):
        work_state.setdefault("plan_snapshot", None)
    state.setdefault("agents", [])
    state.setdefault("completion_attempt", None)
    state.setdefault("continuation_attempts", 0)
    return state


def load_state(session_dir: Path, payload: dict[str, Any]) -> dict[str, Any]:
    state_path = session_dir / "state.json"
    if not state_path.exists():
        prompt_dir = session_dir / "prompts"
        if prompt_dir.is_dir() and any(prompt_dir.glob("P*.json")):
            state = rebuild_state_from_prompts(
                session_dir,
                payload,
                issue="private state file is missing",
                backup_file=None,
            )
        else:
            state = new_state(payload)
    else:
        issue: str | None = None
        try:
            with state_path.open("r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if not isinstance(loaded, dict):
                raise StateIntegrityError("private state root must be an object")
            validate_state_integrity(loaded)
            state = migrate_state(loaded, payload)
            integrity = state.get("integrity")
            if isinstance(integrity, dict) and integrity.get("status") == "failed":
                state = rebuild_state_from_prompts(
                    session_dir,
                    payload,
                    issue=(
                        "retrying prior private-state recovery failure: "
                        + bounded(integrity.get("issue"), 800)
                    ),
                    backup_file=integrity.get("backup_file"),
                )
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            StateIntegrityError,
            TypeError,
            ValueError,
        ) as exc:
            issue = f"{type(exc).__name__}: {exc}"
            backup = preserve_corrupt_state(state_path)
            state = rebuild_state_from_prompts(
                session_dir,
                payload,
                issue=issue,
                backup_file=backup.name if backup is not None else None,
            )
    session = state.setdefault("session", {})
    for key in ("cwd", "model", "permission_mode", "transcript_path"):
        if payload.get(key) is not None:
            session[key] = payload[key]
    return state


def save_state(session_dir: Path, state: dict[str, Any]) -> None:
    state["session"]["updated_at"] = utc_now()
    state["content_hash"] = state_content_hash(state)
    atomic_write_json(session_dir / "state.json", state)


def prompt_text(payload: dict[str, Any]) -> str:
    for key in ("prompt", "user_prompt", "message"):
        if isinstance(payload.get(key), str):
            return payload[key]
    return ""


def assistant_text(payload: dict[str, Any]) -> str:
    for key in ("last_assistant_message", "assistant_response", "response"):
        if isinstance(payload.get(key), str):
            return payload[key]
    return ""


def latest_transcript_turn_id(
    state: dict[str, Any], payload: dict[str, Any]
) -> str | None:
    """Return the latest real turn id recorded by Codex, if available."""
    session = state.get("session")
    stored_path = (
        session.get("transcript_path") if isinstance(session, dict) else None
    )
    raw_path = payload.get("transcript_path") or stored_path
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None
    transcript = Path(raw_path).expanduser()
    try:
        with transcript.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            start = max(0, size - TRANSCRIPT_TAIL_BYTES)
            handle.seek(start)
            tail = handle.read()
    except OSError:
        return None
    if start:
        _, separator, tail = tail.partition(b"\n")
        if not separator:
            return None
    for raw_line in reversed(tail.splitlines()):
        try:
            record = json.loads(raw_line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(record, dict) or record.get("type") != "turn_context":
            continue
        record_payload = record.get("payload")
        if not isinstance(record_payload, dict):
            continue
        turn_id = record_payload.get("turn_id")
        if isinstance(turn_id, str) and turn_id.strip():
            return turn_id.strip()
    return None


def claims_completion(text: str) -> bool:
    if NON_COMPLETION_RE.search(text):
        return False
    return bool(COMPLETION_RE.search(text))


def score_complexity(text: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    lines = [line for line in text.splitlines() if line.strip()]
    bullets = sum(bool(re.match(r"\s*(?:[-*+]|\d+[.)])\s+", line)) for line in lines)
    if len(text) >= 1200:
        score += 3
        reasons.append("long_prompt")
    elif len(text) >= 500:
        score += 2
        reasons.append("medium_prompt")
    if len(lines) >= 12:
        score += 2
        reasons.append("many_lines")
    if bullets >= 4:
        score += 2
        reasons.append("checklist")
    if re.search(
        r"(implement|build|refactor|migrate|install|deploy|测试|实现|构建|迁移|安装|部署)",
        text,
        re.I,
    ):
        score += 2
        reasons.append("implementation")
    if re.search(
        r"(verify|validate|acceptance|doctor|smoke test|验收|验证|不得|必须|不要|边界)",
        text,
        re.I,
    ):
        score += 2
        reasons.append("hard_constraints")
    if re.search(r"(?:^|\s)(?:/|[A-Za-z]:\\)[^\s]+|[\w.-]+\.(?:py|md|toml|json|sh|ps1)\b", text):
        score += 1
        reasons.append("artifacts")
    return score, reasons


def extract_acceptance(text: str) -> list[str]:
    items: list[str] = []
    for raw_line in text.splitlines():
        line = re.sub(r"^\s*(?:[-*+]|\d+[.)])\s+", "", raw_line).strip()
        if not line or len(line) < 6 or len(line) > 500:
            continue
        if re.search(
            r"(must|should|verify|validate|test|accept|do not|不得|必须|确认|验证|测试|验收|门禁|不进入|不保存)",
            line,
            re.I,
        ):
            items.append(line)
    return list(dict.fromkeys(items))[:32]


def is_control_prompt(text: str) -> bool:
    stripped = text.strip()
    return bool(
        stripped.startswith(INTERNAL_CONTINUATION_PREFIX)
        or re.fullmatch(
            r"\$?context-guard(?:\s+(?:on|off|status|export|rollover)(?:\s+.+)?)?",
            stripped,
            re.I,
        )
    )


def control_action(text: str) -> tuple[str | None, str | None]:
    stripped = text.strip()
    match = re.fullmatch(
        r"\$?context-guard(?:\s+(on|off|status|export|rollover)(?:\s+(.+))?)?",
        stripped,
        re.I,
    )
    if not match:
        return None, None
    return (match.group(1) or "on").lower(), match.group(2)


def classify_prompt_origin(
    state: dict[str, Any], payload: dict[str, Any], text: str
) -> tuple[str, str, str | None]:
    if text.lstrip().startswith(INTERNAL_CONTINUATION_PREFIX):
        return "internal", "internal", None
    payload_agent_id = payload.get("agent_id")
    if isinstance(payload_agent_id, str) and payload_agent_id.strip():
        return "subagent_delegation", "delegated", payload_agent_id.strip()
    turn_id = str(payload.get("turn_id") or "")
    for agent in reversed(state.get("agents", [])):
        if (
            isinstance(agent, dict)
            and turn_id
            and turn_id == str(agent.get("start_turn_id") or "")
        ):
            return (
                "subagent_delegation",
                "delegated",
                str(agent.get("agent_id") or "") or None,
            )
    if DELEGATION_RE.search(text):
        running_agents = [
            agent
            for agent in state.get("agents", [])
            if isinstance(agent, dict) and agent.get("status") == "running"
        ]
        if running_agents:
            actor_id = str(running_agents[-1].get("agent_id") or "") or None
            return "subagent_delegation", "delegated", actor_id
    return "human", "user", None


def append_prompt(
    session_dir: Path,
    state: dict[str, Any],
    text: str,
    unicode_repairs: int = 0,
    *,
    origin: str = "human",
    authority: str = "user",
    actor_id: str | None = None,
) -> dict[str, Any]:
    sequences = [
        int(match.group(1))
        for path in (session_dir / "prompts").glob("P*.json")
        if (match := re.fullmatch(r"P(\d{4,})\.json", path.name))
    ]
    sequences.extend(
        int(match.group(1))
        for item in state["prompts"]
        if (match := re.fullmatch(r"P(\d{4,})", str(item.get("id") or "")))
    )
    prompt_id = f"P{max(sequences, default=0) + 1:04d}"
    path = session_dir / "prompts" / f"{prompt_id}.json"
    record = {
        "id": prompt_id,
        "created_at": utc_now(),
        "sha256": sha256_text(text),
        "text": text,
        "unicode_repairs": unicode_repairs,
        "origin": origin,
        "authority": authority,
        "actor_id": actor_id,
    }
    record["record_sha256"] = prompt_record_hash(record)
    if path.exists():
        raise RuntimeError(f"immutable prompt already exists: {path}")
    atomic_write_json(path, record)
    metadata = {
        "id": prompt_id,
        "created_at": record["created_at"],
        "sha256": record["sha256"],
        "chars": len(text),
        "file": f"prompts/{prompt_id}.json",
        "unicode_repairs": unicode_repairs,
        "origin": origin,
        "authority": authority,
        "actor_id": actor_id,
        "record_sha256": record["record_sha256"],
    }
    state["prompts"].append(metadata)
    return metadata


def append_requirement(state: dict[str, Any], prompt: dict[str, Any], text: str) -> str:
    requirement_id = f"R{len(state['requirements']) + 1:03d}"
    state["requirements"].append(
        {
            "id": requirement_id,
            "prompt_id": prompt["id"],
            "text": bounded(text, 900),
            "sha256": prompt["sha256"],
            "status": "pending",
            "evidence": [],
        }
    )
    return requirement_id


def append_acceptance(state: dict[str, Any], prompt_id: str, text: str) -> None:
    existing = {item["text"] for item in state["acceptance_items"]}
    for candidate in extract_acceptance(text):
        if candidate in existing:
            continue
        state["acceptance_items"].append(
            {
                "id": f"A{len(state['acceptance_items']) + 1:03d}",
                "prompt_id": prompt_id,
                "text": candidate,
                "status": "pending",
                "evidence": [],
            }
        )
        existing.add(candidate)


def has_positive_supersession_intent(text: str) -> bool:
    positive = False
    negated = False
    for match in SUPERSESSION_INTENT_RE.finditer(text):
        clause_prefix = re.split(r"[\n.!?。！？,，;；]", text[: match.start()])[-1]
        if SUPERSESSION_NEGATION_PREFIX_RE.search(clause_prefix[-80:]):
            negated = True
            continue
        positive = True
    return positive and not negated


def record_supersession(state: dict[str, Any], text: str, new_requirement_id: str) -> None:
    if len(state["requirements"]) < 2:
        return
    if not has_positive_supersession_intent(text):
        return
    known_ids = {item["id"] for item in state["requirements"]}
    explicit = list(
        dict.fromkeys(
            item.upper()
            for item in re.findall(r"\bR\d{3}\b", text, re.I)
            if item.upper() in known_ids and item.upper() != new_requirement_id
        )
    )
    if len(explicit) > 1:
        return
    target = explicit[0] if explicit else state["requirements"][-2]["id"]
    if target == new_requirement_id:
        return
    if target not in known_ids:
        return
    state["supersedes"].append(
        {
            "old_id": target,
            "new_id": new_requirement_id,
            "created_at": utc_now(),
            "reason": bounded(text, 400),
        }
    )
    for item in state["requirements"]:
        if item["id"] == target:
            item["status"] = "superseded"


def prompt_records_from_disk(session_dir: Path) -> list[dict[str, Any]]:
    prompt_dir = session_dir / "prompts"
    if not prompt_dir.is_dir():
        return []
    records: list[tuple[int, dict[str, Any]]] = []
    for path in sorted(prompt_dir.glob("P*.json")):
        match = re.fullmatch(r"P(\d{4,})\.json", path.name)
        if match is None or path.is_symlink() or not path.is_file():
            raise StateIntegrityError(f"invalid immutable prompt file {path.name}")
        try:
            with path.open("r", encoding="utf-8") as handle:
                record = json.load(handle)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise StateIntegrityError(
                f"cannot read immutable prompt file {path.name}: {exc}"
            ) from exc
        prompt_id = path.stem
        if not isinstance(record, dict) or record.get("id") != prompt_id:
            raise StateIntegrityError(f"immutable prompt identity mismatch in {path.name}")
        text = record.get("text")
        digest = record.get("sha256")
        if not isinstance(text, str) or digest != sha256_text(text):
            raise StateIntegrityError(f"immutable prompt hash mismatch in {path.name}")
        if not isinstance(record.get("created_at"), str):
            raise StateIntegrityError(f"immutable prompt timestamp is invalid in {path.name}")
        unicode_repairs = record.get("unicode_repairs", 0)
        if (
            isinstance(unicode_repairs, bool)
            or not isinstance(unicode_repairs, int)
            or unicode_repairs < 0
        ):
            raise StateIntegrityError(
                f"immutable prompt Unicode repair count is invalid in {path.name}"
            )
        record_digest = record.get("record_sha256")
        if record_digest is not None and record_digest != prompt_record_hash(record):
            raise StateIntegrityError(
                f"immutable prompt record hash mismatch in {path.name}"
            )
        records.append((int(match.group(1)), record))
    if len({sequence for sequence, _ in records}) != len(records):
        raise StateIntegrityError("immutable prompt sequence contains duplicates")
    return [record for _, record in sorted(records, key=lambda item: item[0])]


def replay_prompt_record(
    state: dict[str, Any], record: dict[str, Any]
) -> None:
    text = record["text"]
    origin = record.get("origin")
    if origin not in {"human", "subagent_delegation", "internal"}:
        if text.lstrip().startswith(INTERNAL_CONTINUATION_PREFIX):
            origin = "internal"
        else:
            origin = "human"
    authority = record.get("authority")
    if authority not in {"user", "delegated", "internal"}:
        authority = {
            "human": "user",
            "subagent_delegation": "delegated",
            "internal": "internal",
        }[origin]
    metadata = {
        "id": record["id"],
        "created_at": record["created_at"],
        "sha256": record["sha256"],
        "chars": len(text),
        "file": f"prompts/{record['id']}.json",
        "unicode_repairs": record.get("unicode_repairs", 0),
        "origin": origin,
        "authority": authority,
        "actor_id": record.get("actor_id"),
        "record_sha256": record.get("record_sha256"),
    }
    state["prompts"].append(metadata)
    if origin != "human":
        return
    action, _ = control_action(text)
    if action == "on":
        state["mode"]["active"] = True
        state["mode"]["manual_off"] = False
        state["mode"]["activation_reasons"] = list(
            dict.fromkeys(state["mode"]["activation_reasons"] + ["explicit"])
        )
    elif action == "off":
        state["mode"]["active"] = False
        state["mode"]["manual_off"] = True
    if is_control_prompt(text):
        return
    requirement_id = append_requirement(state, metadata, text)
    append_acceptance(state, metadata["id"], text)
    record_supersession(state, text, requirement_id)
    score, reasons = score_complexity(text)
    goal_requested = bool(re.search(r"^\s*/goal\b", text, re.I | re.MULTILINE))
    if goal_requested:
        reasons.append("goal")
    state["mode"]["complexity_score"] = max(
        state["mode"]["complexity_score"], score
    )
    state["mode"]["activation_reasons"] = list(
        dict.fromkeys(state["mode"]["activation_reasons"] + reasons)
    )
    if not state["mode"]["manual_off"] and (
        score >= 4
        or "$context-guard" in text.lower()
        or goal_requested
        or len(state["acceptance_items"]) >= 2
        or len(state["requirements"]) >= 3
    ):
        state["mode"]["active"] = True


def rebuild_state_from_prompts(
    session_dir: Path,
    payload: dict[str, Any],
    *,
    issue: str,
    backup_file: str | None,
) -> dict[str, Any]:
    rebuilt = new_state(payload)
    try:
        records = prompt_records_from_disk(session_dir)
        if not records:
            raise StateIntegrityError("no immutable prompt records are available")
        for record in records:
            replay_prompt_record(rebuilt, record)
        rebuilt["session"]["created_at"] = records[0]["created_at"]
        rebuilt["open_items"] = open_item_ids(rebuilt)
        rebuilt["integrity"] = {
            "status": "recovered_from_prompts",
            "issue": bounded(issue, 800),
            "recovered_at": utc_now(),
            "backup_file": backup_file,
        }
    except (OSError, StateIntegrityError, TypeError, ValueError) as exc:
        rebuilt["mode"]["active"] = True
        rebuilt["mode"]["manual_off"] = False
        rebuilt["open_items"] = ["STATE_INTEGRITY"]
        rebuilt["integrity"] = {
            "status": "failed",
            "issue": bounded(f"{issue}; prompt recovery failed: {exc}", 1200),
            "recovered_at": None,
            "backup_file": backup_file,
        }
    return rebuilt


def require_usable_state(state: dict[str, Any]) -> None:
    integrity = state.get("integrity")
    status = integrity.get("status") if isinstance(integrity, dict) else None
    if status not in {"ok", "recovered_from_prompts"}:
        issue = integrity.get("issue") if isinstance(integrity, dict) else None
        raise StateIntegrityError(
            "private state integrity is unavailable"
            + (f": {bounded(issue, 800)}" if issue else "")
        )


def open_item_ids(state: dict[str, Any]) -> list[str]:
    result = []
    for collection in ("requirements", "acceptance_items"):
        for item in state[collection]:
            if item.get("status") not in {"pass", "superseded"}:
                result.append(item["id"])
    return result


def trim_evidence(state: dict[str, Any]) -> None:
    referenced = {
        evidence_id
        for collection in ("requirements", "acceptance_items")
        for item in state[collection]
        for evidence_id in item.get("evidence", [])
        if isinstance(evidence_id, str)
    }
    recent_unreferenced = [
        item
        for item in state["evidence"]
        if item.get("id") not in referenced
    ][-EVIDENCE_LIMIT:]
    keep_ids = referenced | {
        item["id"]
        for item in recent_unreferenced
        if isinstance(item.get("id"), str)
    }
    state["evidence"] = [
        item for item in state["evidence"] if item.get("id") in keep_ids
    ]


def status_context(state: dict[str, Any]) -> str:
    integrity = state.get("integrity", {})
    return (
        "Context Guard status: "
        f"active={state['mode']['active']}, "
        f"integrity={integrity.get('status', 'unknown')}, "
        f"requirements={len(state['requirements'])}, "
        f"acceptance={len(state['acceptance_items'])}, "
        f"open={len(open_item_ids(state))}, "
        f"agents={len(state.get('agents', []))}, "
        f"compactions={len(state['compactions'])}, "
        f"continuations={state['continuation_attempts']}."
    )


def trim_agent_records(state: dict[str, Any]) -> None:
    agents = [item for item in state.get("agents", []) if isinstance(item, dict)]
    active = [item for item in agents if item.get("status") == "running"]
    completed = [item for item in agents if item.get("status") != "running"]
    keep = active + completed[-AGENT_RECORD_LIMIT:]
    state["agents"] = keep[-(AGENT_RECORD_LIMIT + len(active)) :]


def agent_record(state: dict[str, Any], agent_id: str) -> dict[str, Any] | None:
    for item in reversed(state.get("agents", [])):
        if isinstance(item, dict) and item.get("agent_id") == agent_id:
            return item
    return None


def tool_actor(state: dict[str, Any], payload: dict[str, Any]) -> tuple[str, str | None]:
    del state
    payload_agent_id = payload.get("agent_id")
    if isinstance(payload_agent_id, str) and payload_agent_id.strip():
        return "subagent", payload_agent_id.strip()
    return "runtime_unattributed", None


def private_metadata_free_text(value: str) -> str:
    lines = [
        line
        for line in value.splitlines()
        if not PRIVATE_METADATA_RE.search(line)
    ]
    return redact_text("\n".join(lines))


def agent_result_envelope(text: str) -> dict[str, Any]:
    found: dict[str, bool] = {}
    for field, aliases in AGENT_RESULT_FIELDS.items():
        found[field] = any(
            re.search(rf"(?im)^\s*(?:[-*]\s*)?{re.escape(alias)}\s*[:：]", text)
            for alias in aliases
        )
    found["complete"] = all(
        found[field] for field in ("outcome", "evidence", "validation", "limitations")
    )
    return found


def subagent_contract_context(state: dict[str, Any]) -> str:
    lines = [
        "Context Guard delegated-task contract:",
        "- The root user's requirements remain authoritative; this subagent may not add, cancel, or supersede them.",
        "- Work only on the delegated scope supplied by the parent agent.",
        "- Return a concise result using labels Outcome, Evidence, Validation, Limitations, and Next.",
        "- Do not claim that the root task is complete.",
        "Root open items:",
    ]
    for collection in ("requirements", "acceptance_items"):
        for item in state.get(collection, []):
            if item.get("status") in {"pass", "superseded"}:
                continue
            lines.append(
                f"- {item.get('id')}: {bounded(item.get('text', ''), 320)}"
            )
    text = private_metadata_free_text("\n".join(lines))
    if len(text) > SUBAGENT_CONTEXT_CHAR_LIMIT:
        text = (
            text[: SUBAGENT_CONTEXT_CHAR_LIMIT - 80]
            + "\n…[subagent contract clipped to budget]"
        )
    return text


def read_prompt_record(session_dir: Path, metadata: dict[str, Any]) -> dict[str, Any] | None:
    relative = metadata.get("file")
    if not isinstance(relative, str):
        return None
    candidate = (session_dir / relative).resolve()
    try:
        candidate.relative_to(session_dir.resolve())
    except ValueError:
        return None
    value = read_json(candidate)
    if not isinstance(value, dict):
        return None
    text = value.get("text")
    digest = value.get("sha256")
    if (
        value.get("id") != metadata.get("id")
        or not isinstance(text, str)
        or digest != sha256_text(text)
        or digest != metadata.get("sha256")
        or (
            value.get("record_sha256") is not None
            and value.get("record_sha256") != prompt_record_hash(value)
        )
    ):
        return None
    return value


def format_items(title: str, items: list[dict[str, Any]], include_evidence: bool = False) -> str:
    lines = [f"## {title}"]
    if not items:
        lines.append("- None")
    for item in items:
        line = f"- {item['id']} [{item.get('status', 'pending')}]: {bounded(item.get('text', ''), 600)}"
        if include_evidence and item.get("evidence"):
            line += f" | evidence: {bounded(item['evidence'], 500)}"
        lines.append(line)
    return "\n".join(lines)


def recovery_packet(session_dir: Path, state: dict[str, Any]) -> str:
    integrity = state.get("integrity", {})
    sections: list[str] = [
        "# CONTEXT-GUARD RECOVERY PACKET",
        "This packet restores task boundaries after compaction. The private raw prompt ledger remains the fact source.",
        (
            "Integrity status: "
            f"{integrity.get('status', 'unknown')}. "
            "If recovery occurred, all reconstructed items require fresh evidence."
        ),
        format_items("Hard boundaries and requirements", state["requirements"], True),
        format_items("Acceptance criteria", state["acceptance_items"], True),
    ]
    if state["supersedes"]:
        lines = ["## Latest user revisions"]
        for item in state["supersedes"][-12:]:
            lines.append(
                f"- {item['new_id']} supersedes {item['old_id']}: {bounded(item['reason'], 400)}"
            )
        sections.append("\n".join(lines))
    open_ids = open_item_ids(state)
    sections.append("## Unfinished items\n- " + (", ".join(open_ids) if open_ids else "None"))
    plan_snapshot = state.get("work_state", {}).get("plan_snapshot")
    if isinstance(plan_snapshot, dict) and plan_snapshot.get("steps"):
        lines = [
            "## Latest Codex plan mirror",
            "This is a read-only recovery copy of the latest observed update_plan state; Codex remains the plan owner.",
            f"- sha256: {plan_snapshot.get('sha256', 'unknown')}",
        ]
        if plan_snapshot.get("explanation"):
            lines.append(
                f"- explanation: {bounded(plan_snapshot.get('explanation'), 500)}"
            )
        for item in plan_snapshot.get("steps", [])[:PLAN_STEP_LIMIT]:
            if isinstance(item, dict):
                lines.append(
                    f"- [{item.get('status', 'pending')}] {bounded(item.get('step', ''), 420)}"
                )
        sections.append("\n".join(lines))
    agent_items = [
        item
        for item in state.get("agents", [])
        if isinstance(item, dict)
    ]
    if agent_items:
        running = [item for item in agent_items if item.get("status") == "running"]
        recent = [item for item in agent_items if item.get("status") != "running"][-4:]
        lines = ["## Bounded subagent coordination state"]
        for item in running + recent:
            line = (
                f"- {item.get('agent_id', 'unknown')} "
                f"[{item.get('status', 'unknown')}] type={item.get('agent_type', 'unknown')}"
            )
            if item.get("result_summary"):
                line += f": {bounded(item.get('result_summary'), 500)}"
            envelope = item.get("result_envelope")
            if isinstance(envelope, dict):
                line += f" | envelope_complete={bool(envelope.get('complete'))}"
            lines.append(line)
        sections.append("\n".join(lines))
    if state["evidence"]:
        lines = ["## Recently verified or attempted evidence"]
        for item in state["evidence"][-12:]:
            lines.append(
                f"- {item['id']} [{item['outcome']}]: {bounded(item['summary'], 500)}"
            )
        sections.append("\n".join(lines))
    human_prompts = [
        metadata
        for metadata in state["prompts"]
        if metadata.get("origin", "human") == "human"
    ]
    prompt_records = [
        read_prompt_record(session_dir, metadata)
        for metadata in (human_prompts[:1] + human_prompts[-3:])
    ]
    prompt_records = [item for item in prompt_records if item]
    if prompt_records:
        lines = ["## Original prompt excerpts and latest updates"]
        seen: set[str] = set()
        for record in prompt_records:
            if record["id"] in seen:
                continue
            seen.add(record["id"])
            lines.append(f"- {record['id']}: {bounded(record.get('text', ''), 1800)}")
        sections.append("\n".join(lines))
    sections.append(
        "## Completion rule\nDo not declare completion unless every non-superseded requirement and acceptance item passes with concrete evidence and open_items is empty."
    )
    text = redact_text("\n\n".join(sections))
    if len(text) > RECOVERY_CHAR_LIMIT:
        text = text[: RECOVERY_CHAR_LIMIT - 120] + "\n\n…[recovery packet clipped to budget]"
    return text


def write_recovery(session_dir: Path, state: dict[str, Any], trigger: str) -> str:
    packet = recovery_packet(session_dir, state)
    record = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "trigger": trigger,
        "state_hash": state["content_hash"],
        "packet_sha256": sha256_text(packet),
        "packet": packet,
    }
    atomic_write_json(session_dir / "recovery.json", record)
    atomic_write_text(session_dir / "recovery.md", packet + "\n")
    return packet


def hook_output(event: str, additional_context: str | None = None, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = dict(extra)
    if additional_context:
        result["hookSpecificOutput"] = {
            "hookEventName": event,
            "additionalContext": additional_context,
        }
    return result


def shell_join(arguments: list[str], windows: bool | None = None) -> str:
    use_windows = os.name == "nt" if windows is None else windows
    return subprocess.list2cmdline(arguments) if use_windows else shlex.join(arguments)


def begin_completion_attempt(
    state: dict[str, Any], payload: dict[str, Any], fallback_turn_id: str
) -> tuple[str, str]:
    turn_id = str(payload.get("turn_id") or fallback_turn_id)
    token = secrets.token_urlsafe(24)
    state["completion_attempt"] = {
        "turn_id": turn_id,
        "token_sha256": sha256_text(token),
        "created_at": utc_now(),
        "staged_at": None,
        "staged_checkpoint": None,
    }
    return turn_id, token


def completion_command_context(
    state: dict[str, Any], turn_id: str, token: str
) -> str:
    common = [
        "--data-dir",
        str(data_root().resolve()),
        "--session-id",
        str(state["session"]["id"]),
        "--turn-id",
        turn_id,
        f"--token={token}",
    ]
    script = str(Path(__file__).resolve())
    status_command = shell_join(
        [sys.executable, script, "checkpoint-status", *common]
    )
    stage_command = shell_join(
        [sys.executable, script, "stage-checkpoint", *common]
    )
    requirement_ids = [
        item["id"]
        for item in state["requirements"]
        if item.get("status") != "superseded"
    ]
    acceptance_ids = [
        item["id"]
        for item in state["acceptance_items"]
        if item.get("status") != "superseded"
    ]
    return (
        "Context Guard is active. Keep completion metadata private: never append "
        "a context-guard checkpoint, HTML comment, JSON block, token, or private "
        "command to the user-facing response. Before claiming full completion, "
        "inspect the private ledger with this exact command:\n"
        f"{status_command}\n"
        "Then stage a turn-bound private checkpoint with this command plus one "
        "`--requirement ID=E####[,E####]` flag for each pending requirement and "
        "one `--acceptance ID=E####[,E####]` flag for each pending acceptance item:\n"
        f"{stage_command}\n"
        "Only successful evidence IDs printed by checkpoint-status are valid. "
        "Previously passed items are carried forward automatically. "
        f"Tracked requirements: {','.join(requirement_ids) or 'none'}; "
        f"acceptance: {','.join(acceptance_ids) or 'none'}."
    )


def completion_attempt_for(
    state: dict[str, Any], turn_id: str, token: str
) -> dict[str, Any]:
    attempt = state.get("completion_attempt")
    if not isinstance(attempt, dict):
        raise RuntimeError("no active private completion attempt")
    if str(attempt.get("turn_id")) != str(turn_id):
        raise RuntimeError("completion attempt belongs to a different turn")
    expected = str(attempt.get("token_sha256") or "")
    if not expected or not hmac.compare_digest(expected, sha256_text(token)):
        raise RuntimeError("invalid private completion token")
    return attempt


def parse_evidence_assignments(
    values: list[str], label: str
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for raw in values:
        item_id, separator, evidence_text = raw.partition("=")
        item_id = item_id.strip().upper()
        if not separator or not item_id:
            raise ValueError(f"{label} must use ID=E####[,E####] syntax")
        if item_id in result:
            raise ValueError(f"duplicate {label} assignment for {item_id}")
        evidence_ids = [
            value.strip().upper()
            for value in evidence_text.split(",")
            if value.strip()
        ]
        if not evidence_ids or any(
            not EVIDENCE_ID_RE.fullmatch(value) for value in evidence_ids
        ):
            raise ValueError(f"{label} {item_id} has invalid evidence IDs")
        result[item_id] = list(dict.fromkeys(evidence_ids))
    return result


def checkpoint_status_snapshot(state: dict[str, Any], turn_id: str) -> dict[str, Any]:
    successful = [
        {
            "id": item["id"],
            "tool": item["tool"],
            "summary": bounded(item["summary"], 350),
        }
        for item in state["evidence"]
        if item.get("outcome") == "success"
    ]
    return {
        "turn_id": turn_id,
        "requirements": [
            {
                "id": item["id"],
                "status": item.get("status", "pending"),
                "text": bounded(item.get("text", ""), 350),
                "evidence": item.get("evidence", []),
            }
            for item in state["requirements"]
            if item.get("status") != "superseded"
        ],
        "acceptance": [
            {
                "id": item["id"],
                "status": item.get("status", "pending"),
                "text": bounded(item.get("text", ""), 350),
                "evidence": item.get("evidence", []),
            }
            for item in state["acceptance_items"]
            if item.get("status") != "superseded"
        ],
        "successful_evidence_count": len(successful),
        "recent_successful_evidence": successful[-30:],
    }


def private_checkpoint(
    state: dict[str, Any],
    requirement_assignments: dict[str, list[str]],
    acceptance_assignments: dict[str, list[str]],
) -> dict[str, Any]:
    checkpoint: dict[str, Any] = {
        "status": "complete",
        "requirements": {},
        "acceptance": {},
        "open_items": [],
    }
    supplied = {
        "requirements": requirement_assignments,
        "acceptance_items": acceptance_assignments,
    }
    output_keys = {
        "requirements": "requirements",
        "acceptance_items": "acceptance",
    }
    for collection in ("requirements", "acceptance_items"):
        known_ids = {
            item["id"]
            for item in state[collection]
            if item.get("status") != "superseded"
        }
        unknown = set(supplied[collection]).difference(known_ids)
        if unknown:
            raise ValueError(
                f"unknown {collection} IDs: {','.join(sorted(unknown))}"
            )
        output = checkpoint[output_keys[collection]]
        for item in state[collection]:
            if item.get("status") == "superseded":
                continue
            evidence_ids = supplied[collection].get(item["id"])
            if evidence_ids is None and item.get("status") == "pass":
                evidence_ids = list(item.get("evidence", []))
            if evidence_ids is not None:
                output[item["id"]] = {
                    "status": "pass",
                    "evidence": evidence_ids,
                }
    return checkpoint


def checkpoint_status(
    root: Path, session_id: str, turn_id: str, token: str
) -> dict[str, Any]:
    session_dir = root / "sessions" / safe_session_id(session_id)
    state = load_state(session_dir, {"session_id": session_id})
    require_usable_state(state)
    completion_attempt_for(state, turn_id, token)
    return checkpoint_status_snapshot(state, turn_id)


def validate_checkpoint_request(
    root: Path,
    session_id: str,
    turn_id: str,
    token: str,
    requirement_values: list[str],
    acceptance_values: list[str],
) -> str:
    session_dir = root / "sessions" / safe_session_id(session_id)
    state = load_state(session_dir, {"session_id": session_id})
    require_usable_state(state)
    completion_attempt_for(state, turn_id, token)
    requirements = parse_evidence_assignments(
        requirement_values, "requirement"
    )
    acceptance = parse_evidence_assignments(
        acceptance_values, "acceptance"
    )
    checkpoint = private_checkpoint(state, requirements, acceptance)
    issues = checkpoint_issues(state, checkpoint)
    if issues:
        raise ValueError("; ".join(issues))
    return sha256_text(canonical_json(checkpoint))


def stage_private_checkpoint(
    root: Path,
    session_id: str,
    turn_id: str,
    token: str,
    requirement_values: list[str],
    acceptance_values: list[str],
) -> dict[str, Any]:
    session_dir = root / "sessions" / safe_session_id(session_id)
    with session_lock(session_dir):
        state = load_state(session_dir, {"session_id": session_id})
        require_usable_state(state)
        attempt = completion_attempt_for(state, turn_id, token)
        requirements = parse_evidence_assignments(
            requirement_values, "requirement"
        )
        acceptance = parse_evidence_assignments(
            acceptance_values, "acceptance"
        )
        checkpoint = private_checkpoint(state, requirements, acceptance)
        issues = checkpoint_issues(state, checkpoint)
        if issues:
            raise ValueError("; ".join(issues))
        attempt["staged_checkpoint"] = checkpoint
        attempt["staged_at"] = utc_now()
        receipt = {
            "turn_id": turn_id,
            "checkpoint_sha256": sha256_text(canonical_json(checkpoint)),
        }
        save_state(session_dir, state)
        return receipt


def handle_user_prompt(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    text = prompt_text(payload)
    origin, authority, actor_id = classify_prompt_origin(state, payload, text)
    prompt = append_prompt(
        session_dir,
        state,
        text,
        int(payload.get("_context_guard_unicode_repairs") or 0),
        origin=origin,
        authority=authority,
        actor_id=actor_id,
    )
    if origin == "subagent_delegation":
        save_state(session_dir, state)
        return {}
    action, argument = control_action(text)
    context: str | None = None
    export_requested = False
    if action == "on":
        state["mode"]["active"] = True
        state["mode"]["manual_off"] = False
        state["mode"]["activation_reasons"] = list(
            dict.fromkeys(state["mode"]["activation_reasons"] + ["explicit"])
        )
        context = status_context(state)
    elif action == "off":
        state["mode"]["active"] = False
        state["mode"]["manual_off"] = True
        state["completion_attempt"] = None
        context = "Context Guard full protection disabled; immutable prompt journaling remains active."
    elif action == "status":
        context = status_context(state)
    elif action == "export":
        export_requested = True
    elif action == "rollover":
        export_requested = False
    if not is_control_prompt(text):
        state["continuation_attempts"] = 0
        requirement_id = append_requirement(state, prompt, text)
        acceptance_count = len(state["acceptance_items"])
        append_acceptance(state, prompt["id"], text)
        new_acceptance_ids = [
            item["id"] for item in state["acceptance_items"][acceptance_count:]
        ]
        record_supersession(state, text, requirement_id)
        score, reasons = score_complexity(text)
        goal_requested = bool(
            re.search(r"^\s*/goal\b", text, re.I | re.MULTILINE)
            or payload.get("goal_id")
            or payload.get("goal")
        )
        if goal_requested:
            reasons.append("goal")
        state["mode"]["complexity_score"] = max(state["mode"]["complexity_score"], score)
        state["mode"]["activation_reasons"] = list(
            dict.fromkeys(state["mode"]["activation_reasons"] + reasons)
        )
        if not state["mode"]["manual_off"] and (
            score >= 4
            or "$context-guard" in text.lower()
            or goal_requested
            or len(state["acceptance_items"]) >= 2
            or len(state["requirements"]) >= 3
        ):
            state["mode"]["active"] = True
        if state["mode"]["active"]:
            acceptance_note = (
                ", ".join(new_acceptance_ids) if new_acceptance_ids else "none"
            )
            context = (
                f"Context Guard is active. This turn added requirement {requirement_id} "
                f"and acceptance IDs {acceptance_note}. Preserve these IDs."
            )
    needs_private_completion = (
        state["mode"]["active"]
        and not state["mode"]["manual_off"]
        and state.get("integrity", {}).get("status") != "failed"
        and action not in {"on", "off", "status", "export", "rollover"}
    )
    if needs_private_completion:
        turn_id, token = begin_completion_attempt(state, payload, prompt["id"])
        private_context = completion_command_context(state, turn_id, token)
        context = f"{context}\n\n{private_context}" if context else private_context
    save_state(session_dir, state)
    if export_requested:
        require_usable_state(state)
        path = export_handoff(session_dir, state, argument)
        context = f"Context Guard exported a redacted handoff to {path}."
    elif action == "rollover":
        require_usable_state(state)
        pack = export_successor_pack(session_dir, state, argument)
        context = (
            "Context Guard exported a bounded successor pack to "
            f"{pack}. It did not create, activate, retire, or authorize any task."
        )
    elif state.get("integrity", {}).get("status") == "failed":
        context = (
            "Context Guard detected unrecoverable private-state corruption. "
            "Prompt journaling continues, but compaction and completion remain "
            "blocked until the private ledger is repaired or protection is "
            "explicitly disabled."
        )
    return hook_output("UserPromptSubmit", context)


def response_text_values(value: Any, *, depth: int = 0) -> list[str]:
    if depth >= 6:
        return []
    if isinstance(value, str):
        if DATA_URL_RE.match(value):
            return []
        return [value[:12000]]
    if isinstance(value, dict):
        values: list[str] = []
        for item in list(value.values())[:64]:
            values.extend(response_text_values(item, depth=depth + 1))
            if sum(len(text) for text in values) >= 24000:
                break
        return values
    if isinstance(value, (list, tuple)):
        values = []
        for item in list(value)[:64]:
            values.extend(response_text_values(item, depth=depth + 1))
            if sum(len(text) for text in values) >= 24000:
                break
        return values
    return []


def normalized_exit_code(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value.strip()):
        return int(value)
    return None


def tool_outcome_details(payload: dict[str, Any]) -> tuple[str, str]:
    response = payload.get("tool_response")
    if isinstance(response, dict):
        if (
            response.get("is_error") is True
            or response.get("isError") is True
            or bool(response.get("error"))
            or response.get("success") is False
        ):
            return "failed", "structured_error"
        raw_exit_code = response.get("exit_code", response.get("exitCode"))
        exit_code = normalized_exit_code(raw_exit_code)
        if raw_exit_code is not None and exit_code is None:
            return "failed", "invalid_exit_code"
        if exit_code is not None:
            return (
                ("success", "structured_exit_code")
                if exit_code == 0
                else ("failed", "structured_exit_code")
            )
        if (
            response.get("is_error") is False
            or response.get("isError") is False
            or response.get("success") is True
        ):
            return "success", "structured_status"
    diagnostic = "\n".join(response_text_values(response))
    if AUTHORITATIVE_SUCCESS_TOOL_RESPONSE_RE.search(diagnostic):
        return "success", "authoritative_success_marker"
    if FAILED_TOOL_RESPONSE_RE.search(diagnostic):
        return "failed", "failure_marker"
    if WEAK_SUCCESS_TOOL_RESPONSE_RE.search(diagnostic):
        return "unknown", "weak_success_marker"
    return "unknown", "unstructured_text"


def tool_outcome(payload: dict[str, Any]) -> str:
    return tool_outcome_details(payload)[0]


def tool_response_text(payload: dict[str, Any]) -> str:
    response = payload.get("tool_response")
    if isinstance(response, str):
        return response
    try:
        return json.dumps(response, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return repr(response)


def tool_is_update_plan(tool_name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", tool_name.lower()).strip("_")
    return normalized == "update_plan" or normalized.endswith("_update_plan")


def capture_plan_snapshot(
    state: dict[str, Any], payload: dict[str, Any], outcome: str
) -> None:
    if outcome != "success" or not tool_is_update_plan(
        str(payload.get("tool_name") or "")
    ):
        return
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("plan"), list):
        return
    steps: list[dict[str, str]] = []
    for raw_item in tool_input["plan"][:PLAN_STEP_LIMIT]:
        if not isinstance(raw_item, dict):
            continue
        step = bounded(raw_item.get("step", ""), 500).strip()
        status = str(raw_item.get("status") or "pending")
        if not step or status not in {"pending", "in_progress", "completed"}:
            continue
        steps.append({"step": step, "status": status})
    if not steps:
        return
    explanation = tool_input.get("explanation")
    snapshot: dict[str, Any] = {
        "source": "update_plan",
        "updated_at": utc_now(),
        "turn_id": str(payload.get("turn_id") or ""),
        "tool_use_id": str(payload.get("tool_use_id") or ""),
        "steps": steps,
    }
    if isinstance(explanation, str) and explanation.strip():
        snapshot["explanation"] = bounded(explanation, 800)
    snapshot["sha256"] = sha256_text(canonical_json(snapshot))
    state.setdefault("work_state", {})["plan_snapshot"] = snapshot


def parse_stage_request_from_tool(
    state: dict[str, Any], payload: dict[str, Any]
) -> tuple[str, str, list[str], list[str]] | None:
    if STAGE_REQUEST_MARKER not in tool_response_text(payload):
        return None
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        raise ValueError("private stage request must come from a shell command")
    try:
        tokens = shlex.split(command, posix=os.name != "nt")
    except ValueError as exc:
        raise ValueError(f"invalid private stage command: {exc}") from exc
    indices = [
        index
        for index, token in enumerate(tokens)
        if token == "stage-checkpoint"
        and index >= 1
        and Path(tokens[index - 1].strip("'\"")).name == "context_guard.py"
    ]
    if not indices:
        return None
    if len(indices) != 1:
        raise ValueError("private stage request command is ambiguous")
    index = indices[0]
    option_values: dict[str, list[str]] = {
        "--data-dir": [],
        "--session-id": [],
        "--turn-id": [],
        "--token": [],
        "--requirement": [],
        "--acceptance": [],
    }
    remainder = tokens[index + 1 :]
    position = 0
    while position < len(remainder):
        raw_option = remainder[position]
        if raw_option.startswith("--") and "=" in raw_option:
            option, value = raw_option.split("=", 1)
            position += 1
        else:
            option = raw_option
            if option not in option_values or position + 1 >= len(remainder):
                raise ValueError(f"invalid private stage option {option!r}")
            value = remainder[position + 1]
            position += 2
        if option not in option_values or not value:
            raise ValueError(f"invalid private stage option {raw_option!r}")
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]
        option_values[option].append(value)
    for option in ("--data-dir", "--session-id", "--turn-id", "--token"):
        if len(option_values[option]) != 1:
            raise ValueError(f"private stage request requires exactly one {option}")
    expected_root = data_root().expanduser().resolve()
    requested_root = Path(option_values["--data-dir"][0]).expanduser().resolve()
    if requested_root != expected_root:
        raise ValueError("private stage request targets a different data directory")
    session_id = option_values["--session-id"][0]
    if session_id != str(state["session"]["id"]):
        raise ValueError("private stage request targets a different session")
    turn_id = option_values["--turn-id"][0]
    if turn_id != str(payload.get("turn_id") or ""):
        raise ValueError("private stage request targets a different turn")
    return (
        turn_id,
        option_values["--token"][0],
        option_values["--requirement"],
        option_values["--acceptance"],
    )


def handle_post_tool(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    if state["mode"]["active"]:
        require_usable_state(state)
        tool_name = str(payload.get("tool_name") or "unknown-tool")
        outcome, outcome_basis = tool_outcome_details(payload)
        tool_input = bounded_evidence(payload.get("tool_input"), 700)
        tool_response = bounded_evidence(payload.get("tool_response"), 900)
        evidence_origin, evidence_actor_id = tool_actor(state, payload)
        state["evidence_sequence"] += 1
        evidence = {
            "id": f"E{state['evidence_sequence']:04d}",
            "created_at": utc_now(),
            "tool": tool_name,
            "origin": evidence_origin,
            "actor_id": evidence_actor_id,
            "outcome": outcome,
            "outcome_basis": outcome_basis,
            "summary": f"input={tool_input}; response={tool_response}",
            "unicode_repairs": int(
                payload.get("_context_guard_unicode_repairs") or 0
            ),
        }
        state["evidence"].append(evidence)
        capture_plan_snapshot(state, payload, outcome)
        trim_evidence(state)
        try:
            stage_request = parse_stage_request_from_tool(state, payload)
            if stage_request is not None:
                turn_id, token, requirement_values, acceptance_values = stage_request
                attempt = completion_attempt_for(state, turn_id, token)
                requirements = parse_evidence_assignments(
                    requirement_values, "requirement"
                )
                acceptance = parse_evidence_assignments(
                    acceptance_values, "acceptance"
                )
                checkpoint = private_checkpoint(state, requirements, acceptance)
                issues = checkpoint_issues(state, checkpoint)
                if issues:
                    raise ValueError("; ".join(issues))
                attempt["staged_checkpoint"] = checkpoint
                attempt["staged_at"] = utc_now()
                save_state(session_dir, state)
                return hook_output(
                    "PostToolUse",
                    "Context Guard privately staged the turn-bound completion "
                    "checkpoint. Send a normal user-facing response without "
                    "checkpoint metadata.",
                )
        except (OSError, RuntimeError, ValueError) as exc:
            save_state(session_dir, state)
            return {
                "decision": "block",
                "reason": (
                    f"{INTERNAL_CONTINUATION_PREFIX} Private checkpoint staging "
                    f"failed: {bounded(exc, 800)}"
                ),
            }
        save_state(session_dir, state)
    return {}


def handle_pre_compact(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    if state["mode"]["manual_off"]:
        return {"continue": True}
    require_usable_state(state)
    state["mode"]["active"] = True
    state["mode"]["activation_reasons"] = list(
        dict.fromkeys(state["mode"]["activation_reasons"] + ["first_compaction"])
    )
    state["compactions"].append(
        {
            "created_at": utc_now(),
            "trigger": payload.get("trigger") or payload.get("source") or "unknown",
        }
    )
    save_state(session_dir, state)
    write_recovery(session_dir, state, "PreCompact")
    return {"continue": True}


def handle_session_start(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    source = str(payload.get("source") or "")
    if source not in {"compact", "resume"} or not state["mode"]["active"]:
        return {}
    require_usable_state(state)
    existing_attempt = state.get("completion_attempt")
    transcript_turn_id = latest_transcript_turn_id(state, payload)
    fallback_turn_id = transcript_turn_id
    if fallback_turn_id is None and isinstance(existing_attempt, dict):
        existing_turn_id = existing_attempt.get("turn_id")
        if existing_turn_id:
            fallback_turn_id = str(existing_turn_id)
    if fallback_turn_id is None:
        fallback_turn_id = f"{source}-{len(state['prompts'])}"
    turn_id, token = begin_completion_attempt(state, payload, fallback_turn_id)
    save_state(session_dir, state)
    packet = write_recovery(session_dir, state, f"SessionStart:{source}")
    private_context = completion_command_context(state, turn_id, token)
    combined = f"{packet}\n\n{private_context}"
    if len(combined) > RECOVERY_CHAR_LIMIT:
        packet_budget = max(0, RECOVERY_CHAR_LIMIT - len(private_context) - 80)
        combined = (
            packet[:packet_budget]
            + "\n\n…[recovery packet clipped to preserve private completion commands]\n\n"
            + private_context
        )
    return hook_output("SessionStart", combined)


def handle_subagent_start(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    if state["mode"]["active"]:
        require_usable_state(state)
    agent_id = str(
        payload.get("agent_id")
        or f"unknown-agent-{payload.get('turn_id') or len(state.get('agents', [])) + 1}"
    )
    record = agent_record(state, agent_id)
    if record is None:
        record = {"agent_id": agent_id}
        state.setdefault("agents", []).append(record)
    record.update(
        {
            "agent_type": str(payload.get("agent_type") or "unknown"),
            "status": "running",
            "started_at": utc_now(),
            "stopped_at": None,
            "start_turn_id": str(payload.get("turn_id") or ""),
            "permission_mode": str(payload.get("permission_mode") or ""),
            "authority": "delegated",
            "requirement_ids": [
                item["id"]
                for item in state.get("requirements", [])
                if item.get("status") != "superseded"
            ],
            "acceptance_ids": [
                item["id"]
                for item in state.get("acceptance_items", [])
                if item.get("status") != "superseded"
            ],
        }
    )
    trim_agent_records(state)
    save_state(session_dir, state)
    if state["mode"]["active"]:
        return hook_output("SubagentStart", subagent_contract_context(state))
    return {}


def handle_subagent_stop(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    if state["mode"]["active"]:
        require_usable_state(state)
    agent_id = str(
        payload.get("agent_id")
        or f"unknown-agent-{payload.get('turn_id') or len(state.get('agents', [])) + 1}"
    )
    record = agent_record(state, agent_id)
    if record is None:
        record = {
            "agent_id": agent_id,
            "started_at": None,
            "start_turn_id": "",
            "authority": "delegated",
            "requirement_ids": [],
            "acceptance_ids": [],
        }
        state.setdefault("agents", []).append(record)
    message = str(payload.get("last_assistant_message") or "")
    safe_message = private_metadata_free_text(message)
    record.update(
        {
            "agent_type": str(
                payload.get("agent_type") or record.get("agent_type") or "unknown"
            ),
            "status": "stopped",
            "stopped_at": utc_now(),
            "stop_turn_id": str(payload.get("turn_id") or ""),
            "result_summary": bounded_evidence(safe_message, 1800),
            "result_sha256": sha256_text(message),
            "result_envelope": agent_result_envelope(safe_message),
            "transcript_available": bool(payload.get("agent_transcript_path")),
        }
    )
    trim_agent_records(state)
    save_state(session_dir, state)
    return {}


def checkpoint_issues(
    state: dict[str, Any], checkpoint: dict[str, Any]
) -> list[str]:
    issues: list[str] = []
    top_status = checkpoint.get("status")
    if top_status != "complete":
        issues.append(f"top-level status must be complete, got {top_status!r}")
    evidence_by_id = {
        item["id"]: item
        for item in state["evidence"]
        if isinstance(item.get("id"), str)
    }
    for collection, key in (
        ("requirements", "requirements"),
        ("acceptance_items", "acceptance"),
    ):
        reported = checkpoint.get(key)
        if not isinstance(reported, dict):
            issues.append(f"missing {key} status map")
            continue
        expected_ids = {
            item["id"]
            for item in state[collection]
            if item.get("status") != "superseded"
        }
        unknown_ids = set(reported).difference(expected_ids)
        if unknown_ids:
            issues.append(
                f"unknown {key} IDs: {','.join(sorted(unknown_ids))}"
            )
        for item in state[collection]:
            item_id = item["id"]
            if item.get("status") == "superseded":
                continue
            value = reported.get(item_id)
            if not isinstance(value, dict):
                issues.append(f"{item_id} is missing")
                continue
            status = value.get("status")
            if status != "pass":
                issues.append(f"{item_id} is {status}")
                continue
            evidence_ids = value.get("evidence")
            if not isinstance(evidence_ids, list) or not evidence_ids:
                issues.append(f"{item_id} passes without evidence")
                continue
            for evidence_id in evidence_ids:
                if (
                    not isinstance(evidence_id, str)
                    or not EVIDENCE_ID_RE.fullmatch(evidence_id)
                ):
                    issues.append(
                        f"{item_id} has invalid evidence reference {evidence_id!r}"
                    )
                    continue
                evidence = evidence_by_id.get(evidence_id)
                if evidence is None:
                    issues.append(
                        f"{item_id} references unknown evidence {evidence_id}"
                    )
                elif evidence.get("outcome") != "success":
                    issues.append(
                        f"{item_id} references non-success evidence {evidence_id} "
                        f"(outcome={evidence.get('outcome') or 'unknown'})"
                    )
    open_items = checkpoint.get("open_items")
    if not isinstance(open_items, list):
        issues.append("open_items must be a list")
    elif open_items:
        issues.append("open_items is not empty: " + ", ".join(map(str, open_items[:12])))
    return issues


def apply_checkpoint(
    state: dict[str, Any], checkpoint: dict[str, Any], turn_id: str
) -> None:
    for collection, key in (
        ("requirements", "requirements"),
        ("acceptance_items", "acceptance"),
    ):
        reported = checkpoint.get(key, {})
        if not isinstance(reported, dict):
            continue
        for item in state[collection]:
            value = reported.get(item["id"])
            if not isinstance(value, dict):
                continue
            item["status"] = "pass"
            item["evidence"] = list(value.get("evidence", []))
    open_items = checkpoint.get("open_items")
    state["open_items"] = [bounded(item, 500) for item in open_items] if isinstance(open_items, list) else []
    state["completion_checkpoint"] = {
        "created_at": utc_now(),
        "turn_id": turn_id,
        "status": "complete",
        "sha256": sha256_text(canonical_json(checkpoint)),
    }
    state["completion_attempt"] = None


def handle_stop(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    if not state["mode"]["active"] or state["mode"]["manual_off"]:
        return {}
    try:
        require_usable_state(state)
    except StateIntegrityError:
        return {
            "continue": False,
            "stopReason": (
                "Context Guard stopped completion because private task state "
                "could not be reconstructed safely."
            ),
            "systemMessage": (
                "Context Guard private-state integrity failed. Review the "
                "preserved corrupt state and immutable prompt ledger."
            ),
        }
    text = assistant_text(payload)
    if NON_COMPLETION_RE.search(text):
        attempt = state.get("completion_attempt")
        if isinstance(attempt, dict) and attempt.get("staged_checkpoint") is not None:
            attempt["staged_checkpoint"] = None
            attempt["staged_at"] = None
            save_state(session_dir, state)
        return {}
    legacy_checkpoint = CHECKPOINT_RE.search(text) is not None
    leaked_private_metadata = PRIVATE_METADATA_RE.search(text) is not None
    attempt = state.get("completion_attempt")
    turn_id = str(
        payload.get("turn_id")
        or (attempt.get("turn_id") if isinstance(attempt, dict) else "")
    )
    turn_matches = (
        isinstance(attempt, dict)
        and str(attempt.get("turn_id")) == turn_id
    )
    checkpoint = (
        attempt.get("staged_checkpoint")
        if turn_matches and isinstance(attempt, dict)
        else None
    )
    completion_claim = claims_completion(text)
    if (
        checkpoint is None
        and not completion_claim
        and not legacy_checkpoint
        and not leaked_private_metadata
    ):
        return {}
    tracked_items = any(
        item.get("status") != "superseded"
        for item in state["requirements"] + state["acceptance_items"]
    )
    if (
        checkpoint is None
        and completion_claim
        and not tracked_items
        and not state["open_items"]
        and not legacy_checkpoint
    ):
        return {}
    issues: list[str] = []
    if legacy_checkpoint:
        issues.append(
            "legacy inline checkpoint metadata is not accepted; stage it privately"
        )
    elif leaked_private_metadata:
        issues.append("user-facing reply contains private checkpoint metadata")
    if checkpoint is None:
        if not turn_matches:
            issues.append("missing turn-bound private completion attempt")
        else:
            issues.append("missing staged private checkpoint")
    elif not isinstance(checkpoint, dict):
        issues.append("invalid staged private checkpoint")
    else:
        issues.extend(checkpoint_issues(state, checkpoint))
    if not issues:
        apply_checkpoint(state, checkpoint, turn_id)
        state["continuation_attempts"] = 0
        save_state(session_dir, state)
        return {}
    concise = "; ".join(issues[:12])
    expected_ids = (
        "Expected IDs: requirements="
        + (",".join(item["id"] for item in state["requirements"]) or "none")
        + "; acceptance="
        + (",".join(item["id"] for item in state["acceptance_items"]) or "none")
        + "."
    )
    if state["continuation_attempts"] >= 2:
        save_state(session_dir, state)
        return {
            "continue": False,
            "stopReason": "Context Guard stopped an unverified completion after two correction attempts.",
            "systemMessage": (
                "Context Guard stopped an unverified completion. Review the private "
                "evidence ledger before retrying."
            )
        }
    state["continuation_attempts"] += 1
    save_state(session_dir, state)
    return {
        "decision": "block",
        "reason": (
            f"{INTERNAL_CONTINUATION_PREFIX} The task is not yet safely complete. "
            "Resolve or explicitly report these items. If claiming completion, use "
            "the private checkpoint commands injected for the continuation turn; do "
            "not put checkpoint metadata in the user-facing reply. "
            f"{concise}. {expected_ids}"
        ),
    }


def safe_export_path(state: dict[str, Any], argument: str | None) -> Path:
    cwd = Path(str(state["session"].get("cwd") or os.getcwd())).expanduser().resolve()
    if argument:
        try:
            parsed = shlex.split(argument, posix=os.name != "nt")
        except ValueError as exc:
            raise ValueError(f"invalid export path: {exc}") from exc
        if len(parsed) != 1:
            raise ValueError("export accepts exactly one path")
        parsed_path = parsed[0]
        if (
            len(parsed_path) >= 2
            and parsed_path[0] == parsed_path[-1]
            and parsed_path[0] in {"'", '"'}
        ):
            parsed_path = parsed_path[1:-1]
        candidate = Path(parsed_path).expanduser()
        candidate = candidate if candidate.is_absolute() else cwd / candidate
    else:
        candidate = cwd / ".codex" / "context-guard" / "CONTEXT_HANDOFF.md"
    resolved = candidate.resolve()
    try:
        resolved.relative_to(cwd)
    except ValueError as exc:
        raise ValueError("export path must stay inside the current project") from exc
    return resolved


def project_root_from_state(state: dict[str, Any]) -> Path:
    root = Path(str(state["session"].get("cwd") or os.getcwd())).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("current project root is not an existing directory")
    return root


def parse_single_path_argument(argument: str | None, label: str) -> str | None:
    if not argument:
        return None
    try:
        parsed = shlex.split(argument, posix=os.name != "nt")
    except ValueError as exc:
        raise ValueError(f"invalid {label} path: {exc}") from exc
    if len(parsed) != 1:
        raise ValueError(f"{label} accepts exactly one path")
    value = parsed[0]
    if (
        len(value) >= 2
        and value[0] == value[-1]
        and value[0] in {"'", '"'}
    ):
        value = value[1:-1]
    return value


def inspect_regular_file(
    path: Path, expected_size: int, *, count_lines: bool = False
) -> tuple[str, int | None]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    digest = hashlib.sha256()
    descriptor = os.open(str(path), flags)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
            raise ValueError("declared successor file changed before hashing")
        bytes_read = 0
        newline_count = 0
        last = b""
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            bytes_read += len(chunk)
            if count_lines:
                newline_count += chunk.count(b"\n")
                last = chunk[-1:]
        if bytes_read != expected_size or os.fstat(handle.fileno()).st_size != expected_size:
            raise ValueError("declared successor file changed while hashing")
    line_count = (
        newline_count + (1 if last and last != b"\n" else 0)
        if count_lines
        else None
    )
    return digest.hexdigest(), line_count


def read_bounded_regular_file(path: Path, limit: int, label: str) -> bytes:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"{label} must be a regular file")
            if info.st_size > limit:
                raise ValueError(f"{label} exceeds its byte limit")
            raw = handle.read(limit + 1)
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"cannot read {label}: {exc}") from exc
    if len(raw) > limit:
        raise ValueError(f"{label} exceeds its byte limit")
    return raw


def successor_project_file(root: Path, raw_path: Any, label: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError(f"{label}.path must be a non-empty project-relative path")
    lexical = Path(raw_path)
    if lexical.is_absolute():
        raise ValueError(f"{label}.path must be project-relative")
    candidate = root / lexical
    if candidate.is_symlink():
        raise ValueError(f"{label}.path must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"{label}.path must stay inside the current project") from exc
    if not resolved.is_file():
        raise ValueError(f"{label}.path must identify a regular file")
    return resolved


def bounded_single_line(value: Any, label: str, limit: int = 1200) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\n" in value
        or "\r" in value
        or len(value) > limit
    ):
        raise ValueError(f"{label} must be non-empty bounded single-line text")
    return redact_text(value.strip())


def validate_authorization_index(
    value: Any, state: dict[str, Any]
) -> dict[str, list[dict[str, Any]]]:
    categories = {"granted", "consumed", "pending", "forbidden"}
    if not isinstance(value, dict) or set(value) != categories:
        raise ValueError(
            "authorization must contain exactly granted, consumed, pending, and forbidden"
        )
    requirement_ids = {
        item["id"]
        for item in state["requirements"] + state["acceptance_items"]
        if item.get("status") != "superseded"
    }
    evidence_ids = {
        item["id"]
        for item in state["evidence"]
        if isinstance(item.get("id"), str) and item.get("outcome") == "success"
    }
    normalized: dict[str, list[dict[str, Any]]] = {}
    for category in sorted(categories):
        items = value.get(category)
        if not isinstance(items, list) or len(items) > 40:
            raise ValueError(f"authorization.{category} must be a bounded list")
        normalized_items: list[dict[str, Any]] = []
        for index, item in enumerate(items):
            label = f"authorization.{category}[{index}]"
            if not isinstance(item, dict) or set(item) != {"text", "source_ids"}:
                raise ValueError(f"{label} must contain exactly text and source_ids")
            text = bounded_single_line(item.get("text"), f"{label}.text", 1000)
            source_ids = item.get("source_ids")
            if (
                not isinstance(source_ids, list)
                or not source_ids
                or len(source_ids) > 20
                or any(not isinstance(source_id, str) for source_id in source_ids)
            ):
                raise ValueError(f"{label}.source_ids must be a non-empty string list")
            allowed = requirement_ids | evidence_ids
            unknown = sorted(set(source_ids) - allowed)
            if unknown:
                raise ValueError(
                    f"{label}.source_ids contains unknown IDs: {', '.join(unknown)}"
                )
            if category != "consumed" and not set(source_ids).issubset(requirement_ids):
                raise ValueError(
                    f"{label} may reference only requirement or acceptance IDs"
                )
            normalized_items.append(
                {"text": text, "source_ids": list(dict.fromkeys(source_ids))}
            )
        normalized[category] = normalized_items
    return normalized


def validate_successor_artifacts(
    root: Path, data: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    current = data.get("current_step_reads")
    audit = data.get("audit_only_files")
    if not isinstance(current, list) or len(current) > MAX_SUCCESSOR_CURRENT_READS:
        raise ValueError(
            f"current_step_reads must contain at most {MAX_SUCCESSOR_CURRENT_READS} items"
        )
    if not isinstance(audit, list) or len(audit) > MAX_SUCCESSOR_AUDIT_FILES:
        raise ValueError(
            f"audit_only_files must contain at most {MAX_SUCCESSOR_AUDIT_FILES} items"
        )
    normalized_current: list[dict[str, Any]] = []
    normalized_audit: list[dict[str, Any]] = []
    seen: set[Path] = set()
    full_bytes = 0
    targeted_lines = 0
    current_hash_bytes = 0
    audit_bytes = 0
    for index, item in enumerate(current):
        label = f"current_step_reads[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{label} must be an object")
        mode = item.get("read_mode")
        keys = {"path", "purpose", "read_mode"}
        if mode == "lines":
            keys.add("line_ranges")
        if set(item) != keys or mode not in {"full", "lines"}:
            raise ValueError(f"{label} has invalid keys or read_mode")
        path = successor_project_file(root, item.get("path"), label)
        if path in seen:
            raise ValueError(f"{label}.path duplicates another declared file")
        seen.add(path)
        size = path.stat().st_size
        if current_hash_bytes + size > MAX_SUCCESSOR_HASH_BYTES:
            raise ValueError("current-step hash byte budget exceeded")
        if mode == "full" and full_bytes + size > MAX_SUCCESSOR_FULL_READ_BYTES:
            raise ValueError("current full-read byte budget exceeded")
        digest, maximum_line = inspect_regular_file(
            path, size, count_lines=mode == "lines"
        )
        current_hash_bytes += size
        normalized = {
            "path": path.relative_to(root).as_posix(),
            "purpose": bounded_single_line(item.get("purpose"), f"{label}.purpose", 1000),
            "read_mode": mode,
            "size": size,
            "sha256": digest,
        }
        if mode == "full":
            full_bytes += size
        else:
            ranges = item.get("line_ranges")
            if not isinstance(ranges, list) or not ranges:
                raise ValueError(f"{label}.line_ranges must be non-empty")
            normalized_ranges: list[list[int]] = []
            previous_end = 0
            assert maximum_line is not None
            for range_index, line_range in enumerate(ranges):
                range_label = f"{label}.line_ranges[{range_index}]"
                if (
                    not isinstance(line_range, list)
                    or len(line_range) != 2
                    or any(
                        isinstance(number, bool) or not isinstance(number, int)
                        for number in line_range
                    )
                    or line_range[0] < 1
                    or line_range[1] < line_range[0]
                    or line_range[0] <= previous_end
                    or line_range[1] > maximum_line
                ):
                    raise ValueError(
                        f"{range_label} must be sorted, non-overlapping, and inside the file"
                    )
                previous_end = line_range[1]
                selected_lines = line_range[1] - line_range[0] + 1
                if targeted_lines + selected_lines > MAX_SUCCESSOR_TARGETED_LINES:
                    raise ValueError("current targeted-line budget exceeded")
                targeted_lines += selected_lines
                normalized_ranges.append(line_range)
            normalized["line_ranges"] = normalized_ranges
        normalized_current.append(normalized)
    for index, item in enumerate(audit):
        label = f"audit_only_files[{index}]"
        if not isinstance(item, dict) or set(item) != {"path", "purpose"}:
            raise ValueError(f"{label} must contain exactly path and purpose")
        path = successor_project_file(root, item.get("path"), label)
        if path in seen:
            raise ValueError(f"{label}.path duplicates another declared file")
        seen.add(path)
        size = path.stat().st_size
        if audit_bytes + size > MAX_SUCCESSOR_AUDIT_BYTES:
            raise ValueError("audit-only hash byte budget exceeded")
        digest, _ = inspect_regular_file(path, size)
        audit_bytes += size
        normalized_audit.append(
            {
                "path": path.relative_to(root).as_posix(),
                "purpose": bounded_single_line(
                    item.get("purpose"), f"{label}.purpose", 1000
                ),
                "size": size,
                "sha256": digest,
            }
        )
    return (
        normalized_current,
        normalized_audit,
        {
            "full_read_bytes": full_bytes,
            "targeted_lines": targeted_lines,
            "current_hash_bytes": current_hash_bytes,
            "audit_hash_bytes": audit_bytes,
        },
    )


def load_successor_input(
    root: Path, state: dict[str, Any]
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    input_path = root / ".codex" / "context-guard" / SUCCESSOR_INPUT_FILENAME
    if not input_path.exists():
        raise ValueError(
            f"missing successor input {input_path}; prepare it before requesting rollover"
        )
    if input_path.is_symlink():
        raise ValueError(f"invalid successor input {input_path}: must not be a symlink")
    try:
        resolved_input = input_path.resolve(strict=True)
        resolved_input.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(
            f"invalid successor input {input_path}: must stay inside the current project"
        ) from exc
    try:
        raw = read_bounded_regular_file(
            resolved_input, MAX_SUCCESSOR_INPUT_BYTES, "successor input"
        )
    except ValueError as exc:
        raise ValueError(
            f"invalid successor input {input_path}: {exc}"
        ) from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"successor input is invalid UTF-8 JSON: {exc}") from exc
    expected = {
        "schema_version",
        "current_status",
        "exact_next_action",
        "authorization",
        "current_step_reads",
        "audit_only_files",
    }
    if not isinstance(data, dict) or set(data) != expected:
        raise ValueError(f"successor input must contain exactly {sorted(expected)}")
    if data.get("schema_version") != 1:
        raise ValueError("successor input schema_version must be 1")
    normalized = {
        "schema_version": 1,
        "current_status": bounded_single_line(
            data.get("current_status"), "current_status", 1200
        ),
        "exact_next_action": bounded_single_line(
            data.get("exact_next_action"), "exact_next_action", 1200
        ),
        "authorization": validate_authorization_index(
            data.get("authorization"), state
        ),
    }
    current, audit, budgets = validate_successor_artifacts(root, data)
    normalized["current_step_reads"] = current
    normalized["audit_only_files"] = audit
    normalized["budgets"] = budgets
    return input_path, normalized, {"sha256": hashlib.sha256(raw).hexdigest()}


def successor_output_dir(
    root: Path, state: dict[str, Any], argument: str | None
) -> Path:
    parsed = parse_single_path_argument(argument, "rollover")
    if parsed is None:
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        candidate = (
            root
            / ".codex"
            / "context-guard"
            / "successor-packs"
            / f"{stamp}-{state['content_hash'][:8]}"
        )
    else:
        raw = Path(parsed).expanduser()
        candidate = raw if raw.is_absolute() else root / raw
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("rollover output must stay inside the current project") from exc
    if resolved.exists():
        raise ValueError("rollover output directory already exists; refusing to overwrite")
    return resolved


def successor_handoff_text(
    state: dict[str, Any], normalized: dict[str, Any]
) -> str:
    lines = [
        "# Context Guard Successor Handoff",
        "",
        f"- Generated: {utc_now()}",
        f"- Source state SHA-256: `{state['content_hash']}`",
        f"- Current status: {normalized['current_status']}",
        f"- Exact next action: {normalized['exact_next_action']}",
        "- Authority rule: this pack grants no new permission; original user requirements remain authoritative.",
        "",
        "## Requirements and acceptance",
        "",
    ]
    for collection in ("requirements", "acceptance_items"):
        for item in state[collection]:
            if item.get("status") == "superseded":
                continue
            lines.append(
                f"- {item['id']} [{item.get('status', 'pending')}]: "
                f"{redact_text(bounded(item.get('text', ''), 700))}"
            )
    lines.extend(["", "## Authorization index", ""])
    for category in ("granted", "consumed", "pending", "forbidden"):
        lines.append(f"### {category.title()}")
        entries = normalized["authorization"][category]
        if not entries:
            lines.append("- None recorded.")
        for entry in entries:
            lines.append(
                f"- {entry['text']} (sources: {', '.join(entry['source_ids'])})"
            )
        lines.append("")
    lines.extend(["## Selective read plan", ""])
    if not normalized["current_step_reads"]:
        lines.append("- No current-step body reads declared.")
    for item in normalized["current_step_reads"]:
        suffix = (
            f" lines={item['line_ranges']}"
            if item["read_mode"] == "lines"
            else ""
        )
        lines.append(
            f"- `{item['path']}` mode={item['read_mode']}{suffix}; "
            f"purpose={item['purpose']}; SHA-256 `{item['sha256']}`"
        )
    lines.extend(["", "## Hash-only historical evidence", ""])
    if not normalized["audit_only_files"]:
        lines.append("- None declared.")
    for item in normalized["audit_only_files"]:
        lines.append(
            f"- `{item['path']}`; purpose={item['purpose']}; "
            f"SHA-256 `{item['sha256']}`"
        )
    lines.extend(
        [
            "",
            "The successor must verify the manifest and declared file hashes before substantive work.",
            "Audit-only file bodies remain unread unless the user explicitly requests a full audit or an integrity mismatch requires it.",
            "",
        ]
    )
    return redact_text("\n".join(lines))


def export_successor_pack(
    session_dir: Path, state: dict[str, Any], argument: str | None = None
) -> Path:
    del session_dir
    require_usable_state(state)
    root = project_root_from_state(state)
    input_path, normalized, input_receipt = load_successor_input(root, state)
    output = successor_output_dir(root, state, argument)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=".context-guard-pack.", dir=output.parent)
    )
    try:
        handoff_text = successor_handoff_text(state, normalized)
        handoff_path = temporary / SUCCESSOR_HANDOFF_FILENAME
        atomic_write_text(handoff_path, handoff_text)
        manifest = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "project_root": ".",
            "source_session_id_sha256": sha256_text(str(state["session"]["id"])),
            "source_state_sha256": state["content_hash"],
            "input": {
                "path": input_path.relative_to(root).as_posix(),
                "sha256": input_receipt["sha256"],
            },
            "authority": {
                "grants_new_authority": False,
                "index_is_declarative_only": True,
                "requirements_remain_authoritative": True,
            },
            "current_status": normalized["current_status"],
            "exact_next_action": normalized["exact_next_action"],
            "requirements": [
                {
                    "id": item["id"],
                    "status": item.get("status", "pending"),
                    "text": redact_text(bounded(item.get("text", ""), 700)),
                    "source_prompt_sha256": item.get("sha256"),
                }
                for item in state["requirements"]
                if item.get("status") != "superseded"
            ],
            "acceptance": [
                {
                    "id": item["id"],
                    "status": item.get("status", "pending"),
                    "text": redact_text(bounded(item.get("text", ""), 700)),
                    "evidence": item.get("evidence", []),
                }
                for item in state["acceptance_items"]
                if item.get("status") != "superseded"
            ],
            "open_items": open_item_ids(state),
            "compaction_count": len(state["compactions"]),
            "authorization": normalized["authorization"],
            "read_policy": {
                "mode": "selective",
                "audit_only_bodies_default": False,
            },
            "current_step_reads": normalized["current_step_reads"],
            "audit_only_files": normalized["audit_only_files"],
            "budgets": normalized["budgets"],
            "handoff": {
                "path": SUCCESSOR_HANDOFF_FILENAME,
                "sha256": sha256_text(handoff_text),
            },
        }
        atomic_write_json(temporary / SUCCESSOR_MANIFEST_FILENAME, manifest)
        os.replace(temporary, output)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return output


def export_handoff(
    session_dir: Path, state: dict[str, Any], argument: str | None = None
) -> Path:
    del session_dir
    target = safe_export_path(state, argument)
    lines = [
        "# Context Guard Handoff",
        "",
        f"- Generated: {utc_now()}",
        f"- Session state hash: `{state['content_hash']}`",
        f"- Protected: `{state['mode']['active']}`",
        "",
        "## Task boundaries",
        "",
    ]
    for item in state["requirements"]:
        lines.append(
            f"- {item['id']} [{item['status']}]: {redact_text(bounded(item['text'], 700))}"
        )
        for evidence in item.get("evidence", []):
            lines.append(f"  - Evidence: {redact_text(bounded(evidence, 500))}")
    lines.extend(["", "## Acceptance criteria", ""])
    for item in state["acceptance_items"]:
        lines.append(
            f"- {item['id']} [{item['status']}]: {redact_text(bounded(item['text'], 700))}"
        )
        for evidence in item.get("evidence", []):
            lines.append(f"  - Evidence: {redact_text(bounded(evidence, 500))}")
    lines.extend(["", "## Supersessions", ""])
    if state["supersedes"]:
        for item in state["supersedes"]:
            lines.append(f"- {item['new_id']} supersedes {item['old_id']}")
    else:
        lines.append("- None")
    lines.extend(["", "## Open items", ""])
    open_ids = open_item_ids(state)
    lines.append("- " + (", ".join(open_ids) if open_ids else "None"))
    lines.extend(["", "## Recent bounded evidence", ""])
    if state["evidence"]:
        for item in state["evidence"][-12:]:
            lines.append(
                f"- {item['id']} [{item['outcome']}]: {redact_text(bounded(item['summary'], 700))}"
            )
    else:
        lines.append("- None")
    lines.extend(
        [
            "",
            "> Raw prompts, transcripts, credentials, URL query values, and plugin-private paths are intentionally omitted.",
            "",
        ]
    )
    atomic_write_text(target, redact_text("\n".join(lines)))
    return target


def cleanup_old_sessions(root: Path, current: Path | None = None) -> int:
    sessions = root / "sessions"
    if not sessions.is_dir():
        return 0
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=RETENTION_DAYS)
    removed = 0
    for candidate in sessions.iterdir():
        if candidate.is_symlink() or not candidate.is_dir():
            continue
        if current is not None and candidate.resolve() == current.resolve():
            continue
        state_path = candidate / "state.json"
        try:
            with state_path.open("r", encoding="utf-8") as handle:
                state = json.load(handle)
            if not isinstance(state, dict):
                continue
            validate_state_integrity(state)
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            StateIntegrityError,
            TypeError,
            ValueError,
        ):
            continue
        ended = parse_time(state.get("session", {}).get("ended_at"))
        if ended is None or ended >= cutoff:
            continue
        for path in sorted(candidate.rglob("*"), reverse=True):
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
        candidate.rmdir()
        removed += 1
    return removed


def handle_session_end(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    del payload
    state["session"]["ended_at"] = utc_now()
    save_state(session_dir, state)
    if state["mode"]["active"]:
        write_recovery(session_dir, state, "SessionEnd")
    cleanup_old_sessions(data_root(), current=session_dir)
    return {}


def dispatch(payload: dict[str, Any]) -> dict[str, Any]:
    repaired_payload, unicode_repairs = repair_unicode_scalars(payload)
    if not isinstance(repaired_payload, dict):
        raise TypeError("hook payload must be an object")
    payload = repaired_payload
    if unicode_repairs:
        payload["_context_guard_unicode_repairs"] = unicode_repairs
    event = str(payload.get("hook_event_name") or payload.get("event") or "")
    session_dir = session_dir_for(payload)
    with session_lock(session_dir):
        state = load_state(session_dir, payload)
        handlers = {
            "UserPromptSubmit": handle_user_prompt,
            "PostToolUse": handle_post_tool,
            "PreCompact": handle_pre_compact,
            "SessionStart": handle_session_start,
            "SubagentStart": handle_subagent_start,
            "SubagentStop": handle_subagent_stop,
            "Stop": handle_stop,
            "SessionEnd": handle_session_end,
        }
        handler = handlers.get(event)
        if handler is None:
            return {}
        return handler(session_dir, state, payload)


def safe_dispatch(payload: dict[str, Any]) -> dict[str, Any]:
    event = str(payload.get("hook_event_name") or payload.get("event") or "")
    try:
        return dispatch(payload)
    except Exception as exc:
        message = bounded(f"{type(exc).__name__}: {exc}", 800)
        if event == "PreCompact":
            return {
                "continue": False,
                "systemMessage": f"Context Guard could not save the recovery packet: {message}",
            }
        if event == "Stop":
            return {
                "continue": False,
                "stopReason": (
                    "Context Guard stopped an unverified completion because "
                    "private validation failed."
                ),
            }
        return {"systemMessage": f"Context Guard {event or 'hook'} warning: {message}"}


def command_hook() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        console_write(
            json.dumps(
                {"systemMessage": f"Context Guard received invalid hook JSON: {exc.msg}"},
                ensure_ascii=True,
            )
        )
        return 0
    console_write(json.dumps(safe_dispatch(payload), ensure_ascii=True))
    return 0


def find_latest_state(root: Path) -> tuple[Path, dict[str, Any]] | None:
    candidates: list[tuple[float, Path, dict[str, Any]]] = []
    sessions = root / "sessions"
    if not sessions.is_dir():
        return None
    for candidate in sessions.iterdir():
        try:
            if candidate.is_symlink() or not candidate.is_dir():
                continue
            state_path = candidate / "state.json"
            if not state_path.is_file():
                continue
            state = load_state(candidate, {"session_id": candidate.name})
            require_usable_state(state)
            mtime = state_path.stat().st_mtime
        except (OSError, RuntimeError, StateIntegrityError, TypeError, ValueError):
            continue
        if isinstance(state, dict):
            candidates.append((mtime, candidate, state))
    if not candidates:
        return None
    _, session_dir, state = max(candidates, key=lambda item: item[0])
    return session_dir, state


def command_status() -> int:
    latest = find_latest_state(data_root())
    if latest is None:
        print("Context Guard has no local session state.")
        return 0
    _, state = latest
    print(status_context(state))
    return 0


def command_checkpoint_status(args: argparse.Namespace) -> int:
    try:
        snapshot = checkpoint_status(
            args.data_dir.expanduser().resolve(),
            args.session_id,
            args.turn_id,
            args.token,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        console_write(f"[FAIL] {bounded(exc, 800)}", stream=sys.stderr)
        return 1
    console_write(json.dumps(snapshot, ensure_ascii=True, indent=2))
    return 0


def command_stage_checkpoint(args: argparse.Namespace) -> int:
    try:
        checkpoint_sha256 = validate_checkpoint_request(
            args.data_dir.expanduser().resolve(),
            args.session_id,
            args.turn_id,
            args.token,
            args.requirement,
            args.acceptance,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        console_write(f"[FAIL] {bounded(exc, 800)}", stream=sys.stderr)
        return 1
    print(
        f"{STAGE_REQUEST_MARKER} {checkpoint_sha256[:12]}"
    )
    return 0


def command_self_test() -> int:
    hooks = Path(__file__).resolve().parent.parent / "hooks" / "hooks.json"
    config = read_json(hooks)
    expected = {
        "UserPromptSubmit",
        "PostToolUse",
        "PreCompact",
        "SessionStart",
        "SubagentStart",
        "SubagentStop",
        "Stop",
        "SessionEnd",
    }
    actual = set(config.get("hooks", {})) if isinstance(config, dict) else set()
    if expected != actual:
        print(f"FAIL hook events: expected {sorted(expected)}, got {sorted(actual)}")
        return 1
    if sys.version_info < (3, 9):
        print(f"FAIL Python 3.9+ required, got {sys.version.split()[0]}")
        return 1
    print(
        f"PASS context-guard self-test: Python {sys.version.split()[0]}, "
        f"{len(actual)} hook events"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("hook", help="Read one Codex hook payload from stdin")
    subparsers.add_parser("status", help="Show the latest private session summary")
    subparsers.add_parser("cleanup", help="Delete ended sessions older than 30 days")
    subparsers.add_parser("self-test", help="Validate the runtime and hook bundle")
    for name, help_text in (
        (
            "checkpoint-status",
            "Inspect turn-bound private requirements and successful evidence",
        ),
        (
            "stage-checkpoint",
            "Stage a validated private checkpoint before the final response",
        ),
    ):
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("--data-dir", type=Path, required=True)
        command.add_argument("--session-id", required=True)
        command.add_argument("--turn-id", required=True)
        command.add_argument("--token", required=True)
        if name == "stage-checkpoint":
            command.add_argument("--requirement", action="append", default=[])
            command.add_argument("--acceptance", action="append", default=[])
    args = parser.parse_args()
    if args.command == "hook":
        return command_hook()
    if args.command == "status":
        return command_status()
    if args.command == "cleanup":
        print(f"Removed {cleanup_old_sessions(data_root())} expired session(s).")
        return 0
    if args.command == "checkpoint-status":
        return command_checkpoint_status(args)
    if args.command == "stage-checkpoint":
        return command_stage_checkpoint(args)
    return command_self_test()


if __name__ == "__main__":
    raise SystemExit(main())
