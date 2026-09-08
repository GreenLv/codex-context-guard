"""Pure PreToolUse action/effect classifier for Context Guard.

No ledger, no state, no I/O. Only stdlib (fully self-contained). This module
must be importable in a process where cg_ledger, cg_release_policy, and
context_guard are poisoned.

Phase 4 semantics (frozen plan section 4.4): classification resolves real
command segments and the REAL executable position of every invocation, then
classifies by subcommand and effect. Text-position command words (echo/
printf/rg/grep arguments, quoted phrases, doc examples) are never actions;
--dry-run/--check style variants and read-only forms are simulation or
read_only and never consume authorization; only real external mutations are
actions. Ambiguity is a bounded, deterministic class: a known mutation
executable handed to an argument-runner (xargs/find/watch/parallel) is
ambiguous, everything else unresolvable stays fail-open for the profiles.

The router-facing API is the three-state classifier
:class:`classify_pre_tool_state` (STATE_SAFE / STATE_CANDIDATE /
STATE_AMBIGUOUS): only provably side-effect-free invocations are SAFE;
CANDIDATE delegates for authorization; AMBIGUOUS delegates for a fail-open
decision (release profile may fail closed for obvious external mutation
executables).
"""

from __future__ import annotations

import json as _json
import os
import re
import shlex
from typing import Any


# Inline stdlib-only utilities (previously from cg_common) so this module
# is fully self-contained with zero non-stdlib dependencies. Heavy stdlib
# modules (hashlib, subprocess, pathlib) are imported lazily inside the
# only functions that use them, so the router's SAFE hot path never pays
# for them.
def _canonical_json(value):
    return _json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def _sha256_text(text):
    import hashlib as _hashlib
    return _hashlib.sha256(text.encode()).hexdigest()

def _bounded(value, limit=300):
    return str(value)[:limit]

EXECUTION_ID_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]*$")


def validate_pre_tool_decision(decision: Any) -> None:
    """Validate the synchronous PreToolUse allow/deny output subset."""
    if not isinstance(decision, dict) or set(decision) != {"hookSpecificOutput"}:
        raise ValueError("PreToolUse decision must contain only hookSpecificOutput")
    output = decision.get("hookSpecificOutput")
    if not isinstance(output, dict):
        raise ValueError("PreToolUse hookSpecificOutput must be an object")
    allowed = {"hookEventName", "permissionDecision", "permissionDecisionReason"}
    if not set(output).issubset(allowed) or output.get("hookEventName") != "PreToolUse":
        raise ValueError("unsupported PreToolUse output field")
    permission = output.get("permissionDecision")
    if permission not in {"allow", "deny"}:
        raise ValueError("Phase-4 PreToolUse decision must be allow or deny")
    reason = output.get("permissionDecisionReason")
    if permission == "deny" and (not isinstance(reason, str) or not reason or len(reason) > 512):
        raise ValueError("PreToolUse deny requires a bounded reason")
    if permission == "allow" and reason is not None and (
        not isinstance(reason, str) or len(reason) > 512
    ):
        raise ValueError("PreToolUse allow reason is invalid")


SHELL_TOOL_NAMES = {
    "bash", "shell", "exec_command", "mcp_exec_command", "unified_exec",
}


APPLY_PATCH_TOOL_NAMES = {"apply_patch", "mcp_apply_patch"}


def normalized_tool_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


def pre_tool_input_sha256(tool_name: str, tool_input: Any) -> str:
    return _sha256_text(
        _canonical_json({"tool_name": tool_name, "tool_input": tool_input})
    )


def repository_identity(cwd: Any) -> str:
    from pathlib import Path
    try:
        resolved = str(Path(str(cwd or os.getcwd())).expanduser().resolve())
    except (OSError, RuntimeError, ValueError):
        resolved = str(cwd or "unresolved")
    return "repo-" + _sha256_text(resolved)


def repository_commit(cwd: Any) -> str:
    import subprocess
    root = str(cwd or os.getcwd())
    try:
        result = subprocess.run(
            ["git", "-C", root, "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=False,
            timeout=2,
        )
        status = subprocess.run(
            ["git", "-C", root, "status", "--porcelain=v1", "--untracked-files=all"],
            text=True,
            capture_output=True,
            check=False,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return "unresolved"
    value = result.stdout.strip().lower()
    clean = status.returncode == 0 and not status.stdout.strip()
    return (
        value
        if clean and result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", value)
        else "unresolved"
    )


def _shell_command(tool_input: Any) -> str | None:
    if isinstance(tool_input, str):
        return tool_input
    if isinstance(tool_input, dict):
        for key in ("cmd", "command"):
            value = tool_input.get(key)
            if isinstance(value, str):
                return value
    return None


def _unquote_command_token(token: str) -> str:
    """Remove quote pairs retained by non-POSIX ``shlex`` tokenization."""
    while len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}:
        token = token[1:-1]
    return token


def _command_basename(token: str) -> str:
    """Return a shell executable basename for either path separator style."""
    name = _unquote_command_token(token).replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.removesuffix(".exe")


def _command_tokens(
    command: str,
    *,
    posix: bool | None = None,
    _windows_shell: str | None = None,
) -> list[str]:
    # Newlines separate commands exactly like ";" in POSIX shells; shlex
    # would otherwise fold them into ordinary whitespace and merge the
    # segments. Quoted newlines stay inside their quoted token.
    posix_mode = os.name != "nt" if posix is None else posix
    windows_shell = _windows_shell or (
        "powershell" if posix is None and os.name == "nt" else "cmd"
    )
    powershell_mode = not posix_mode and windows_shell == "powershell"
    pieces: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(command):
        char = command[index]
        if escaped:
            pieces.append(char)
            escaped = False
            index += 1
            continue
        escape_char = "\\" if posix_mode else "\x60" if powershell_mode else None
        if char == escape_char and quote != "'":
            escaped = True
            pieces.append(char)
            index += 1
            continue
        quote_chars = {"'", '"'} if posix_mode or powershell_mode else {'"'}
        if (
            powershell_mode
            and quote == "'"
            and char == "'"
            and index + 1 < len(command)
            and command[index + 1] == "'"
        ):
            pieces.extend(("'", "'"))
            index += 2
            continue
        if char in quote_chars:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
        pieces.append("; " if char in "\r\n" and quote is None else char)
        index += 1
    command = "".join(pieces)
    if not posix_mode:
        # Non-POSIX shlex only honors quotes at word starts, so a quoted
        # ";" or "&" inside an env-assignment value splits into separate
        # segments and hides the real invocation. Mask punctuation AND
        # whitespace inside quote spans with sentinel prefixes before
        # lexing and restore them per token afterwards: a control char or
        # blank inside quotes is never a segment boundary, and the
        # assignment keeps binding the value the shell would use
        # (fail-closed: hostile selector values stay visible to the
        # classifier).
        if any(char in command for char in _QUOTE_SENTINELS.values()):
            return []
        masked: list[str] = []
        quote = None
        escaped = False
        index = 0
        while index < len(command):
            char = command[index]
            if escaped:
                masked.append(char)
                escaped = False
                index += 1
                continue
            if powershell_mode and char == "\x60" and quote != "'":
                masked.append(char)
                escaped = True
                index += 1
                continue
            if (
                powershell_mode
                and quote == "'"
                and char == "'"
                and index + 1 < len(command)
                and command[index + 1] == "'"
            ):
                masked.extend(("'", "'"))
                index += 2
                continue
            quote_chars = {"'", '"'} if powershell_mode else {'"'}
            if char in quote_chars:
                if quote is None:
                    quote = char
                elif quote == char:
                    quote = None
                masked.append(char)
                index += 1
                continue
            if quote is not None and char in _QUOTE_SENTINELS:
                # Whole-word sentinel: the shell punctuation or blank
                # inside the quote span is replaced by a wordchar sentinel
                # and restored verbatim after lexing, so it can never act
                # as a segment boundary or split the quoted value.
                masked.append(_QUOTE_SENTINELS[char])
                index += 1
                continue
            masked.append(char)
            index += 1
        command = "".join(masked)
    try:
        lexer = shlex.shlex(
            command,
            posix=posix_mode,
            punctuation_chars=";&|()",
        )
        lexer.whitespace_split = True
        lexer.commenters = ""
        if not posix_mode:
            lexer.quotes = "'" + '"' if powershell_mode else '"'
            lexer.wordchars += "".join(_QUOTE_SENTINELS.values())
        tokens = [_unquote_command_token(token) for token in lexer]
        if not posix_mode:
            # Restore the sentinel mapping to the exact original bytes.
            restore = str.maketrans(
                {value: key for key, value in _QUOTE_SENTINELS.items()}
            )
            tokens = [token.translate(restore) for token in tokens]
        return tokens
    except ValueError:
        return []


_QUOTE_SENTINELS = {
    ";": "\x03",
    "&": "\x04",
    "|": "\x05",
    "(": "\x06",
    ")": "\x07",
    " ": "\x01",
    "\t": "\x02",
}


SHELL_CONTROL_TOKENS = {";", "&&", "||", "|", "&", "(", ")"}


SHELL_WRAPPERS = {"bash", "dash", "ksh", "pwsh", "powershell", "sh", "zsh"}
POSIX_SHELL_WRAPPERS = SHELL_WRAPPERS - {"pwsh", "powershell"}


def _outer_windows_shell(
    command: str, *, posix: bool | None, windows_shell: str
) -> str:
    """Select quote rules for an explicit POSIX wrapper on Windows.

    A direct non-POSIX command is projected with CMD quote rules so a single
    quote never hides a real CMD control boundary.  Codex commonly spells an
    explicit POSIX wrapper payload with an outer PowerShell single-quoted
    argument; recognize only that known wrapper position before recursively
    switching the payload itself to POSIX rules.
    """
    posix_mode = os.name != "nt" if posix is None else posix
    if posix_mode or windows_shell != "cmd":
        return windows_shell
    first = command.lstrip().split(maxsplit=1)[0] if command.strip() else ""
    return (
        "powershell"
        if _command_basename(first) in POSIX_SHELL_WRAPPERS
        else windows_shell
    )


def _expanded_command_tokens(
    command: str,
    *,
    depth: int = 0,
    posix: bool | None = None,
    _windows_shell: str | None = None,
) -> list[str]:
    """Tokenize a command and boundedly inspect explicit shell ``-c`` wrappers.

    Kept for wire compatibility with existing probes: the inner wrapper
    script's tokens are APPENDED to the flat token list. Position-aware
    classification uses :func:`_expanded_command_segments`, which splices
    wrapper scripts in place so segment boundaries stay truthful.
    """
    windows_shell = _windows_shell or (
        "powershell" if posix is None and os.name == "nt" else "cmd"
    )
    token_shell = _outer_windows_shell(command, posix=posix, windows_shell=windows_shell)
    tokens = _command_tokens(command, posix=posix, _windows_shell=token_shell)
    if depth >= 3:
        return tokens
    expanded = list(tokens)
    for index, token in enumerate(tokens):
        wrapper = _command_basename(token)
        if wrapper not in SHELL_WRAPPERS:
            continue
        for option_index in range(index + 1, min(len(tokens), index + 5)):
            option = tokens[option_index].lower()
            if option in SHELL_CONTROL_TOKENS:
                break
            is_command_option = (
                option in {"-c", "--command", "-command"}
                or (option.startswith("-") and "c" in option[1:] and wrapper not in {"pwsh", "powershell"})
            )
            if is_command_option and option_index + 1 < len(tokens):
                is_powershell = wrapper in {"pwsh", "powershell"}
                nested_posix = True if not is_powershell else False
                expanded.extend(
                    _expanded_command_tokens(
                        tokens[option_index + 1],
                        depth=depth + 1,
                        posix=nested_posix,
                        _windows_shell=(
                            "powershell" if is_powershell else "cmd"
                        ),
                    )
                )
                break
    return expanded


def command_segments(tokens: list[str]) -> list[list[str]]:
    """Split a token stream into command segments at control operators."""
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in SHELL_CONTROL_TOKENS:
            segments.append([])
            continue
        segments[-1].append(token)
    return [segment for segment in segments if segment]


_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# Prefixes whose own name is never the effect carrier: the first token after
# them is the real executable (sudo/env/exec/command/time/...). ``timeout``
# consumes one duration argument first.
TRANSPARENT_PREFIXES = {
    "sudo", "env", "command", "exec", "time", "nice", "nohup", "stdbuf", "doas",
}
PREFIX_ARG_CONSUMERS = {"timeout"}


def _segment_invocation(
    segment: list[str],
) -> tuple[str, list[str], dict[str, str]] | None:
    """Resolve a segment to (executable basename, args, visible env) or None.

    Environment assignments are never transparent noise: the VISIBLE ones —
    leading assignments and assignments passed through the ``env`` prefix —
    are captured, because a selector such as ``NPM_CONFIG_REGISTRY`` or
    ``GH_REPO`` changes the real remote target. Quoted phrases stay single
    tokens, so their basenames can never resolve to an executable here.

    Bounded ``env`` grammar: known flags and ``-u NAME`` argument forms are
    consumed; any OTHER option after ``env`` makes the executable position
    unresolvable — the segment resolves to ("", [], env) and classifies as
    the bounded envelope, never as provably safe.
    """
    index = 0
    env: dict[str, str] = {}
    in_env_prefix = False
    while index < len(segment):
        token = segment[index]
        if _ENV_ASSIGNMENT_RE.match(token):
            name, _, value = token.partition("=")
            # Non-POSIX shlex preserves quotes around an assignment value
            # inside Windows shell-wrapper payloads.  Normalize only matching
            # outer pairs so target selectors bind the value the shell uses.
            env[name] = _unquote_command_token(value)
            index += 1
            continue
        basename = _command_basename(token)
        if basename in TRANSPARENT_PREFIXES:
            # Only `env` consumes option/assignment arguments of its own.
            in_env_prefix = basename == "env"
            index += 1
            continue
        if in_env_prefix:
            if token in {"-u", "--unset", "-C", "--chdir"}:
                index += 2
                continue
            if token.startswith("--") and "=" in token:
                index += 1
                continue
            if token.startswith("-"):
                if token in {"-i", "-v", "-0", "--ignore-environment",
                             "--null", "--debug"}:
                    index += 1
                    continue
                # Unknown env option: the real executable position cannot
                # be proven — bounded unresolvable marker.
                return "", [], env
            in_env_prefix = False
        if basename in PREFIX_ARG_CONSUMERS and index + 2 < len(segment):
            index += 2
            continue
        return basename, segment[index + 1 :], env
    return None


def command_invocations_full(
    command: str, *, posix: bool | None = None
) -> list[tuple[str, list[str], dict[str, str]]]:
    """Every real invocation with its visible environment assignments.

    An executable name of "" marks a bounded unresolvable segment (unknown
    ``env`` prefix option): envelope state, never provably safe."""
    invocations = []
    for segment in _expanded_command_segments(command, posix=posix):
        invocation = _segment_invocation(segment)
        if invocation is not None:
            invocations.append(invocation)
    return invocations


def _expanded_command_segments(
    command: str,
    *,
    depth: int = 0,
    posix: bool | None = None,
    _windows_shell: str | None = None,
) -> list[list[str]]:
    """Position-aware segment expansion: shell ``-c`` wrapper scripts are
    parsed recursively and spliced in place, so a nested invocation keeps
    its own segment boundary (``bash -c 'git tag v1' ; npm publish`` stays
    two invocations)."""
    windows_shell = _windows_shell or (
        "powershell" if posix is None and os.name == "nt" else "cmd"
    )
    token_shell = _outer_windows_shell(command, posix=posix, windows_shell=windows_shell)
    tokens = _command_tokens(command, posix=posix, _windows_shell=token_shell)
    if not tokens:
        return []
    if depth >= 3:
        return command_segments(tokens)
    result: list[list[str]] = []
    for segment in command_segments(tokens):
        spliced = False
        if segment and _command_basename(segment[0]) in SHELL_WRAPPERS:
            wrapper = _command_basename(segment[0])
            for option_index in range(1, min(len(segment), 5)):
                option = segment[option_index].lower()
                if option in SHELL_CONTROL_TOKENS:
                    break
                is_command_option = (
                    option in {"-c", "--command", "-command"}
                    or (
                        option.startswith("-")
                        and "c" in option[1:]
                        and wrapper not in {"pwsh", "powershell"}
                    )
                )
                if is_command_option and option_index + 1 < len(segment):
                    # A POSIX shell keeps POSIX quoting semantics even when its
                    # outer launcher command was tokenized on Windows.
                    is_powershell = wrapper in {"pwsh", "powershell"}
                    nested_posix = True if not is_powershell else False
                    result.extend(
                        _expanded_command_segments(
                            " ".join(segment[option_index + 1 :]),
                            depth=depth + 1,
                            posix=nested_posix,
                            _windows_shell=(
                                "powershell" if is_powershell else "cmd"
                            ),
                        )
                    )
                    spliced = True
                    break
        if not spliced:
            result.append(segment)
    return result if result else [tokens]


def command_invocations(
    command: str, *, posix: bool | None = None
) -> list[tuple[str, list[str]]]:
    """Every real (executable position) invocation of a shell command."""
    return [
        (executable, args)
        for executable, args, _env in command_invocations_full(command, posix=posix)
    ]


# Known external mutation executables: their presence as an ARGUMENT of an
# argument-runner (xargs/find/watch/parallel) is the one bounded ambiguity
# class; everywhere else a mutation executable outside executable position
# is provably inert text.
MUTATION_EXECUTABLES = {"git", "gh", "npm", "cargo", "gem", "docker", "twine"}
ARG_RUNNER_EXECUTABLES = {"xargs", "find", "watch", "parallel"}

GIT_GLOBAL_ARG_OPTIONS = {"-C", "-c", "--git-dir", "--work-tree"}

GIT_TAG_INERT_FLAGS = {
    "-d", "--delete", "-l", "--list", "-v", "--verify",
    "--contains", "--points-at",
}
PUSH_FORCE_FLAGS = {"--force", "--force-with-lease", "-f"}
PUSH_DRY_RUN_FLAGS = {"--dry-run", "-n"}
GH_RELEASE_VERBS = {"create", "edit", "delete", "upload"}
GH_RELEASE_INERT_VERBS = {"view", "list", "status"}

# Registry grammar: (tool, CLI subcommand) -> (operation, tool). Publish,
# unpublish, yank, and deprecate are DISTINCT exact semantics; a publish
# authorization never covers the reverse/metadata mutations.
REGISTRY_OPERATIONS = {
    ("npm", "publish"): ("publish", "npm"),
    ("npm", "unpublish"): ("unpublish", "npm"),
    ("npm", "deprecate"): ("deprecate", "npm"),
    ("cargo", "publish"): ("publish", "cargo"),
    ("cargo", "yank"): ("yank", "cargo"),
    ("gem", "push"): ("publish", "gem"),
    ("gem", "yank"): ("yank", "gem"),
    ("docker", "push"): ("publish", "docker"),
    ("twine", "upload"): ("publish", "twine"),
}
REGISTRY_OPERATION_TOOLS = frozenset(tool for tool, _op in REGISTRY_OPERATIONS)
_MCP_MUTATION_MARKERS = {
    "create_release": "github_release_create",
    "update_release": "github_release_edit",
    "delete_release": "github_release_delete",
    "upload_release_asset": "github_release_upload",
    "publish_package": "registry_publish_package",
    "unpublish_package": "registry_unpublish_package",
    "yank_package": "registry_yank_package",
    "deprecate_package": "registry_deprecate_package",
}
REGISTRY_DRY_RUN_FLAGS = {
    "npm": {"--dry-run"},
    "cargo": {"--dry-run", "-n"},
    "docker": {"--dry-run"},
    "twine": {"--dry-run"},
    "gem": set(),
}

VERSION_PATTERN = (
    r"v?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:[-+][A-Za-z0-9._-]+)?"
)


def _first_version_token(values: list[str]) -> str | None:
    for value in values:
        candidate = value.removeprefix("refs/tags/")
        if re.fullmatch(VERSION_PATTERN, candidate):
            return candidate
    return None


_GIT_PSEUDO_REFS = {
    "HEAD",
    "FETCH_HEAD",
    "ORIG_HEAD",
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "BISECT_HEAD",
    "AUTO_MERGE",
}


def _is_valid_git_branch_name(value: Any) -> bool:
    """Bounded Git branch-name validation, separate from execution IDs."""
    text = str(value or "")
    if not text or len(text) > 1024 or text.upper() in _GIT_PSEUDO_REFS:
        return False
    if text.startswith("-") or text.endswith(("/", ".")):
        return False
    if ".." in text or "@{" in text or "//" in text:
        return False
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        return False
    if any(char in " ~^:?*[\\" for char in text):
        return False
    components = text.split("/")
    return all(
        component
        and not component.startswith(".")
        and not component.endswith((".", ".lock"))
        for component in components
    )


def current_branch(cwd: Any) -> str:
    import subprocess
    try:
        result = subprocess.run(
            ["git", "-C", str(cwd or os.getcwd()), "branch", "--show-current"],
            text=True,
            capture_output=True,
            check=False,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    value = result.stdout.strip()
    return value if result.returncode == 0 and _is_valid_git_branch_name(value) else "unknown"


def _git_invocation_action(
    args: list[str], branch_cwd: Any = None
) -> dict[str, str] | None:
    """Classify one real git invocation by subcommand and effect."""
    index = 0
    while index < len(args) and args[index].startswith("-"):
        option = args[index]
        index += 2 if option in GIT_GLOBAL_ARG_OPTIONS else 1
    if index >= len(args):
        return None
    subcommand = args[index].lower()
    tail = args[index + 1 :]
    if subcommand == "tag":
        if any(value in GIT_TAG_INERT_FLAGS for value in tail):
            return None
        positional_tags = [value for value in tail if not value.startswith("-")]
        if positional_tags:
            tag = _first_version_token(tail) or "unknown"
            return {
                "tier": "A", "semantic_action_id": "release_tag_mutation",
                "canonical_target_id": f"tag:{tag}", "write_surface_id": "git_release_tag",
                "tag": tag,
            }
        return None
    if subcommand == "push":
        if any(value in PUSH_DRY_RUN_FLAGS for value in tail):
            return None
        positional = [value for value in tail if not value.startswith("-")]
        version = _first_version_token(tail)
        if version is not None or "--tags" in tail or any("refs/tags/" in value for value in tail):
            tag = version or "all"
            return {
                "tier": "A", "semantic_action_id": "release_tag_push",
                "canonical_target_id": f"tag:{tag}", "write_surface_id": "git_remote_tag",
                "tag": tag,
                "remote": positional[0] if positional else "unknown",
            }
        remote = positional[0] if positional else "unknown"
        if len(positional) > 1:
            refspec = positional[1]
        elif branch_cwd is not None:
            refspec = current_branch(branch_cwd)
        else:
            refspec = "unknown"
        ref = refspec.rsplit(":", 1)[-1]
        semantic = "remote_push"
        if any(
            value in PUSH_FORCE_FLAGS
            or value.startswith("--force-with-lease")
            or value == "--force-if-includes"
            or value.startswith("+")
            for value in tail
        ):
            # --force-with-lease=<ref>[:<expect>] and --force-if-includes
            # are force semantics in value form too; a plain push
            # authorization never covers them.
            semantic = "force_push"
        elif "--delete" in tail or any(value.startswith(":") for value in tail):
            semantic = "remote_branch_delete"
        return {
            "tier": "B", "semantic_action_id": semantic,
            "canonical_target_id": f"remote:{remote}:{ref.lstrip(':')}",
            "write_surface_id": "git_remote_branch",
            "remote": remote,
            "ref": ref.lstrip(":"),
        }
    return None


GH_GLOBAL_VALUE_OPTIONS = {"--repo", "-R", "--hostname"}
GH_GLOBAL_FLAG_OPTIONS = {"--web", "-w", "--paginate", "--json"}

REGISTRY_GLOBAL_VALUE_OPTIONS = {
    "gh": {"--repo", "-R", "--hostname"},
    "npm": {"--registry", "--workspace", "-w", "--userconfig", "--prefix",
            "--cache", "--loglevel", "--tag", "--otp", "--access",
            "--useragent"},
    "cargo": {"--config", "--manifest-path", "--target", "--jobs", "-j",
              "--color"},
    "gem": {"--config-file"},
    "docker": {"--config", "--context", "-c", "--host", "-H", "--log-level",
               "-l"},
    "twine": {"--config", "--repository", "-r", "--repository-url"},
}
REGISTRY_GLOBAL_FLAG_OPTIONS = {
    "gh": {"--web", "-w", "--paginate", "--json"},
    "npm": {"-g", "--global", "--workspaces", "--offline",
            "--prefer-offline", "--no-audit", "--no-fund", "--json",
            "--silent", "-s", "--quiet", "-q", "--if-present",
            "--ignore-scripts", "--dry-run"},
    "cargo": {"-q", "--quiet", "-v", "--verbose", "--frozen", "--locked",
              "--offline"},
    "gem": set(),
    "docker": {"--debug", "-D"},
    "twine": set(),
}
REGISTRY_SUBCOMMAND_VALUE_OPTIONS = {
    "npm": {"--registry", "--tag", "--access", "--otp", "--userconfig",
            "--workspace", "-w", "--prefix"},
    "cargo": {"--manifest-path", "--target", "--index", "--registry",
              "--config", "-j", "--jobs", "--version"},
    "gem": {"--host", "-v", "--version"},
    "docker": {"--platform"},
    "twine": {"--repository", "-r", "--repository-url", "--config"},
}

# Real option ALIAS pairs inside each tool's grammar: the two spellings
# are the SAME option, so captured values are stored and compared on the
# canonical (long) spelling. Repeating the SAME value is idempotent —
# across aliases, across option regions, and across separated/= forms;
# different values are a conflict (undetermined — controlled deny),
# never spelling- or order-dependent (P1-J). npm's -w/--workspace also
# compares on its own workspace dimension; gem's -v/--version is a
# subcommand-tail option canonicalized by the same table.
CANONICAL_VALUE_OPTION_SPELLINGS: dict[str, dict[str, str]] = {
    "gh": {"-R": "--repo"},
    "cargo": {"-j": "--jobs"},
    "docker": {"-c": "--context", "-H": "--host", "-l": "--log-level"},
    "npm": {"-w": "--workspace"},
    "twine": {"-r": "--repository"},
    "gem": {"-v": "--version"},
}

# Visible environment/config selectors that change the REAL remote target
# (P1-D/P1-I). Each maps the environment variable onto the equivalent CLI
# option dimension; the CLI option always wins when both are present.
# npm reads its config environment case-insensitively AND accepts its
# whole config surface as npm_config_* variables, so the target-affecting
# allowlist covers registry, userconfig (never read — undetermined deny),
# prefix, and workspace; ``npm_config_workspaces`` is the plural boolean
# and is handled as the multi-target envelope. gh and cargo match their
# exact documented spellings. Unknown variables remain inert.
ENV_TARGET_SELECTORS: dict[str, dict[str, str]] = {
    "npm": {
        "npm_config_registry": "--registry",
        "npm_config_userconfig": "--userconfig",
        "npm_config_prefix": "--prefix",
        "npm_config_workspace": "--workspace",
    },
    "gh": {"GH_REPO": "--repo", "GH_HOST": "--hostname"},
    "cargo": {"CARGO_REGISTRY_DEFAULT": "--registry"},
}
NPM_WORKSPACES_ENV_VAR = "npm_config_workspaces"
_NPM_TRUTHY = {"true", "1", "yes", "on"}
_NPM_FALSY = {"false", "0", "no", "off", ""}


def _npm_env_value(name: str, env: dict[str, str]) -> str | None:
    """The npm config environment value of ONE logical variable, matched
    case-insensitively across spellings. Two spellings carrying
    DIFFERENT values are a conflict (undetermined); an empty value is
    returned as "" (undetermined for value dimensions), and no matching
    spelling returns None."""
    wanted = name.lower()
    values: list[str] = []
    for key, value in env.items():
        if key.lower() == wanted:
            values.append(value)
    if not values:
        return None
    distinct = {value for value in values}
    if len(distinct) > 1:
        return "\x00conflict"
    return values[0]


def _env_selector_options(
    executable: str, env: dict[str, str]
) -> tuple[dict[str, str], set[str]]:
    """Visible env selectors of one invocation, mapped to their option
    dimension (case-insensitive multi-spelling grouping for npm), plus
    the set of CONFLICTED options (two spellings disagreeing). Unknown
    variables are inert."""
    table = ENV_TARGET_SELECTORS.get(executable)
    if not table or not env:
        return {}, set()
    matched: dict[str, str] = {}
    conflicts: set[str] = set()
    if executable == "npm":
        for logical, option in table.items():
            value = _npm_env_value(logical, env)
            if value is None:
                continue
            if value == "\x00conflict" or value == "":
                conflicts.add(option)
                continue
            matched[option] = value
        return matched, conflicts
    for name, value in env.items():
        option = table.get(name)
        if option is None:
            continue
        if value == "":
            conflicts.add(option)
            continue
        existing = matched.get(option)
        if existing is not None and existing != value:
            conflicts.add(option)
            continue
        matched[option] = value
    return matched, conflicts


# ---------------------------------------------------------------------------
# Canonical execution projection (R7 closure table). The closed field set
# every declared mutation surface must resolve — through ONE semantic source
# (this module) shared by the router grammar and the heavy target
# projection — before an action can become an exact authorization target:
#
#   executable          resolved command position (never text)
#   operation           publish/unpublish/yank/deprecate/release verb
#   simulation          tri-state (--dry-run bare/=true vs =false vs absent)
#   trusted_adapter     MCP namespace x method family x tool identity
#   repository_host     GitHub repo/host or local repository identity
#   package/version/source   registry identity (from trusted metadata,
#                       explicit spec, or the exact image reference)
#   registry_name/index/url  the tool's OWN registry value domain, with
#                       documented equivalences normalized (never mixed)
#   config_env_selectors visible env/config selectors folded into the
#                       option dimensions they control (CLI wins)
#   release_tag/target  GitHub release tag + --target commit-ish
#
# Fields stay either EXACT or explicitly undetermined (empty) — never
# dropped and never sentinel-compared.
# ---------------------------------------------------------------------------

CANONICAL_PROJECTION_FIELDS = (
    "executable", "operation", "simulation", "trusted_adapter",
    "repository_host", "package", "version", "source",
    "registry_name", "registry_index_url", "config_env_selectors",
    "release_tag", "release_target_commit",
)

# Documented default equivalences per tool value domain (P1-E): the
# canonical default identity maps onto every documented spelling of the
# same real endpoint — and ONLY those. npm's registry is a base URL whose
# default host is registry.npmjs.org; Cargo's --registry takes a registry
# NAME whose default name is crates-io (= crates.io), --index takes a URL;
# twine's -r is a .pypirc repository NAME (default "pypi") and its default
# --repository-url is https://upload.pypi.org/legacy/.
DEFAULT_REGISTRY_ENDPOINTS = {
    "npm": "registry.npmjs.org",
    "cargo": "crates.io",
    "gem": "rubygems.org",
    "docker": "docker.io",
    "twine": "pypi.org",
    "pypi": "pypi.org",
}
CARGO_REGISTRY_NAME_DEFAULTS = {"crates-io": "crates.io"}
TWINE_REPOSITORY_NAME_DEFAULTS = {"pypi": "pypi.org"}
TWINE_REPOSITORY_URL_DEFAULTS = {
    "upload.pypi.org/legacy": "pypi.org",
}
_GEM_HOST_DEFAULTS = {"rubygems.org": "rubygems.org"}


def canonical_registry_url(value: str) -> str:
    """Canonical host[:port][/path] form of a registry URL: scheme and
    trailing slash are not identity; a non-root path is (case kept)."""
    text = str(value or "").strip()
    if not text:
        return ""
    lowered = text.lower()
    for scheme in ("https://", "http://"):
        if lowered.startswith(scheme):
            text = text[len(scheme):]
            break
    text = text.rstrip("/")
    first, slash, path = text.partition("/")
    return first.lower() + slash + path


def canonical_registry_identity(tool: str, option: str, raw_value: str) -> str:
    """Canonical value of ONE registry option in the tool's OWN domain.

    ``option`` selects the domain: --registry (npm URL / cargo+twine name),
    --index (cargo URL), --repository-url/--host (URL). Unknown raw values
    stay exact strings so they can only ever equal themselves — two
    different real endpoints never collapse.
    """
    text = str(raw_value or "").strip()
    if not text:
        return ""
    if tool == "npm" and option == "--registry":
        return canonical_registry_url(text)
    if tool == "cargo" and option == "--registry":
        lowered = text.lower()
        return CARGO_REGISTRY_NAME_DEFAULTS.get(lowered, text)
    if tool == "cargo" and option == "--index":
        return "index:" + canonical_registry_url(text)
    if tool == "twine" and option in {"--repository", "-r"}:
        lowered = text.lower()
        return TWINE_REPOSITORY_NAME_DEFAULTS.get(lowered, text)
    if tool == "twine" and option == "--repository-url":
        canonical = canonical_registry_url(text)
        return TWINE_REPOSITORY_URL_DEFAULTS.get(canonical, canonical)
    if tool == "gem" and option == "--host":
        canonical = canonical_registry_url(text)
        return _GEM_HOST_DEFAULTS.get(canonical, canonical)
    return text


# The registry options of each tool that participate in the endpoint
# identity, in the tool's OWN value domain (npm: URL; cargo: registry
# NAME + index URL; twine: .pypirc repository NAME + URL; gem: host URL).
REGISTRY_ENDPOINT_OPTION_DOMAINS: dict[str, tuple[str, ...]] = {
    "npm": ("--registry",),
    "cargo": ("--registry", "--index"),
    "gem": ("--host",),
    "twine": ("--repository", "-r", "--repository-url"),
}


def canonical_registry_endpoint(tool: str, values: dict[str, str]) -> str:
    """Canonical endpoint identity of one CLI invocation.

    Documented default spellings normalize onto the default identity (no
    false deny); any non-default dimension becomes a named drift
    component bound to its option (so --registry X and --index X can
    never collapse); an EMPTY explicit value is unresolvable ("") — the
    controlled deny, never a silent default.
    """
    parts: list[str] = []
    for option in sorted(REGISTRY_ENDPOINT_OPTION_DOMAINS.get(tool, ())):
        if option not in values:
            continue
        raw = str(values.get(option) or "").strip()
        if not raw:
            # An explicitly EMPTY value cannot prove which endpoint is
            # effective: undetermined, never defaulted.
            return ""
        canonical = canonical_registry_identity(tool, option, raw)
        if canonical and canonical != DEFAULT_REGISTRY_ENDPOINTS.get(tool):
            parts.append(f"{option}={canonical}")
    default = DEFAULT_REGISTRY_ENDPOINTS.get(tool, "")
    if not parts:
        return default
    return default + "|" + "|".join(parts)


def split_docker_image_reference(
    reference: str,
) -> tuple[str, str, str] | None:
    """Split a Docker image reference into (registry host or "", name, tag).

    Per the Docker docs a reference is NAME[:TAG]; the registry host is the
    first path component when it contains a dot, a colon, or equals
    "localhost" — otherwise the reference targets Docker Hub. A missing tag
    means every tag of the repository, so the tag component stays empty and
    the caller treats the version as undetermined. Malformed references
    return None (unresolvable — never guessed).
    """
    text = str(reference or "").strip().strip("\"'")
    if not text or any(ch.isspace() for ch in text):
        return None
    name, has_colon, tag = text.rpartition(":")
    if has_colon and ("/" not in tag and tag):
        rest = name
    else:
        rest, tag = text, ""
    components = rest.split("/")
    host = ""
    if len(components) >= 2 and (
        "." in components[0] or ":" in components[0]
        or components[0] == "localhost"
    ):
        host = components[0].lower()
        rest = "/".join(components[1:])
    if not rest or not all(component for component in rest.split("/")):
        return None
    return host, rest, tag


# MCP adapter provenance: the closed allowlist of namespaces AND EXACT
# registered methods whose structured tool identity may satisfy an
# authorization. A registry surface is trusted only when the adapter
# namespace EQUALS the structured tool identity; the github namespace is
# trusted only for the github release family; and the RAW method token
# must be EXACTLY one of the registered method spellings. Unknown or
# cross-family namespaces and near-miss method spellings are deliberately
# unmatchable ("untrusted-adapter:<ns>") — they never inherit an
# authorization (P1-B/P1-G).
MCP_REGISTRY_ADAPTER_NAMESPACES = frozenset(
    {"npm", "cargo", "gem", "docker", "twine", "pypi"}
)
MCP_GITHUB_ADAPTER_NAMESPACE = "github"

_MCP_METHOD_FAMILIES = {
    "create_release": "github_release",
    "update_release": "github_release",
    "delete_release": "github_release",
    "upload_release_asset": "github_release",
    "publish_package": "registry_package",
    "unpublish_package": "registry_package",
    "yank_package": "registry_package",
    "deprecate_package": "registry_package",
}


def _mcp_marker_semantic(normalized: str) -> str:
    """The longest registered marker CONTAINED in the normalized name —
    the deterministic semantic for exact AND near-miss surfaces. Exact
    registered methods never reach the near-miss caller, so plain
    containment is the near-miss rule (garbage before, after, or around
    the marker all gate)."""
    best_marker = ""
    best_semantic = ""
    for marker, semantic in _MCP_MUTATION_MARKERS.items():
        if marker in normalized and len(marker) > len(best_marker):
            best_marker, best_semantic = marker, semantic
    return best_semantic


def mcp_adapter_provenance(tool_name: Any) -> tuple[str, str, bool]:
    """(namespace, method family, near_miss) of a structured adapter tool
    name.

    Namespace and method come from the RAW ``mcp__<ns>__<method>``
    identity (not the lossy normalized form). ``family`` is
    "github_release", "registry_package", or "" when the name carries no
    known mutation marker at all. The family is EXACT only when the raw
    method token is precisely a registered method and the whole raw name
    is exactly mcp__ns__METHOD (or the bare METHOD); any other name that
    still hides a known marker — garbage prefix/suffix inside the method,
    wrong case, extra __-segments — is a NEAR-MISS: the family is still
    set (so the surface stays a gated candidate, never silently safe) and
    ``near_miss`` is True, which makes the provenance deliberately
    untrusted.
    """
    raw = str(tool_name or "")
    parts = raw.split("__")
    mcp_form = len(parts) == 3 and parts[0] == "mcp"
    namespace = parts[1] if mcp_form else ""
    method = parts[2] if mcp_form else ""
    normalized = normalized_tool_name(raw)
    family = _MCP_METHOD_FAMILIES.get(method, "")
    if not family and not mcp_form and normalized in _MCP_METHOD_FAMILIES:
        # A bare tool named exactly like a registered method: no adapter
        # namespace at all — an exact surface, deliberately untrusted.
        family = _MCP_METHOD_FAMILIES[normalized]
    if family:
        return namespace, family, False
    if _mcp_marker_semantic(normalized):
        # Near-miss: a known mutation marker hides inside the name but the
        # raw method is not an exactly registered one. Gated candidate,
        # never trusted, never silently safe.
        family = (
            "github_release"
            if normalized.endswith("_release") or "_release_" in normalized
            else "registry_package"
        )
        return namespace, family, True
    return "", "", False


def trusted_mcp_adapter(tool_name: Any, structured_tool: Any = None) -> bool:
    """True only when the EXACT registered method, the namespace, and the
    structured tool identity all agree inside the closed allowlist. Near
    misses, non-MCP names, and unknown namespaces are never trusted."""
    namespace, family, near_miss = mcp_adapter_provenance(tool_name)
    if near_miss or not namespace or not family:
        return False
    if family == "github_release":
        return namespace == MCP_GITHUB_ADAPTER_NAMESPACE
    if namespace not in MCP_REGISTRY_ADAPTER_NAMESPACES:
        return False
    if structured_tool is None:
        return True
    return namespace == str(structured_tool or "").strip().lower()


def registry_reverse_identity(
    tool: str, positionals: list[str], values: dict[str, str]
) -> tuple[str, str]:
    """(package, version) of a reverse/metadata mutation in the tool's OWN
    spec grammar (empty components = undetermined, never a sentinel):

      npm      unpublish/yank/deprecate <name>@<version> — scoped names
               split at the LAST @ and keep their leading @;
      cargo    yank <crate>@<version> | <crate> --version <version> (both
               orders);
      gem      yank <gem> -v <version> (the -v/--version flag may sit
               before or after the name).
    """
    spec = positionals[0] if positionals else ""
    if tool == "npm":
        name, _, version = spec.rpartition("@")
        if not name:
            return "", ""
        return name, version.removeprefix("v")
    if tool == "cargo":
        if "@" in spec:
            name, _, version = spec.rpartition("@")
            return (name, version.removeprefix("v")) if name else ("", "")
        name = spec
        version = str(values.get("--version") or "")
        if not name or not version:
            return "", ""
        return name, version.removeprefix("v")
    if tool == "gem":
        name = spec
        # -v and --version are the same option: live captures store the
        # canonical --version spelling (P1-J); the -v fallback keeps
        # hand-built value dicts resolvable.
        version = str(values.get("--version") or values.get("-v") or "")
        if not name or not version:
            return "", ""
        return name, version.removeprefix("v")
    return "", ""


def _skip_global_options(
    executable: str, args: list[str], start: int
) -> tuple[int, dict[str, Any]]:
    """Skip the supported global-option prefix of one invocation and
    collect the STRUCTURED option values that change the effective target.

    Returns (index of the first positional token or len(args), collected)
    where collected carries workspace selector, option flags, option
    values (registry/repository/manifest/...), a tri-state dry-run
    (True / False / None), and a CONFLICTS set: an option left without
    its value, an explicitly empty = value, or two occurrences with
    different values make that dimension undetermined — controlled deny,
    never last-wins guessing or a silent default (P1-H/P1-I). An unknown
    pre-subcommand option signals (index=-1, ...) — the invocation cannot
    be reliably resolved and becomes the bounded high-risk envelope.
    """
    value_opts = REGISTRY_GLOBAL_VALUE_OPTIONS.get(executable, set())
    flag_opts = REGISTRY_GLOBAL_FLAG_OPTIONS.get(executable, set())
    aliases = CANONICAL_VALUE_OPTION_SPELLINGS.get(executable, {})
    collected: dict[str, Any] = {
        "workspace": None,
        "flags": [],
        "values": {},
        "dry_run": None,
        "conflicts": set(),
    }

    def capture(name: str, value: str | None) -> None:
        if executable == "npm" and name in {"--workspace", "-w"}:
            if value is None or value == "":
                collected["conflicts"].add("--workspace")
                return
            if (
                collected["workspace"] is not None
                and collected["workspace"] != value
            ):
                collected["conflicts"].add("--workspace")
                return
            collected["workspace"] = value
            return
        canonical = aliases.get(name, name)
        if value is None or value == "":
            collected["conflicts"].add(canonical)
            return
        existing = collected["values"].get(canonical)
        if existing is not None and existing != value:
            collected["conflicts"].add(canonical)
            return
        collected["values"][canonical] = value

    index = start
    while index < len(args):
        token = args[index]
        if not token.startswith("-"):
            return index, collected
        if "=" in token:
            name, _, value = token.partition("=")
            if name == "--dry-run":
                collected["dry_run"] = value.strip().lower() not in {
                    "false", "0", "no", "off", "",
                }
                collected["flags"].append(name)
                index += 1
                continue
            capture(name, value if value else None)
            collected["flags"].append(name)
            index += 1
            continue
        if token in value_opts:
            capture(
                token, args[index + 1] if index + 1 < len(args) else None
            )
            if token == "--dry-run":
                collected["dry_run"] = True
            collected["flags"].append(token)
            index += 2
            continue
        if token in flag_opts:
            if token == "--dry-run":
                collected["dry_run"] = True
            collected["flags"].append(token)
            index += 1
            continue
        return -1, collected
    return index, collected

def _dry_run_tri_state(tokens: list[str]) -> bool | None:
    """Tri-state --dry-run semantics over a token list.

    True  — an explicit simulation (--dry-run, --dry-run=true, ...),
    False — an explicitly disabled simulation (--dry-run=false is a REAL
            mutation, pre- or post-subcommand alike),
    None  — no dry-run option present.
    """
    state = None
    for token in tokens:
        if token == "--dry-run":
            state = True
        elif token.startswith("--dry-run="):
            value = token.partition("=")[2].strip().lower()
            state = value not in {"false", "0", "no", "off", ""}
    return state


def _registry_invocation_state(
    executable: str, args: list[str], env: dict[str, str] | None = None
) -> tuple[str, dict[str, Any] | None]:
    """Classify one registry-tool invocation by its REAL option grammar.

    Returns ("mutation", action) for a resolved publish/unpublish/yank/
    deprecate subcommand, ("envelope", None) when the invocation cannot
    resolve to ONE exact target (unknown pre-subcommand option, all
    workspaces at once — CLI flag or npm_config_workspaces env, a publish
    naming several distribution files), and ("inert", None) for every
    non-mutation invocation. --dry-run (bare or =true) is a simulation;
    --dry-run=false is a REAL mutation, pre- or post-subcommand alike.
    Visible env selectors (P1-D/P1-I) fold into the option dimensions
    whenever the CLI option itself is absent; conflicting spellings,
    missing values, and conflicting repeats make the dimension
    undetermined (controlled deny), never dropped.
    """
    index, collected = _skip_global_options(executable, args, 0)
    if index == -1:
        return "envelope", None
    if index >= len(args):
        return "inert", None
    operation = REGISTRY_OPERATIONS.get((executable, args[index].lower()))
    if operation is None:
        return "inert", None
    operation_name, tool = operation
    tail = args[index + 1 :]
    tail_dry_run = _dry_run_tri_state(tail)
    if tail_dry_run is None and any(
        flag in REGISTRY_DRY_RUN_FLAGS.get(executable, set()) for flag in tail
    ):
        tail_dry_run = True
    dry_run = (
        collected["dry_run"] if collected["dry_run"] is not None else tail_dry_run
    )
    if dry_run is True:
        return "inert", None
    workspaces_value = collected["values"].get("--workspaces")
    if "--workspaces" in collected["flags"] and (
        workspaces_value is None
        or workspaces_value.strip().lower() not in _NPM_FALSY
    ):
        # Every workspace at once: the exact package identity is
        # undetermined, so the invocation cannot be a single exact target.
        # The =false spelling explicitly disables the multi-target mode.
        return "envelope", None
    if executable == "npm":
        workspaces_env = _npm_env_value(NPM_WORKSPACES_ENV_VAR, env or {})
        if workspaces_env is not None and (
            workspaces_env == "\x00conflict"
            or workspaces_env.strip().lower() not in _NPM_FALSY
        ):
            # npm_config_workspaces=true (or an unparseable value) is the
            # same multi-target mode as the CLI flag.
            return "envelope", None
    positionals: list[str] = []
    sub_value_opts = REGISTRY_SUBCOMMAND_VALUE_OPTIONS.get(tool, set())
    walk = 0
    tail_values: dict[str, str] = {}
    tail_aliases = CANONICAL_VALUE_OPTION_SPELLINGS.get(tool, {})
    while walk < len(tail):
        token = tail[walk]
        if token.startswith("-"):
            if "=" in token:
                name, _, value = token.partition("=")
                if name == "--dry-run":
                    walk += 1
                    continue
                canonical = tail_aliases.get(name, name)
                if value:
                    existing = tail_values.get(canonical)
                    if existing is not None and existing != value:
                        collected.setdefault("conflicts", set()).add(canonical)
                    else:
                        tail_values[canonical] = value
                else:
                    collected.setdefault("conflicts", set()).add(canonical)
                walk += 1
                continue
            if token in sub_value_opts:
                canonical = tail_aliases.get(token, token)
                if walk + 1 < len(tail):
                    value = tail[walk + 1]
                    existing = tail_values.get(canonical)
                    if existing is not None and existing != value:
                        collected.setdefault("conflicts", set()).add(canonical)
                    else:
                        tail_values[canonical] = value
                    walk += 2
                else:
                    # An option left without its value cannot prove the
                    # dimension it controls.
                    collected.setdefault("conflicts", set()).add(canonical)
                    walk += 1
                continue
            walk += 1
            continue
        positionals.append(token)
        walk += 1
    if operation_name == "publish" and len(positionals) > 1:
        # Several distribution files at once (twine upload a.tar.gz b.whl):
        # more than one exact identity, never a single authorized target.
        return "envelope", None
    # Region merge on CANONICAL dimensions (P1-J): the same option spelled
    # in two regions with different values is a conflict (undetermined —
    # never last-wins); the same value repeats idempotently.
    values = dict(collected["values"])
    for name, value in tail_values.items():
        existing = values.get(name)
        if existing is not None and existing != value:
            collected.setdefault("conflicts", set()).add(name)
        else:
            values[name] = value
    # Visible env/config selectors fold into their option dimension ONLY
    # when the CLI option itself is absent (the CLI always wins); env
    # conflicts are undetermined, never dropped.
    env_values, env_conflicts = _env_selector_options(executable, env or {})
    for option, value in env_values.items():
        values.setdefault(option, value)
    conflicts = set(collected.get("conflicts") or ()) | set(env_conflicts)
    if tool == "npm" and values.get("--workspace"):
        if collected["workspace"] is None:
            # npm_config_workspace selects the effective source exactly
            # like the CLI option.
            collected["workspace"] = values["--workspace"]
        elif collected["workspace"] != values["--workspace"]:
            # The workspace dimension repeats across regions with
            # different values: undetermined, never region-priority.
            conflicts.add("--workspace")
    action = {
        "tier": "A",
        "semantic_action_id": f"registry_{tool}_{operation_name}",
        "canonical_target_id": f"registry:{tool}:{operation_name}",
        "write_surface_id": "package_registry",
        "release_version": "unresolved",
        "registry_operation": operation_name,
        "registry_tool": tool,
        "registry_tail": tail[:8],
        "registry_workspace": collected["workspace"],
        "registry_flags": collected["flags"][:8],
        "registry_values": values,
        "registry_positionals": positionals[:8],
    }
    if conflicts:
        action["registry_conflicts"] = sorted(conflicts)
    return "mutation", action

GH_INHERITED_VALUE_OPTIONS = {"--repo", "-R", "--hostname", "--target"}
# -R and --repo are the SAME option: values are captured and compared on
# the canonical --repo dimension, so a cross-alias repeat with a different
# value is a conflict and a same-value repeat is idempotent (P1-J).
GH_OPTION_ALIAS_SPELLINGS = {"-R": "--repo"}
GH_RELEASE_VERB_TAIL_VALUE_OPTIONS = {
    "--title", "--notes", "--notes-file", "--assets", "--notes-start-tag",
}


def _gh_capture_option(
    collected: dict[str, Any], name: str, value: str | None
) -> None:
    """Capture one inherited-option value position-independently on the
    CANONICAL option dimension (-R and --repo are the same repo option).

    Repeating the SAME value is idempotent — across aliases, across the
    three legal regions, and across separated/= spellings; a conflicting
    value, or an option left WITHOUT its value, is a controlled conflict
    — the target becomes undetermined (deny), never last-wins guessing
    (P1-H/P1-J).
    """
    canonical = GH_OPTION_ALIAS_SPELLINGS.get(name, name)
    if value is None or value == "":
        collected.setdefault("conflicts", set()).add(canonical)
        return
    existing = collected["values"].get(canonical)
    if existing is not None and existing != value:
        collected.setdefault("conflicts", set()).add(canonical)
        return
    collected["values"][canonical] = value


def _gh_scan_options(
    tokens: list[str],
    collected: dict[str, Any],
    *,
    stop_at_positional: bool,
) -> int:
    """Scan one option region (before the noun, between noun and verb, or
    the verb tail) with ONE position-independent grammar: inherited
    options (--repo/-R/--hostname/--target) capture their values in both
    the separated and the = form; known value options consume theirs; the
    walk returns at the first positional when ``stop_at_positional``."""
    walk = 0
    while walk < len(tokens):
        token = tokens[walk]
        if not token.startswith("-"):
            if stop_at_positional:
                return walk
            if collected.get("tag") is None:
                collected["tag"] = token
            walk += 1
            continue
        if "=" in token:
            name, _, value = token.partition("=")
            if name in GH_INHERITED_VALUE_OPTIONS:
                _gh_capture_option(collected, name, value)
            walk += 1
            continue
        if token in GH_INHERITED_VALUE_OPTIONS:
            _gh_capture_option(
                collected, token,
                tokens[walk + 1] if walk + 1 < len(tokens) else None,
            )
            walk += 2
            continue
        if token in GH_RELEASE_VERB_TAIL_VALUE_OPTIONS:
            walk += 2 if walk + 1 < len(tokens) else 1
            continue
        walk += 1
    return walk


def _gh_invocation_state(
    executable: str, args: list[str], env: dict[str, str] | None = None
) -> tuple[str, dict[str, Any] | None]:
    """gh invocations: ONE position-independent grammar over the THREE
    regions the GitHub CLI accepts inherited options in — after ``gh``,
    between ``release`` and the verb, and after the verb. --repo/-R/
    --hostname bind the real target repo/host wherever they appear;
    ``--target`` changes the commit an auto-created tag points at. An
    unknown pre-noun option is the bounded envelope, never provably safe;
    missing values and CONFLICTING repeats make the target undetermined
    (controlled deny), never last-wins guessing. Verb-tail values
    (--title/--notes/...) can never impersonate the release tag.
    """
    index, collected = _skip_global_options(executable, args, 0)
    if index == -1:
        return "envelope", None
    if index >= len(args) or args[index].lower() != "release":
        return "inert", None
    collected.setdefault("values", {})
    # Region 2: between the release noun and the verb — inherited options
    # are legal exactly here (gh release --repo o/r create ...), so the
    # scan stops at the first positional, which IS the verb.
    scan = args[index + 1 :]
    verb_index = _gh_scan_options(scan, collected, stop_at_positional=True)
    if verb_index >= len(scan):
        return "inert", None
    verb = scan[verb_index].lower()
    if verb not in GH_RELEASE_VERBS:
        return "inert", None
    verb_tail = scan[verb_index + 1 :]
    if "--dry-run" in verb_tail:
        return "inert", None
    # Region 3: the verb tail. The tag is the first true positional;
    # option values are never the tag.
    collected["tag"] = None
    _gh_scan_options(verb_tail, collected, stop_at_positional=False)
    tag = collected.get("tag") or "unknown"
    action = {
        "tier": "A", "semantic_action_id": f"github_release_{verb}",
        "canonical_target_id": f"release:{tag}",
        "write_surface_id": "github_release",
        "release_version": tag,
    }
    gh_repo_value = collected["values"].get("--repo") or ""
    if gh_repo_value:
        action["gh_repo"] = gh_repo_value
    if collected["values"].get("--hostname"):
        action["gh_hostname"] = collected["values"]["--hostname"]
    if collected["values"].get("--target"):
        action["gh_target"] = collected["values"]["--target"]
    conflicts = sorted(collected.get("conflicts") or ())
    if conflicts:
        # Conflicting repeats or missing values: the real target cannot be
        # proven — the identity dimensions involved become undetermined.
        action["gh_conflicts"] = conflicts
    # Visible env selectors (P1-D) fold in only when the option is absent.
    env_values, _env_conflicts = _env_selector_options(executable, env or {})
    for option, value in env_values.items():
        if option == "--repo" and not gh_repo_value:
            action["gh_repo"] = value
        elif option == "--hostname" and "gh_hostname" not in action:
            action["gh_hostname"] = value
    return "mutation", action

def _git_invocation_state(
    executable: str, args: list[str], branch_cwd: Any = None
) -> tuple[str, dict[str, str] | None]:
    action = _git_invocation_action(args, branch_cwd=branch_cwd)
    return ("mutation", action) if action is not None else ("inert", None)


def _invocation_state(
    executable: str,
    args: list[str],
    env: dict[str, str] | None = None,
    branch_cwd: Any = None,
) -> tuple[str, dict[str, str] | None]:
    if executable == "":
        # Bounded unresolvable segment (unknown `env` prefix option).
        return "envelope", None
    if executable == "git":
        return _git_invocation_state(executable, args, branch_cwd=branch_cwd)
    if executable == "gh":
        return _gh_invocation_state("gh", args, env)
    if executable in REGISTRY_OPERATION_TOOLS:
        return _registry_invocation_state(executable, args, env)
    return "inert", None


def _shell_actions(
    command: str, *, branch_cwd: Any = None, posix: bool | None = None
) -> list[dict[str, str]]:
    """Every real mutation action carried by a shell command.

    Only invocations whose executable sits in a real command position are
    considered; simulation (--dry-run/-n) and read-only forms produce no
    action; envelope invocations (unresolvable option prefixes) produce no
    action here but classify as the bounded envelope upstream.
    ``branch_cwd`` resolves a bare ``git push`` refspec to the current
    branch; purity callers pass None (``unknown``).
    """
    actions: list[dict[str, str]] = []
    for executable, args, env in command_invocations_full(command, posix=posix):
        state, action = _invocation_state(
            executable, args, env, branch_cwd=branch_cwd
        )
        if state == "mutation" and action is not None:
            actions.append(action)
    return actions


def _shell_invocation_states(
    command: str, *, posix: bool | None = None
) -> list[str]:
    """The per-invocation state sequence: inert / mutation / envelope."""
    states = []
    for executable, args, env in command_invocations_full(command, posix=posix):
        state, _action = _invocation_state(executable, args, env)
        states.append(state)
    return states

def classify_pre_tool_action(payload: dict[str, Any]) -> dict[str, Any] | None:
    tool_name = str(payload.get("tool_name") or "")
    normalized = normalized_tool_name(tool_name)
    tool_input = payload.get("tool_input")
    input_sha = pre_tool_input_sha256(tool_name, tool_input)
    action: dict[str, Any] | None = None
    if normalized in SHELL_TOOL_NAMES or normalized.endswith("_exec_command"):
        command = _shell_command(tool_input)
        if command is None:
            return None
        actions = _shell_actions(command, branch_cwd=payload.get("cwd"))
        if len(actions) == 1:
            action = actions[0]
        elif len(actions) > 1:
            action = {
                "tier": "A" if any(item["tier"] == "A" for item in actions) else "B",
                "semantic_action_id": "compound_remote_mutation",
                "canonical_target_id": f"compound:{_sha256_text(_canonical_json(actions))}",
                "write_surface_id": "multiple_remote_surfaces",
                "release_version": "unresolved",
            }
    if action is None:
        semantic = _mcp_marker_semantic(normalized)
        if semantic:
            action = {
                "tier": "A", "semantic_action_id": semantic,
                "canonical_target_id": f"tool-target:{_sha256_text(_canonical_json(tool_input))}",
                "write_surface_id": "remote_release_api",
                "release_version": "unresolved",
            }
            _namespace, family, near_miss = mcp_adapter_provenance(tool_name)
            if family:
                # Structured adapter provenance rides on the action. An
                # EMPTY namespace marks a non-MCP bare tool name, and a
                # near-miss method spelling is deliberately untrusted
                # (P1-B/P1-G closed allowlist) — neither can inherit.
                action["mcp_namespace"] = "" if near_miss else _namespace
    if action is None:
        return None
    if "release_version" not in action:
        target_value = action["canonical_target_id"].split(":", 1)[-1]
        action["release_version"] = target_value if target_value != "unknown" else "unresolved"
    return {
        **action,
        "input_sha256": input_sha,
        "repository_id": repository_identity(payload.get("cwd")),
        "candidate_commit": repository_commit(payload.get("cwd")),
    }


def classify_action_kind(tool_name: str, tool_input: Any) -> dict[str, Any] | None:
    """Pure, fast action-kind detection (no git subprocess, no repo fields).

    Text-position command words, quoted phrases, and simulation variants
    never produce an action kind.
    """
    normalized = normalized_tool_name(tool_name)
    if normalized in SHELL_TOOL_NAMES or normalized.endswith("_exec_command"):
        command = _shell_command(tool_input)
        if command is None:
            return None
        actions = _shell_actions(command)
        if len(actions) == 1:
            return actions[0]
        if len(actions) > 1:
            return {
                "tier": "A" if any(item["tier"] == "A" for item in actions) else "B",
                "semantic_action_id": "compound_remote_mutation",
                "canonical_target_id": f"compound:{_sha256_text(_canonical_json(actions))}",
                "write_surface_id": "multiple_remote_surfaces",
                "release_version": "unresolved",
            }
        return None
    semantic = _mcp_marker_semantic(normalized)
    if semantic:
        return {
            "tier": "A", "semantic_action_id": semantic,
            "canonical_target_id": f"tool-target:{_sha256_text(_canonical_json(tool_input))}",
            "write_surface_id": "remote_release_api",
            "release_version": "unresolved",
        }
    return None


def _shell_runner_ambiguity(command: str, *, posix: bool | None = None) -> bool:
    """True only when a known mutation executable is handed to an
    argument-runner (xargs/find/watch/parallel) — executed later, position
    unresolvable from the command string alone."""
    for executable, args in command_invocations(command, posix=posix):
        if executable in ARG_RUNNER_EXECUTABLES and any(
            _command_basename(value) in MUTATION_EXECUTABLES for value in args
        ):
            return True
    return False


# Three-state PreToolUse classification plus the bounded high-risk
# envelope: SAFE and generic AMBIGUOUS (malformed/unparseable) take the
# silent light-layer fast path; CANDIDATE delegates; the runner envelope
# (STATE_AMBIGUOUS_CANDIDATE) delegates for profile decisions.
STATE_SAFE = "safe"
STATE_CANDIDATE = "candidate"
STATE_AMBIGUOUS = "ambiguous"
STATE_AMBIGUOUS_CANDIDATE = "ambiguous_candidate"

# Tools that are read-only by contract and need no shell parsing.
SAFE_TOOL_NAMES = {
    "read", "view", "grep", "glob", "search", "web_search", "fetch",
}


def classify_pre_tool_state(tool_name: Any, tool_input: Any) -> str:
    """Classify a PreToolUse invocation into SAFE / CANDIDATE / AMBIGUOUS.

    Pure, fast, stdlib-only. EVERY tool passes through here; only SAFE may
    take the router fast path (empty object, zero state I/O). CANDIDATE
    covers recognized mutation surfaces: shell commands carrying a real
    mutation invocation, apply_patch, and registered remote/MCP mutation
    methods. AMBIGUOUS covers structurally unreliable input, and the one
    bounded semantic class: a mutation executable passed to an
    argument-runner. Unknown non-mutation tools (including MCP tools with
    unregistered methods) are SAFE and return the empty object immediately.
    """
    if not isinstance(tool_name, str) or not tool_name.strip():
        return STATE_AMBIGUOUS
    normalized = normalized_tool_name(tool_name)
    if normalized in APPLY_PATCH_TOOL_NAMES or normalized.endswith("_apply_patch"):
        return STATE_CANDIDATE
    if normalized in SHELL_TOOL_NAMES or normalized.endswith("_exec_command"):
        return _classify_shell_state(normalized, tool_input)
    if _mcp_marker_semantic(normalized):
        # Exact registered methods AND near-miss spellings (garbage
        # prefix/suffix, wrong case, extra __ segments) are gated
        # candidates — a near-miss is never silently safe (P1-G).
        return STATE_CANDIDATE
    if normalized in SAFE_TOOL_NAMES:
        return STATE_SAFE
    return STATE_SAFE


def _classify_shell_state(normalized: str, tool_input: Any) -> str:
    if not isinstance(tool_input, dict):
        return STATE_AMBIGUOUS
    command = _shell_command(tool_input)
    if not isinstance(command, str) or not command.strip():
        return STATE_AMBIGUOUS
    if not _command_tokens(command):
        # shlex could not tokenize the command reliably (unterminated
        # quote, stray backslash, ...) — parseability, not safety.
        return STATE_AMBIGUOUS
    if _shell_runner_ambiguity(command):
        # Obvious mutation executable behind an argument runner: delegate
        # as a candidate-high-risk envelope so profiles can decide.
        return STATE_AMBIGUOUS_CANDIDATE
    if any(
        state == "envelope" for state in _shell_invocation_states(command)
    ):
        # An unknown pre-subcommand option on a mutation executable cannot
        # be reliably resolved: bounded high-risk envelope, profile decides.
        return STATE_AMBIGUOUS_CANDIDATE
    if _shell_actions(command):
        return STATE_CANDIDATE
    if local_source_effect(command) is not None:
        return STATE_CANDIDATE
    return STATE_SAFE


def classify_shell_effects(
    command: str, *, posix: bool | None = None
) -> list[dict[str, str]]:
    """Per-invocation effect classes for diagnostics and conformance tests.

    Single source of truth: every row derives from :func:`_invocation_state`
    (the same grammar the gate uses), so diagnostics can never drift from
    enforcement. Effects: mutation (gated), simulation (--dry-run, ungated),
    read_only (ungated query forms), envelope (bounded high-risk ambiguity),
    inert (provably unrelated).
    """
    rows: list[dict[str, str]] = []
    for executable, args, env in command_invocations_full(command, posix=posix):
        state, action = _invocation_state(executable, args, env)
        effect = "inert"
        if state == "envelope":
            effect = "envelope"
        elif state == "mutation":
            effect = "mutation"
        elif executable in MUTATION_EXECUTABLES or executable in REGISTRY_OPERATION_TOOLS:
            # A mutation executable whose invocation resolved to no action:
            # either a simulation (--dry-run) or a read-only form.
            tokens = [value.lower() for value in args]
            dry_flags = REGISTRY_DRY_RUN_FLAGS.get(executable, set())
            if (
                "--dry-run" in tokens
                or _dry_run_tri_state(args) is True
                or any(flag in dry_flags for flag in args)
            ):
                effect = "simulation"
            elif executable in REGISTRY_OPERATION_TOOLS:
                effect = "read_only"
            else:
                effect = "read_only"
        rows.append({"executable": executable, "effect": effect})
    return rows

def is_stateless_pre_tool(payload: dict[str, Any]) -> bool:
    """Light-router fast-path predicate: provably SAFE calls AND generic
    (malformed/unresolvable) ambiguity both take the silent empty-object
    path with zero state I/O; only candidates and the runner envelope
    reach the heavy core."""
    return classify_pre_tool_state(
        payload.get("tool_name"), payload.get("tool_input")
    ) in {STATE_SAFE, STATE_AMBIGUOUS}


GIT_COMMIT_SIMULATION_FLAGS = {"--dry-run"}


def is_git_commit_command(command: str) -> bool:
    """True when a command really executes ``git commit`` at a real
    executable position (``--dry-run`` is a simulation, not a commit)."""
    for executable, args in command_invocations(command):
        if executable != "git" or not args:
            continue
        index = 0
        while index < len(args) and args[index].startswith("-"):
            option = args[index]
            index += 2 if option in GIT_GLOBAL_ARG_OPTIONS else 1
        if index < len(args) and args[index].lower() == "commit":
            if not any(
                value in GIT_COMMIT_SIMULATION_FLAGS for value in args[index + 1 :]
            ):
                return True
    return False


def local_source_effect(command: str) -> dict[str, Any] | None:
    """Recognized local observations, never high-risk action authorization.

    This only routes literal direct-shell source writes and real commits to
    the existing stateful Hook. It does not interpret JavaScript/tool text.
    """
    invocations = command_invocations(command)
    if any(exe in {"cd", "pushd", "set-location"} for exe, _args in invocations):
        return {"kind": "unsupported", "paths": []}
    commits = []
    for exe, args in invocations:
        if exe != "git":
            continue
        index = 0
        roots = []
        while index < len(args) and args[index].startswith("-"):
            flag = args[index]
            if flag in {"--git-dir", "--work-tree"} or flag.startswith(("--git-dir=", "--work-tree=")):
                return {"kind": "unsupported", "paths": []}
            if flag == "-C" and index + 1 < len(args):
                roots.append(args[index + 1])
            index += 2 if flag in GIT_GLOBAL_ARG_OPTIONS else 1
        if index < len(args) and args[index] == "commit" and "--dry-run" not in args[index+1:]:
            commits.append({"roots": roots})
    if commits:
        return {"kind": "commit", "paths": [], "roots": commits[0]["roots"]} if all(c == commits[0] for c in commits) else {"kind": "unsupported", "paths": []}
    paths: list[str] = []
    tokens = _command_tokens(command)
    for i, token in enumerate(tokens[:-1]):
        if token in {">", ">>"} and tokens[i+1] not in {"&", "1", "2", "/dev/null"}:
            paths.append(tokens[i+1].strip("\"'"))
    for exe, args in invocations:
        if exe.lower() in {"set-content", "add-content", "out-file"}:
            for flag in {"-path", "-literalpath", "-filepath"}:
                lowered = [a.lower() for a in args]
                if flag in lowered and lowered.index(flag) + 1 < len(args):
                    paths.append(args[lowered.index(flag)+1].strip("\"'"))
    if paths:
        return {"kind": "edit", "paths": list(dict.fromkeys(paths))}
    return None
