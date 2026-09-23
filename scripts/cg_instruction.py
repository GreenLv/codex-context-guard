"""Lossless instruction/object segmentation; never an authority or path resolver.

Offsets are Python character offsets plus explicit UTF-8 byte offsets into the
unchanged source. The masked view is only for classification, never hashing,
persisting a source span, resolving a locator, or certifying an object.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Fragment:
    kind: str
    start: int
    end: int
    byte_start: int
    byte_end: int
    text: str


# Quoting makes the entire object opaque, including spaces and punctuation.
# Apostrophes in contractions are not opening quotes. Unclosed fences remain
# data through end-of-input, rather than turning an example into an instruction.
_QUOTES = re.compile(
    r"```[\s\S]*?(?:```|\Z)|~~~[\s\S]*?(?:~~~|\Z)|`[^`\n]*`|"
    r'"[^"\n]*"|(?<!\w)\x27[^\x27\n]*\x27|“[^”\n]*”|‘[^’\n]*’|「[^」\n]*」|『[^』\n]*』'
)
_BLOCK = re.compile(r"(?m)^\s*>[^\n]*")
# A lexical path is data even when unsupported by the evidence resolver (UNC,
# traversal, etc.). In particular no prefix of an invalid path gains authority.
_PATH = re.compile(
    r"(?<![\w:/\\])(?:https?://|codex://|[A-Za-z]:[\\/]|\\\\|/|\.{1,2}[\\/]|~/)"
    r"[^\s,;，；。!?！？\x27\"`<>]+|"
    r"(?<![\w:/\\])(?:[\w.@+~-]+[\\/])+[\w.@+~\\/-]+|"
    r"(?<![\w.])[^\s/\\,;，；。!?！？\x27\"`<>]+\.(?:py|js|ts|json|md|txt|sh|ps1|yaml|yml)\b",
    re.UNICODE | re.IGNORECASE,
)


def fragments(text: str) -> tuple[Fragment, ...]:
    """Partition every original character exactly once, retaining raw objects."""
    ambiguous: set[tuple[int, int]] = set()
    objects: list[tuple[int, int]] = sorted(
        match.span() for pattern in (_QUOTES, _BLOCK) for match in pattern.finditer(text)
    )
    for match in _PATH.finditer(text):
        if not any(begin <= match.start() < end for begin, end in objects):
            objects.append(match.span())
            # A bare extension followed immediately by CJK may be a filename
            # or adjacent prose. Preserve all bytes but do not certify a
            # smaller action from the masked prefix. Quoting resolves it.
            if re.search(r"\.[A-Za-z0-9]+[\u3400-\u9fff]", match.group()):
                ambiguous.add(match.span())
    merged: list[tuple[int, int]] = []
    for begin, end in sorted(objects):
        if merged and begin < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((begin, end))
    offsets = [0]
    for char in text:
        offsets.append(offsets[-1] + len(char.encode("utf-8")))
    result: list[Fragment] = []
    cursor = 0
    for begin, end in merged:
        if cursor < begin:
            result.append(Fragment("instruction", cursor, begin, offsets[cursor], offsets[begin],
                                   text[cursor:begin]))
        result.append(Fragment("ambiguous_object" if (begin, end) in ambiguous else "object",
                               begin, end, offsets[begin], offsets[end], text[begin:end]))
        cursor = end
    if cursor < len(text):
        result.append(Fragment("instruction", cursor, len(text), offsets[cursor], offsets[-1], text[cursor:]))
    return tuple(result)


def instruction_text(text: str, *, preserve_newlines: bool = True) -> str:
    """A position-preserving view; object newlines retain clause boundaries."""
    return "".join(part.text if part.kind == "instruction" else
                   "".join("\n" if preserve_newlines and char == "\n" else " " for char in part.text)
                   for part in fragments(text))


def action_matches(pattern: re.Pattern[str], text: str) -> list[re.Match[str]]:
    """Return original-source matches whose action is outside opaque data.

    Match against the instruction view so a verb before a path cannot absorb
    an action word inside it. Match offsets remain original character offsets.
    """
    return list(pattern.finditer(instruction_text(text)))


def action_search(pattern: re.Pattern[str], text: str) -> re.Match[str] | None:
    return next(iter(action_matches(pattern, text)), None)


def governed_test_action(text: str) -> re.Match[str] | None:
    """Preserve the bounded 'run test_*.py' grammar, not bare path keywords.

    A suite basename supplies the type of the explicitly requested run. A
    directory named test, review or commit never supplies an extra action.
    This is a lexical candidate only; the existing target/readiness adapter
    still verifies the complete locator before certifying a test result.
    """
    view = instruction_text(text)
    for part in fragments(text):
        if part.kind != "object":
            continue
        locator = part.text.strip('"\x27`“”‘’')
        if not (re.match(r"(?:[A-Za-z]:[\\/]|/|\\\\|\.{1,2}[\\/]|~/)", locator)
                or re.fullmatch(r"[^\s/\\]+(?:[/\\][^\n]+)?", locator)
                or re.fullmatch(r"test[^/\\]*\.py", locator, re.I)):
            continue
        basename = re.split(r"[/\\]", locator)[-1]
        if not re.search(r"(?:^|[_. -])test[^/\\]*\.py$", basename, re.I):
            continue
        governors = list(re.finditer(r"\b(?:run|execute)\b|运行|执行", view[:part.start], re.I))
        if governors and not view[governors[-1].end():part.start].strip():
            return governors[-1]
    return None
