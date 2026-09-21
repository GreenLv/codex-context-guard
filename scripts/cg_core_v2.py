"""Host-neutral, side-effect-free core v2 projection. No execution authority.

Input trust belongs to the host adapter; this is not a public receipt API.
All temporal joins are bounded by the caller's explicit as-of watermark.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from typing import Any

from cg_core_v2_schema import load_strict, validate_snapshot

SCHEMA = "core-observation/v2"
DOMAIN = b"context-guard/core/v2\0"
MAX_INTEGER = 9007199254740991


def canonical_bytes(value: Any) -> bytes:
    def check(node: Any) -> None:
        if node is None or isinstance(node, bool):
            return
        if isinstance(node, str):
            node.encode("utf-8", "strict")
            return
        if type(node) is int and abs(node) <= MAX_INTEGER:
            return
        if isinstance(node, list):
            for child in node:
                check(child)
            return
        if isinstance(node, dict) and all(isinstance(k, str) for k in node):
            for key, child in node.items():
                check(key)
                check(child)
            return
        raise ValueError("noncanonical_value")

    check(value)
    # Unicode scalar order and UTF-8 byte order coincide.
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(DOMAIN + canonical_bytes(value)).hexdigest()


def _index(rows: list[dict], watermark: int) -> dict[str, dict]:
    result: dict[str, dict] = {}
    seen: set[str] = set()
    for row in rows:
        if row["id"] in seen:
            raise ValueError("duplicate_identity")
        seen.add(row["id"])
        if row["seq"] <= watermark:
            result[row["id"]] = row
    return result


def _source_matches(
    span: dict, sources: dict[str, dict], *, root: bool = False
) -> bool:
    source = sources.get(span["source_id"])
    if source and source["text"] is not None:
        raw = source["text"].encode("utf-8")
        try:
            raw[: span["start"]].decode("utf-8")
            raw[: span["end"]].decode("utf-8")
        except UnicodeDecodeError:
            return False
    return bool(
        source
        and (not root or source["kind"] == "root")
        and span["sha256"] == source["sha256"]
        and 0 <= span["start"] < span["end"] <= source["byte_length"]
    )


def _control_speech(text: str, kind: str, rules: dict[str, str]) -> bool:
    """Accept only a direct control utterance, never cited or reported text."""
    if re.match(r"^\s*(?:```|`|[“‘\"]|>)", text):
        return False
    speech = re.sub(
        r"```[\s\S]*?```|`[^`]*`|“[^”]*”|‘[^’]*’|\"[^\"]*\"",
        "对象", text.strip(),
    )
    speech = re.sub(
        r"^(?:(?:请(?:先)?|现在|先)\s*|(?:please|now|kindly)\s+)+",
        "", speech, flags=re.I,
    )
    if kind == "persistence" and _subjectless_compound_persistence(speech):
        return True
    if re.match(r"^(?:不要|不得|别|切勿|无需|不必|do\s+not\b|don't\b|never\b)", speech, re.I):
        return False
    if kind == "persistence":
        match = re.search(rules["USER_PERSISTENCE_RE"], speech, re.I | re.S)
        return bool(match and match.start() == 0)
    if kind == "resume":
        return (_current_unit_scope_speech(speech, kind)
                or bool(re.match(rules["EXECUTION_RESUME_RE"], speech, re.I)))
    if kind == "pause":
        return bool(re.match(r"^(?:暂停|搁置|pause\b|hold\b)", speech, re.I))
    if kind == "cancel":
        return bool(re.match(r"^(?:取消|撤销|不再进行|cancel\b|drop\b)", speech, re.I))
    return False


def _subjectless_compound_persistence(text: str) -> bool:
    """One direct negative-stop plus positive-until act, with no object NP."""
    return bool(re.fullmatch(
        r"\s*(?:(?:请|现在)\s*)?"
        r"(?:不要|不得|别|切勿)\s*(?:停止|停下|暂停|结束)\s*[,，]\s*"
        r"(?:持续|继续|一直)\s*(?:执行|推进|工作)\s*"
        r"(?:直到|直至)\s*(?:完成|结束)\s*[。.!！]?\s*",
        text,
    ))


def _single_root_task_scope(prefix: str, rows: list[dict]) -> bool:
    """Resolve an omitted task object only from one preceding root task."""
    if not rows:
        return False
    direct = prefix.strip().rstrip("。.!！")
    if re.search(r"[。！？;；\n]", direct):
        return False
    if len(rows) == 1:
        return _direct_work_clause(direct)
    parents = [row for row in rows if row.get("parent_id") is None]
    if len(parents) != 1 or parents[0].get("action") != "local_edit":
        return False
    parent = parents[0]
    if not all(row is parent or (
        row.get("parent_id") == parent.get("id")
        and row.get("action") in {"test_verify", "state_readback"}
        and row.get("target") == parent.get("target")
    ) for row in rows):
        return False
    clauses = direct.split("并")
    # The dependency graph, not a fixed number of coordinated clauses,
    # establishes one task. Every required child must have its own direct
    # predicate in the same root; an unrelated sibling fails the graph above.
    return (len(clauses) == len(rows)
            and len(clauses) >= 2
            and all(_direct_work_clause(clause) for clause in clauses))


def _action_class_scope_speech(text: str, kind: str) -> tuple[str, int, int] | None:
    """Find a test-class object in one direct, complete control clause.

    This returns a source span, not authority: the caller still validates the
    immutable root, full receipt-time catalog, and every controlled ref.
    """
    noun = r"(?P<noun>(?:本轮|这轮|当前|全部|这项|该项)测试)"
    if kind == "persistence":
        pattern = (r"\s*(?:(?:请|请先|先)\s*)?"
                   r"(?:持续|继续|一直)(?:执行|推进|完成|处理|运行)\s*"
                   r"(?:(?:本轮|这轮|当前|全部)测试\s*)?[,，]?\s*"
                   r"(?:直到|直至)\s*" + noun +
                   r"\s*(?:完成|结束)(?:为止)?\s*[。.!！]?\s*")
    else:
        pattern = (r"\s*(?:(?:请|请先|先)\s*)?"
                   r"(?:暂停|搁置|取消|撤销|继续)\s*" + noun +
                   r"\s*[。.!！]?\s*")
    match = re.fullmatch(pattern, text)
    return (match.group("noun"), match.start("noun"), match.end("noun")) if match else None


def _direct_work_clause(text: str) -> bool:
    """A preceding coordinated predicate, not reported/negated source text."""
    clause = text.strip().rstrip("，,。.!！")
    unquoted = re.sub(r"`[^`]*`|“[^”]*”|‘[^’]*’|\"[^\"]*\"", "对象", clause)
    # A preceding command must be one complete predicate. A comma/colon
    # introducing another speaker or another predicate, or an earlier
    # coordination chain, cannot lend its initial imperative to a later 并.
    if re.search(r"[,，:：;；]|并|然后|随后|\b(?:and|then)\b", unquoted, re.I):
        return False
    if re.match(r"^(?:如果|假如|假设|未来|以后|将来|当|若|if|when|later|future)\b", clause, re.I):
        return False
    if re.match(r"^(?:不要|不得|别|切勿|无需|不必|do\s+not|don't|never)\b", clause, re.I):
        return False
    return bool(re.match(
        r"^(?:(?:请|请先|先|现在)\s*)?"
        r"(?:运行|测试|修复|修改|编辑|更新|实现|检查|评估|测量|提交|推送|执行)"
        r"|^(?:please\s+)?(?:run|test|repair|fix|edit|update|implement|check|evaluate|measure|commit|push)\b",
        clause, re.I,
    ))


def _root_sentence_bounds(raw: bytes, span: dict, rules: dict[str, str]) -> tuple[int, int] | None:
    """Return a governing sentence start and same-control-clause end.

    Punctuation inside quoted/code data is never a speech-act boundary.
    A comma may end a target clause, but cannot itself start a new direct
    control: reported speech after a comma remains governed by its prefix.
    """
    text = raw.decode("utf-8")
    sentences = [0]
    delimiters: list[tuple[int, int, str]] = []
    compound_commas: set[int] = set()
    offset = 0
    quoted_by: str | None = None
    segment_start = 0
    for index, char in enumerate(text):
        before = offset
        offset += len(char.encode("utf-8"))
        if quoted_by is not None:
            if char == quoted_by:
                quoted_by = None
            continue
        if char in {"“", "‘", '"', "`"}:
            quoted_by = {"“": "”", "‘": "’"}.get(char, char)
            continue
        if char == "并":
            preceding = text[segment_start:index]
            following = text[index + 1:]
            if (_direct_work_clause(preceding)
                    and _control_speech(following.split("。", 1)[0], "persistence", rules)):
                sentences.append(offset)
                delimiters.append((before, offset, char))
                segment_start = index + 1
                continue
        if char in "。！？;；\n" or (
            char in ".!?" and (index + 1 == len(text) or text[index + 1].isspace())
        ):
            sentences.append(offset)
            delimiters.append((before, offset, char))
            segment_start = index + 1
        elif char in "，,":
            remainder = re.split(r"[。！？;；\n]", text[index + 1:], maxsplit=1)[0]
            if _subjectless_compound_persistence(
                text[segment_start:index] + char + remainder
            ):
                compound_commas.add(before)
            delimiters.append((before, offset, char))
    start = max((b for b in sentences if b <= span["start"]), default=0)
    if raw[start:span["start"]].strip():
        return None
    clause_end = len(raw)
    delimiter_end = len(raw)
    for begin, after, char in delimiters:
        if begin < span["start"]:
            continue
        if begin in compound_commas:
            continue
        if char in "，,":
            following = raw[after:].decode("utf-8").lstrip()
            # An until-clause is the same persistence command. A coordinated
            # new action is not, regardless of punctuation wording.
            if re.match(r"^(?:直到|直至|until\b)", following, re.I):
                continue
        clause_end, delimiter_end = begin, after
        break
    content_end = clause_end
    while content_end > start and raw[content_end - 1:content_end].isspace():
        content_end -= 1
    if span["end"] not in {content_end, delimiter_end}:
        return None
    return start, delimiter_end


def _current_unit_scope_speech(text: str, kind: str) -> bool:
    # A singleton item is not itself a referent: "cancel B" cannot be
    # relabeled as current_unit merely because only A is in the snapshot.
    lead = r"\s*(?:(?:请|请先|先)\s*|(?:please|now)\s+)*"
    end = r"\s*[。.!！]?\s*"
    # A determiner and a current-unit qualifier are separate grammatical
    # roles, shared by every control kind. Recognizing this phrase only
    # proposes a scope; immutable root/catalog checks still bind its members.
    en_scoped = (r"(?:(?:(?:this|the)\s+)?current|this)"
                 r"\s+(?:task|work)")
    scoped = (r"(?:(?:当前|本轮|这轮|全部|整个)(?:任务|工作|事项)|"
              + en_scoped + r")")
    if kind in {"pause", "resume", "cancel"}:
        verb = {"pause": r"(?:暂停|搁置|pause|hold)",
                "resume": r"(?:继续|continue)",
                "cancel": r"(?:取消|撤销|cancel|drop)"}[kind]
        noun = scoped if kind == "cancel" else r"(?:" + scoped + r")?"
        return bool(re.fullmatch(lead + verb + r"\s*" + noun + end,
                                 text, re.I))
    if kind == "persistence":
        if _subjectless_compound_persistence(text):
            return True
        # Complete current-unit grammar: no unbound object can be inserted
        # before or after the until-clause and silently govern the snapshot.
        zh = (lead + r"(?:持续|继续|一直)(?:执行|推进|工作|完成|处理)"
              r"\s*[,，]?\s*(?:直到|直至)(?:(?:当前|本轮|这轮|全部|整个))?"
              r"(?:任务|工作|事项)(?:完成|结束)" + end)
        terminal = r"(?:is\s+)?(?:done|complete|finished)"
        en_head = lead + r"(?:keep|continue)\s+(?:going|working)"
        en = (en_head + r"(?:\s+on\s+" + en_scoped + r")?"
              r"\s+until\s+(?:" + en_scoped
              + r"|(?:whole|entire)\s+(?:task|work))\s+" + terminal + end)
        en_anaphora = (en_head + r"\s+on\s+" + en_scoped
                       + r"\s+until\s+it\s+" + terminal + end)
        return bool(re.fullmatch(zh, text, re.I) or re.fullmatch(en, text, re.I)
                    or re.fullmatch(en_anaphora, text, re.I))
    return False


def _explicit_target_speech(prefix: str, suffix: str, kind: str) -> bool:
    """A single literal object must exhaust a control clause's object role."""
    if kind in {"pause", "resume", "cancel"}:
        verb = {"pause": r"(?:暂停|搁置|pause|hold)",
                "resume": r"(?:继续|continue)",
                "cancel": r"(?:取消|撤销|cancel|drop)"}[kind]
        return bool(
            re.fullmatch(r"\s*(?:(?:请|请先|先)\s*|please\s+)*" + verb
                         + r"\s*(?:文件|目录|测试|仓库)?\s*[`“\"]?\s*", prefix, re.I)
            and re.fullmatch(r"\s*[`”\"]?\s*[。.!！]?\s*", suffix)
        )
    if kind == "persistence":
        return bool(
            re.fullmatch(r"\s*(?:(?:请|请先)\s*|please\s+)*"
                         r"(?:持续|继续|一直)(?:执行|推进|完成|处理)\s*[`“\"]?\s*",
                         prefix, re.I)
            and re.fullmatch(r"\s*[`”\"]?\s*(?:的测试)?\s*(?:直到|直至)"
                             r"(?:当前|本轮|这轮)?(?:任务|工作|测试)?(?:完成|结束)"
                             r"\s*[。.!！]?\s*", suffix, re.I)
        )
    return False


def _scope_open(req: dict, at_seq: int) -> bool:
    """A supersession closes future scope without erasing earlier controls."""
    end = req.get("superseded_at_seq")
    if req["status"] == "superseded" and end is None:
        return False  # A migrated final label has no trustworthy effective time.
    return req["seq"] <= at_seq and (end is None or at_seq < end)


def _fold_root_controls(
    snapshot: dict, sources: dict[str, dict], requirements: dict[str, dict],
    facts: dict[str, dict], units: set[str], watermark: int, rules: dict[str, str],
) -> tuple[dict[str, str], list[str], set[str], set[str]]:
    """Fold sourced controls over their exact at-receipt requirement set.

    Invalid/ambiguous controls are diagnostics, never continuation authority.
    Requirements and controls are distinct from ordinary tool permissions.
    """
    states: dict[str, str] = {}
    errors: list[str] = []
    represented: set[str] = set()
    resumed: set[str] = set()
    controls = snapshot.get("root_controls", [])
    if len({c["id"] for c in controls}) != len(controls):
        raise ValueError("duplicate_root_control")
    ordered = sorted(controls, key=lambda c: (c["seq"], c["source"]["start"], c["id"]))
    positions: set[tuple[int, str, int]] = set()
    for control in ordered:
        if control["seq"] > watermark:
            continue
        span = control["source"]
        source = sources.get(span["source_id"])
        if source is not None and source["unit"] not in units:
            continue  # An unrelated sibling cannot affect this closure.
        control_unit = source["unit"] if source is not None else None
        position = (control["seq"], span["source_id"], span["start"])
        valid = bool(
            source and source["kind"] == "root" and source["unit"] in units
            and source["seq"] == control["seq"] <= watermark
            and _source_matches(span, sources, root=True)
            and position not in positions
            and sum(s["seq"] == control["seq"] for s in sources.values()) == 1
        )
        positions.add(position)
        if not valid:
            errors.append(control["id"])
            continue
        text = source["text"].encode("utf-8")[span["start"]:span["end"]].decode("utf-8")
        sentence = _root_sentence_bounds(source["text"].encode("utf-8"), span, rules)
        if sentence is None or not _control_speech(text, control["kind"], rules):
            errors.append(control["id"])
            continue
        basis = control["scope_basis"]
        target = basis["target"]
        target_span = basis["target_source"]
        scope_kind = basis["kind"]
        if scope_kind == "current_unit":
            valid = (target is None and target_span is None
                     and _current_unit_scope_speech(text, control["kind"]))
        else:
            valid = bool(
                isinstance(target, str) and target and target_span
                and target_span["source_id"] == span["source_id"]
                and _source_matches(target_span, sources, root=True)
                and span["start"] <= target_span["start"] < target_span["end"] <= span["end"]
                and sentence[0] <= target_span["start"] < target_span["end"] <= sentence[1]
            )
            if valid and scope_kind in {"exact", "directory"}:
                valid = (source["text"].encode("utf-8")[
                    target_span["start"]:target_span["end"]
                ].decode("utf-8") == target)
                if valid:
                    raw = source["text"].encode("utf-8")
                    valid = _explicit_target_speech(
                        raw[span["start"]:target_span["start"]].decode("utf-8"),
                        raw[target_span["end"]:span["end"]].decode("utf-8"),
                        control["kind"],
                    )
        if not valid:
            errors.append(control["id"])
            continue
        eligible = {
            key: req for key, req in requirements.items()
            if req["unit"] == control_unit and _scope_open(req, control["seq"])
            # Ordinary work controls never cancel proof, prohibition, Goal,
            # or adopted release contracts.
            and req["kind"] == "execution"
            and states.get(key) != "cancelled"
            and _source_matches(req["source"], sources, root=True)
        }
        if any(req["unit"] == control_unit and req["kind"] == "execution"
               and req.get("superseded_at_seq") == control["seq"]
               for req in requirements.values()):
            errors.append(control["id"])
            continue  # Same event sequence has no proved intra-root ordering.
        if scope_kind == "current_unit" and _subjectless_compound_persistence(text):
            prior = source["text"].encode("utf-8")[:span["start"]].decode("utf-8")
            if (not all(req["source"]["source_id"] == source["id"]
                        and req["seq"] == control["seq"] for req in eligible.values())
                    or not _single_root_task_scope(prior, list(eligible.values()))):
                errors.append(control["id"])
                continue
        if scope_kind == "current_unit":
            selected = eligible
            # The immutable root's unit is the adapter's receipt-time active
            # selection. Other pending units do not defeat that selection;
            # the adapter must replay its whole at-seq ledger and cannot use
            # this one projection to attest catalog completeness by itself.
        elif scope_kind == "exact":
            selected = {key: req for key, req in eligible.items() if req["target"] == target}
        elif scope_kind == "directory":
            selected = {key: req for key, req in eligible.items()
                        if req["target"].startswith(target.rstrip("/") + "/")}
        elif scope_kind == "action_class":
            noun = source["text"].encode("utf-8")[
                target_span["start"]:target_span["end"]
            ].decode("utf-8")
            parsed = _action_class_scope_speech(text, control["kind"])
            valid = bool(target == "test_verify" and parsed and parsed[0] == noun
                         and span["start"] + len(text[:parsed[1]].encode("utf-8"))
                         == target_span["start"])
            selected = {key: req for key, req in eligible.items()
                        if req["action"] == target} if valid else {}
            if noun.startswith(("这项", "该项")) and len(selected) != 1:
                valid = False
        elif scope_kind == "parent_task":
            noun = source["text"].encode("utf-8")[
                target_span["start"]:target_span["end"]
            ].decode("utf-8")
            parents = {key: req for key, req in eligible.items()
                       if req["action"] == "local_edit"
                       and any(child["parent_id"] == key for child in eligible.values())}
            if noun in {"这项修复", "该项修复"}:
                grammar = bool(re.fullmatch(
                    r"\s*(?:(?:请|请先|先)\s*)?(?:暂停|搁置|取消|撤销|继续)\s*"
                    + re.escape(noun) + r"\s*[。.!！]?\s*", text,
                ))
            else:
                grammar = bool(
                    control["kind"] == "persistence"
                    and re.fullmatch(r"(?:本轮|这轮|当前).{1,48}(?:修复|修改).{0,24}(?:测试|验证)", noun)
                    and re.fullmatch(r"\s*(?:(?:请|请先)\s*)?(?:持续|继续|一直)(?:完成|推进|执行|处理)\s*"
                                     + re.escape(noun)
                                     + r"\s*[,，]?\s*(?:直到|直至)(?:当前|本轮|这轮)"
                                     r"(?:任务|工作|事项)(?:完成|结束)\s*[。.!！]?\s*", text)
                )
                parents = {key: req for key, req in parents.items()
                           if req["source"]["source_id"] == span["source_id"]}
            valid = bool(grammar and len(parents) == 1 and target in parents)
            if valid:
                selected = {target: parents[target]}
                while True:
                    children = {key: req for key, req in eligible.items()
                                if req["required"] and req["parent_id"] in selected}
                    children = {key: req for key, req in children.items() if key not in selected}
                    if not children:
                        break
                    selected.update(children)
            else:
                selected = {}
        else:
            valid = False
            selected = {}
        if not valid:
            errors.append(control["id"])
            continue
        refs = control["controlled_requirements"]
        if not refs or len({ref["requirement_id"] for ref in refs}) != len(refs):
            errors.append(control["id"])
            continue
        ref_ids = {ref["requirement_id"] for ref in refs}
        if ref_ids != set(selected):
            errors.append(control["id"])
            continue
        for ref in refs:
            req = selected[ref["requirement_id"]]
            selected_at_receipt: set[str] = set()
            if req["target_origin"]["constraint_kind"] == "work_unit":
                for fact in facts.values():
                    if (fact["kind"] != "readiness" or fact["outcome"] != "success"
                            or fact["requirement_id"] != req["id"]
                            or fact["seq"] > control["seq"]):
                        continue
                    call = sources.get(fact["call_source_id"])
                    result = sources.get(fact["source_id"])
                    if (call and result and call["kind"] == "host_call"
                            and result["kind"] == "host_result"
                            and call["seq"] < result["seq"] <= control["seq"]
                            and call["target"] == fact["target"]
                            and call["target_kind"] == req["target_origin"]["subject_kind"]):
                        selected_at_receipt.add(fact["target"])
            if (
                ref["unit"] != req["unit"] or ref["revision"] != req["revision"]
                or ref["source_id"] != req["source"]["source_id"]
                or ref["seq"] != req["seq"]
                or (ref["target"] is None and (
                    scope_kind in {"exact", "directory"}
                    or req["target_origin"]["constraint_kind"] != "work_unit"
                    or bool(selected_at_receipt)))
                or (ref["target"] is not None and ref["target"] != req["target"])
                or (req["target_origin"]["constraint_kind"] == "work_unit"
                    and (len(selected_at_receipt) > 1
                         or (bool(selected_at_receipt) != (ref["target"] is not None))
                         or (selected_at_receipt and ref["target"] not in selected_at_receipt)))
                or ref["scope_sha256"] != req["scope_sha256"]
                or (req["seq"] == control["seq"]
                    and req["source"]["source_id"] != span["source_id"])
            ):
                valid = False
                break
        if not valid:
            errors.append(control["id"])
            continue
        represented.add(span["source_id"])
        for key in selected:
            prior = states.get(key, "ordinary")
            if control["kind"] == "cancel":
                states[key] = "cancelled"
            elif control["kind"] == "pause":
                states[key] = ("persistent_paused" if prior in
                               {"persistent", "persistent_paused"} else "paused")
            elif control["kind"] == "resume":
                if prior in {"paused", "persistent_paused"}:
                    states[key] = "persistent" if prior == "persistent_paused" else "ordinary"
                    resumed.add(key)
            elif control["kind"] == "persistence" and prior != "cancelled":
                states[key] = "persistent"
    return states, errors, represented, resumed


def project(snapshot: dict) -> dict:
    """Compute predicates/Stop diagnostics, never tool permission or effects."""
    validate_snapshot(snapshot)
    canonical_bytes(snapshot)
    if snapshot.get("schema") != SCHEMA:
        raise ValueError("unsupported_core_schema")
    watermark = snapshot["as_of"]
    unit, revision = snapshot["unit"], snapshot["revision"]
    sources = _index(snapshot["sources"], watermark)
    for source in sources.values():
        if source.get("target") is not None and source["kind"] != "host_call":
            raise ValueError("selection_target_requires_host_call")
        if source.get("origin_root_source_id") is not None:
            origin = sources.get(source["origin_root_source_id"])
            if (source["kind"] != "host_call" or origin is None
                    or origin["kind"] != "root" or origin["unit"] != source["unit"]
                    or origin["seq"] > source["seq"]
                    or origin["turn"] != source["turn"]):
                raise ValueError("host_call_origin_root_mismatch")
        if (source.get("target") is None) != (source.get("target_kind") is None):
            raise ValueError("selection_target_kind_pair_required")
        if (source.get("locator_base") is not None or source.get("locator_flavor") is not None) and source["kind"] != "root":
            raise ValueError("locator_base_requires_root")
        if (source.get("locator_base") is None) != (source.get("locator_flavor") is None):
            raise ValueError("locator_base_flavor_pair_required")
        if source["kind"] == "root":
            text = source["text"]
            if (
                text is None
                or len(text.encode("utf-8")) != source["byte_length"]
                or hashlib.sha256(text.encode("utf-8")).hexdigest() != source["sha256"]
            ):
                raise ValueError("root_source_identity_mismatch")
    unit_rows = {u["id"]: u for u in snapshot["units"]}
    if len(unit_rows) != len(snapshot["units"]) or unit not in unit_rows:
        raise ValueError("unit_identity_invalid")
    for row in unit_rows.values():
        source = sources.get(row["source_id"])
        if not source or source["kind"] != "root" or source["unit"] != row["id"]:
            raise ValueError("unit_source_invalid")
        visited = {row["id"]}
        parent = row["parent_id"]
        while parent is not None:
            if parent in visited or parent not in unit_rows:
                raise ValueError("unit_parent_invalid")
            visited.add(parent)
            parent = unit_rows[parent]["parent_id"]
    units = {unit}
    while True:
        added = {
            key
            for key, row in unit_rows.items()
            if row["required"] and row["parent_id"] in units
        } - units
        if not added:
            break
        units.update(added)
    requirements = _index(snapshot["requirements"], watermark)
    active_root_ids = {
        key for key, source in sources.items()
        if source["kind"] == "root" and source["unit"] in units
        and source["revision"] == revision
    } | {
        req["source"]["source_id"] for req in requirements.values()
        if req["unit"] in units
    } | {
        control["source"]["source_id"] for control in snapshot.get("root_controls", [])
        if control["seq"] <= watermark
        and control["source"]["source_id"] in sources
        and sources[control["source"]["source_id"]]["unit"] in units
    }
    coverage_errors = []
    unknown_coverage = []
    for key, source in sources.items():
        if source["kind"] != "root" or key not in active_root_ids:
            continue
        spans = sorted(
            (c for c in snapshot["coverage"] if c["source"]["source_id"] == key),
            key=lambda c: c["source"]["start"],
        )
        cursor = 0
        for coverage in spans:
            span = coverage["source"]
            if not _source_matches(span, sources, root=True) or span["start"] != cursor:
                coverage_errors.append(key)
            cursor = span["end"]
            if coverage["kind"] == "unknown":
                unknown_coverage.append(key)
        if cursor != source["byte_length"]:
            coverage_errors.append(key)
    facts = _index(snapshot["facts"], watermark)
    for req in requirements.values():
        keys = ("superseded_at_seq", "supersession_source_id",
                "superseded_by_requirement_id")
        present = [key in req for key in keys]
        if any(present) and not all(present):
            raise ValueError("supersession_identity_incomplete")
        if not all(present):
            continue
        end = req["superseded_at_seq"]
        if end <= req["seq"] or req["status"] != "superseded":
            raise ValueError("supersession_interval_invalid")
        if end > watermark:
            continue
        source = sources.get(req["supersession_source_id"])
        successor = requirements.get(req["superseded_by_requirement_id"])
        if (source is None or source["kind"] != "root"
                or source["unit"] != req["unit"] or source["seq"] != end
                or successor is None or successor["unit"] != req["unit"]
                or successor["seq"] != end
                or successor["source"]["source_id"] != source["id"]
                or successor["revision"] <= req["revision"]):
            raise ValueError("supersession_source_mismatch")
    current = {
        key: row
        for key, row in requirements.items()
        if row["unit"] in units and _scope_open(row, watermark)
    }
    if any(
        r["parent_id"] is not None and r["parent_id"] not in requirements
        for r in current.values()
    ):
        raise ValueError("requirement_parent_missing")
    valid_facts: dict[str, dict] = {}
    for key, fact in facts.items():
        source = sources.get(fact["source_id"])
        if not source or source["seq"] > fact["seq"]:
            continue
        if (source["unit"], source["revision"]) != (fact["unit"], fact["revision"]):
            continue
        if fact["kind"] in {"action_event", "state_outcome", "readiness"}:
            call = sources.get(fact["call_source_id"])
            if (
                not call
                or call["kind"] != "host_call"
                or source["kind"] != "host_result"
            ):
                continue
            if not call["call_id"] or call["call_id"] != source["call_id"]:
                continue
            # A result may describe a different object from the call that
            # produced it.  Result prose or a fact's requirement_id cannot
            # turn that call into evidence for the requested target.
            if call.get("target") != fact["target"] or call.get("target_kind") is None:
                continue
            origin_id = call.get("origin_root_source_id")
            fact_requirement = current.get(fact["requirement_id"])
            if (origin_id is not None and fact_requirement is not None
                    and fact_requirement["kind"] != "constraint"
                    and sources[origin_id]["seq"] <
                    sources[fact_requirement["source"]["source_id"]]["seq"]):
                continue
            if call["seq"] >= source["seq"] or (call["unit"], call["revision"]) != (
                fact["unit"],
                fact["revision"],
            ):
                continue
        elif source["kind"] != {
            "state_outcome": "host_result",
            "delivery": "final_delivery",
            "readiness": "host_result",
            "external_operation": "external_lifecycle",
        }.get(fact["kind"]):
            continue
        valid_facts[key] = fact
    historical_effect_facts = dict(valid_facts)
    invalidated = {
        fid
        for f in valid_facts.values()
        for fid in f["invalidates"]
        if fid in valid_facts and valid_facts[fid]["seq"] < f["seq"]
    }
    valid_facts = {key: f for key, f in valid_facts.items() if key not in invalidated}
    conditions = {c["id"]: c for c in snapshot["conditions"]}
    if len(conditions) != len(snapshot["conditions"]):
        raise ValueError("duplicate_condition")
    released = set()
    for key, condition in conditions.items():
        req = current.get(condition["requirement_id"])
        if not req or not _source_matches(condition["source"], sources, root=True):
            continue
        if condition["source"]["source_id"] != req["source"]["source_id"]:
            continue
        if condition["status"] == "released" and any(
            fid in valid_facts
            and valid_facts[fid]["condition_id"] == key
            and valid_facts[fid]["requirement_id"] == req["id"]
            and valid_facts[fid]["outcome"] == "success"
            for fid in condition["fact_ids"]
        ):
            released.add(key)
    historical_explained = {
        key: row for key, row in requirements.items()
        if row["unit"] in units and row["status"] == "superseded"
        and row.get("superseded_at_seq") is not None
        and row["superseded_at_seq"] <= watermark
        and _source_matches(row["source"], sources, root=True)
    }
    for coverage in snapshot["coverage"]:
        span = coverage["source"]
        source = sources.get(span["source_id"])
        if (
            not source
            or source["unit"] not in units
            or coverage["kind"] != "interpreted"
        ):
            continue
        covered = sorted(
            [(r["source"]["start"], r["source"]["end"])
             for r in (*current.values(), *historical_explained.values())
             if r["source"]["source_id"] == span["source_id"]
             and r["source"]["start"] < span["end"]
             and r["source"]["end"] > span["start"]]
            + [(c["source"]["start"], c["source"]["end"])
               for c in snapshot.get("root_controls", [])
               if c["seq"] <= watermark
               and c["source"]["source_id"] == span["source_id"]
               and _source_matches(c["source"], sources, root=True)]
        )
        cursor = span["start"]
        raw = source["text"].encode("utf-8")
        separators = " \t\r\n,，。.!?？；;：:、"
        for start, end in covered:
            if start > cursor and raw[cursor:start].decode("utf-8").strip(separators):
                break
            cursor = max(cursor, end)
        if cursor < span["end"] and raw[cursor:span["end"]].decode("utf-8").strip(separators):
            coverage_errors.append(span["source_id"])
    predicates: dict[str, str] = {}
    delivery: list[str] = []
    for key, req in current.items():
        if not _scope_open(req, watermark):
            predicates[key] = ("legacy_review" if req.get("superseded_at_seq") is None
                               else "superseded")
            continue
        source = sources.get(req["source"]["source_id"])
        source_valid = (
            _source_matches(req["source"], sources, root=True)
            and source["unit"] == req["unit"]
            and source["revision"] == req["revision"]
        )
        origin = req["target_origin"]
        constraint = origin["root_constraint"]
        target_span = origin["root_constraint_source"]
        target_source = sources.get(target_span["source_id"])
        root_target_valid = bool(
            _source_matches(target_span, sources, root=True)
            and target_source["unit"] == req["unit"]
            and target_source["revision"] == req["revision"]
            and target_source["text"]
            .encode("utf-8")[target_span["start"] : target_span["end"]]
            .decode("utf-8")
            == constraint
        )
        constraint_kind = origin["constraint_kind"]
        resolved_constraint = origin.get("resolved_constraint")
        relative_constraint = resolved_constraint is not None
        base = target_source.get("locator_base") if target_source else None
        flavor = target_source.get("locator_flavor") if target_source else None
        relative_literal = (
            constraint[:-1] if constraint_kind == "directory" and constraint.endswith("/")
            else constraint
        )
        subject_kind = origin["subject_kind"]
        filesystem_subject = subject_kind == "filesystem"
        inherently_filesystem = (
            req["action"] in {"local_edit", "local_commit", "remote_push"}
            or any(f["requirement_id"] == key and f["kind"] == "readiness"
                   and f["predicate"] == "file_exists" for f in valid_facts.values())
        )
        if inherently_filesystem and not filesystem_subject:
            root_target_valid = False
        target_is_absolute = bool(
            (req["target"].startswith("/") and not req["target"].startswith("//")
             and posixpath.normpath(req["target"]) == req["target"])
            or re.fullmatch(r"[A-Za-z]:[\\/][^:]+", req["target"])
        )
        if relative_constraint and not filesystem_subject:
            root_target_valid = False
        if relative_constraint:
            valid_relative = bool(
                flavor == "posix" and isinstance(base, str) and base.startswith("/")
                and posixpath.normpath(base) == base
                and not base.startswith("//")
                and not constraint.startswith(("/", "\\"))
                and ":" not in relative_literal and "\\" not in relative_literal
                and not relative_literal.startswith(("~", "$", "%"))
                and not constraint.endswith("//")
                and all(part not in {"", ".", ".."} for part in relative_literal.split("/"))
                and posixpath.join(base, relative_literal) == resolved_constraint
                and constraint_kind in {"exact", "directory"}
            )
            if not valid_relative:
                root_target_valid = False
        elif constraint_kind in {"exact", "directory"} and filesystem_subject and not (
            constraint.startswith("/") or (len(constraint) >= 3 and constraint[1:3] in {":\\", ":/"})
        ):
            root_target_valid = False
        selection_source_id = origin["selection_source_id"]
        selection = sources.get(selection_source_id) if selection_source_id else None
        selected_by_host = bool(
            selection
            and selection["kind"] == "host_call"
            and selection.get("target") == req["target"]
            and selection.get("target_kind") == subject_kind
            and selection["unit"] == req["unit"]
            and selection["revision"] == req["revision"]
            and source is not None
            and source["seq"] <= selection["seq"] <= watermark
            and any(
                fact["call_source_id"] == selection_source_id
                and fact["target"] == req["target"]
                and fact["requirement_id"] == req["id"]
                for fact in valid_facts.values()
            )
        )
        if constraint_kind == "exact":
            root_target_allowed = (
                resolved_constraint == req["target"] and (selected_by_host or req["kind"] == "constraint")
                if relative_constraint else constraint == req["target"]
            )
        elif constraint_kind == "directory":
            directory = resolved_constraint if relative_constraint else constraint.rstrip("/")
            root_target_allowed = bool(
                directory and req["target"].startswith(directory + "/")
                and ".." not in req["target"].split("/")
                and ((selected_by_host or req["kind"] == "constraint")
                     if relative_constraint else constraint.endswith("/"))
            )
        else:
            root_target_allowed = selected_by_host
        typed_host_conflict = any(
            f["requirement_id"] == key and f["target"] == req["target"]
            and f["kind"] in {"readiness", "action_event", "state_outcome"}
            and sources[f["call_source_id"]].get("target_kind") != subject_kind
            for f in valid_facts.values()
        )
        target_valid = (
            root_target_valid
            and not typed_host_conflict
            and (not filesystem_subject or target_is_absolute)
            and (not filesystem_subject or not (constraint_kind in {"exact", "directory"} and not relative_constraint and not target_is_absolute))
            and origin["resolved"] == req["target"]
            and (origin["observed"] is None if req["kind"] == "constraint"
                 else origin["observed"] == req["target"])
            and root_target_allowed
            and (constraint_kind != "work_unit" or selected_by_host)
            and (origin["implementation_choice"] is None if req["kind"] == "constraint"
                 else origin["implementation_choice"] == req["target"])
            and (origin["host_selection"] is None if req["kind"] == "constraint"
                 else origin["host_selection"] == req["target"])
        )
        if req["status"] == "legacy_review" or not source_valid or not target_valid:
            predicates[key] = "legacy_review"
            continue
        if req["kind"] == "constraint":
            mutation_facts = [f for f in historical_effect_facts.values() if (
                f["requirement_id"] == key
                and f["unit"] == req["unit"]
                and f["revision"] == req["revision"]
                and f["target"] == req["target"]
                and f["kind"] == "action_event"
                and f["predicate"] == "mutation_applied"
                and f["outcome"] == "success"
                and sources[f["call_source_id"]].get("target") == req["target"]
                and sources[f["call_source_id"]].get("target_kind") == subject_kind
            )] if req["predicate"] == "no_mutation" else []
            root_seq = sources[req["source"]["source_id"]]["seq"]
            def origin_bound(f: dict) -> int:
                call = sources[f["call_source_id"]]
                origin_id = call.get("origin_root_source_id")
                return sources[origin_id]["seq"] if origin_id is not None else call["seq"]

            violated = any(
                origin_bound(f) >= root_seq
                and sources[f["call_source_id"]]["seq"] > root_seq
                and f["seq"] <= watermark for f in mutation_facts
            )
            crossing = any(
                origin_bound(f) < root_seq <= f["seq"]
                or sources[f["call_source_id"]]["seq"] <= root_seq <= f["seq"]
                for f in mutation_facts
            )
            predicates[key] = (
                "constraint_violated" if violated else
                "constraint_unresolved" if crossing else "constraint_active"
            )
            continue
        matched = [
            f
            for f in valid_facts.values()
            if (f["unit"], f["revision"], f["target"], f["predicate"])
            == (req["unit"], req["revision"], req["target"], req["predicate"])
            and f["requirement_id"] == key
            and f["kind"] == req["evidence_kind"]
            and (f["kind"] == "delivery" or sources[f["call_source_id"]].get("target_kind") == subject_kind)
            and f["seq"] >= req["seq"]
        ]
        matched.sort(key=lambda f: f["seq"])
        matched = matched[-1:] if matched else []
        matched = [f for f in matched if f["outcome"] == "success"]
        if req["kind"] == "information":
            matched = [
                f
                for f in matched
                if f["kind"] == "delivery"
                and sources[f["source_id"]]["turn"] == snapshot["turn"]
            ]
            if matched:
                delivery.append(key)
        else:
            matched = [
                f for f in matched if f["kind"] in {"action_event", "state_outcome"}
            ]
        predicates[key] = (
            "satisfied" if matched and req["kind"] != "unknown" else "insufficient"
        )
    actions: list[dict] = []
    rejected: list[dict] = []
    for candidate in snapshot["actions"]:
        reason = "action_basis_insufficient"
        req = current.get(candidate["requirement_id"])
        if candidate["seq"] > watermark:
            continue
        valid = bool(
            req
            and _scope_open(req, watermark)
            and candidate["schema"] == "current-action-basis/v1"
            and candidate["state"] == "current"
            and candidate["owner"] == "assistant"
            and candidate["action"] not in {"generic_work", "unknown"}
            and predicates[req["id"]] == "insufficient"
            and req["kind"] in {"execution", "proof"}
            and _source_matches(candidate["source"], sources, root=True)
            and candidate["source"] == req["source"]
            and all(
                candidate[k] == req[k]
                for k in ("unit", "revision", "scope_sha256", "target", "predicate")
            )
            and candidate["seq"] >= req["seq"]
            and all(cid in released for cid in req["condition_ids"])
        )
        if valid:
            relation = candidate["relation"]
            valid = relation == "direct" and candidate["action"] == req["action"]
            # Substep admissibility is explicit in the root requirement predicate,
            # never inferred from a broad resume or caller-supplied owner.
            valid |= (
                relation == "verification_substep"
                and req["predicate"] == "test_passed"
                and candidate["action"] == "test_verify"
            )
            valid |= (
                relation == "readback_substep"
                and req["predicate"] == "state_matches"
                and candidate["action"] == "readback"
            )
        ready = candidate["readiness_fact_ids"]
        valid = (
            valid
            and bool(ready)
            and all(
                fid in valid_facts
                and valid_facts[fid]["kind"] == "readiness"
                and valid_facts[fid]["outcome"] == "success"
                and valid_facts[fid]["requirement_id"] == candidate["requirement_id"]
                and (
                    valid_facts[fid]["unit"],
                    valid_facts[fid]["revision"],
                    valid_facts[fid]["target"],
                )
                == (candidate["unit"], candidate["revision"], candidate["target"])
                for fid in ready
            )
        )
        if valid:
            actions.append(
                {
                    k: candidate[k]
                    for k in (
                        "requirement_id",
                        "unit",
                        "revision",
                        "action",
                        "target",
                        "predicate",
                        "owner",
                        "source",
                        "seq",
                    )
                }
            )
        else:
            rejected.append(
                {"requirement_id": candidate["requirement_id"], "reason": reason}
            )
    intent = snapshot["intent"]
    intent_span = intent["source"]
    intent_source = sources.get(intent_span["source_id"]) if intent_span else None
    intent_valid = bool(
        intent_span
        and _source_matches(intent_span, sources, root=True)
        and intent_source["unit"] == unit
        and intent_source["revision"] == revision
    )
    intent_text = ""
    if intent_valid:
        intent_text = (
            intent_source["text"]
            .encode("utf-8")[intent_span["start"] : intent_span["end"]]
            .decode("utf-8")
            .strip()
        )
    # Reuse the accepted recognizers without adding words or requiring a
    # rewritten prompt. Source spans still require a current root binding.
    from pathlib import Path

    rules = load_strict(
        (
            Path(__file__).resolve().parent.parent / "assets/core-intent-v2.json"
        ).read_text(encoding="utf-8")
    )["patterns"]
    control_states, control_errors, control_sources, control_resumed = (
        _fold_root_controls(snapshot, sources, requirements,
                            historical_effect_facts, units, watermark, rules)
    )
    kept_actions = []
    for candidate in actions:
        control_state = control_states.get(candidate["requirement_id"])
        if control_state in {"paused", "persistent_paused", "cancelled"}:
            rejected.append({"requirement_id": candidate["requirement_id"],
                             "reason": "root_control_" + control_state})
        else:
            kept_actions.append(candidate)
    actions = kept_actions
    # The legacy intent label is a speech-act hint only. It cannot attach an
    # earlier persistence phrase to arbitrary later requirements.
    persistence = any(state in {"persistent", "persistent_paused"}
                      and key in requirements and _scope_open(requirements[key], watermark)
                      for key, state in control_states.items())
    persistence_ready = any(
        control_states.get(a["requirement_id"]) == "persistent" for a in actions
    )
    old_resume = bool(
        intent_valid and intent["kind"] in {"resume", "persistence_and_resume"}
        and _control_speech(intent_text, "resume", rules)
        and any(current[a["requirement_id"]]["seq"] <= intent_source["seq"]
                for a in actions)
    )
    resumed = bool(old_resume or any(a["requirement_id"] in control_resumed
                                      for a in actions))
    external = sorted(
        {
            f["operation_id"]
            for f in valid_facts.values()
            if f["unit"] in units
            and f["kind"] == "external_operation"
            and f["outcome"] == "unknown"
            and f["operation_id"]
            and f["requirement_id"] in current
            and f["revision"] == current[f["requirement_id"]]["revision"]
            and f["condition_id"] in conditions
            and f["condition_id"] not in released
            and conditions[f["condition_id"]]["kind"] == "external_dependency"
            and conditions[f["condition_id"]]["operation_id"] == f["operation_id"]
            and f["condition_id"] in current[f["requirement_id"]]["condition_ids"]
        }
    )
    missing = sorted(
        k
        for k, r in current.items()
        if r["required"] and _scope_open(r, watermark)
        and control_states.get(k) != "cancelled"
        and predicates[k] not in {"satisfied", "constraint_active"}
    )
    # A parent cannot certify around required children, nor can an empty
    # interpretation certify an unrepresented root source.
    represented = ({r["source"]["source_id"] for r in current.values()}
                   | {r["source"]["source_id"] for r in historical_explained.values()}
                   | control_sources)
    missing_sources = active_root_ids - represented
    certifiable = not (
        missing or coverage_errors or unknown_coverage or missing_sources
        or control_errors
    )
    reasons = []
    if snapshot["completion_claim"] and not certifiable:
        reasons.append("wrong_whole_completion")
    if snapshot["proof_violation"]:
        reasons.append("explicit_proof_unsatisfied")
    if persistence_ready:
        reasons.append("explicit_user_persistence")
    if resumed:
        reasons.append("resume_with_actionable_work")
    correction = bool(
        reasons and snapshot["corrections_used"] == 0 and snapshot["progress_changed"]
    )
    return {
        "schema": "core-state/v2",
        "unit": unit,
        "revision": revision,
        "as_of": watermark,
        "coverage": snapshot["coverage"],
        "predicates": predicates,
        "delivery": sorted(delivery),
        "facts": sorted(valid_facts),
        "current_actions": actions,
        "rejected_actions": rejected,
        "unmet_requirements": missing,
        "certifiable": certifiable,
        "coverage_errors": sorted(set(coverage_errors)),
        "unknown_coverage": sorted(set(unknown_coverage)),
        "target_origins": {k: r["target_origin"] for k, r in current.items()},
        "root_control_states": dict(sorted(control_states.items())),
        "root_control_errors": sorted(control_errors),
        "conditions": {
            k: "released" if k in released else "pending" for k in conditions
        },
        "explicit_user_persistence": persistence,
        "resume_with_actionable_work": resumed,
        "registered_external_operations": external,
        "ordinary_path_interference": False,
        "stop": "bounded_correction"
        if correction
        else "typed_wait"
        if external and not actions
        else "ordinary_end",
        "reason_codes": reasons,
        "correction_count": int(correction),
        "goal_complete_allowed": not snapshot["goal_contract_adopted"] or certifiable,
        "release_state": snapshot["release_state"],
    }


if __name__ == "__main__":
    import sys

    print(canonical_bytes(project(load_strict(sys.stdin.read()))).decode("utf-8"))
