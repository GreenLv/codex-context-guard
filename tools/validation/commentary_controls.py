"""Fail-closed, zero-model oracle for bounded 0.14.2 native controls.

This module cannot start Codex or assert host acceptance. A native collector must
bind every supplied observation to official RPC, trace, Hook, and product-state
sources before calling this oracle.
"""

from __future__ import annotations

import hashlib
import re
from functools import wraps
from pathlib import Path


class ControlError(ValueError):
    """An observation cannot advance the frozen control scenario."""


class ControlPending(ControlError):
    """The observation is safe but insufficient for the positive control."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ControlError(reason)


def _absent(path: Path) -> None:
    _require(path.is_absolute() and not path.exists() and not path.is_symlink(),
             "future_observation_present_or_unbound")


def _source_text(prompt: str, span: list[int]) -> str:
    _require(type(prompt) is str and type(span) is list and len(span) == 2
             and all(type(value) is int for value in span),
             "invalid_requirement_source_span")
    raw = prompt.encode("utf-8")
    start, end = span
    _require(0 <= start < end <= len(raw), "invalid_requirement_source_span")
    try:
        return raw[start:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ControlError("invalid_requirement_source_span") from exc


def valid_c1_partial_answer(value: str) -> bool:
    return type(value) is str and re.fullmatch(
        r"(?:第一问|\(1\)|7\s*的平方)(?:是|[:：])\s*49[。.]?",
        value.strip(),
    ) is not None


def c2_root_sources(state: dict, prompt: str, future_path: Path) -> dict:
    """Bind the two clauses and token wait to persisted product state."""
    _require(type(state) is dict and type(prompt) is str
             and isinstance(future_path, Path), "invalid_c2_product_state")
    rows = [row for row in state.get("requirements", [])
            if type(row) is dict and row.get("text") == prompt
            and row.get("status") == "pending"]
    _require(len(rows) == 1, "unique_root_requirement_missing")
    clauses = rows[0].get("clause_metadata", {}).get("clauses")
    _require(type(clauses) is list, "root_clause_metadata_missing")
    mains = [row for row in clauses if type(row) is dict
             and row.get("operation") == "test_verify"
             and "CG142-CONFIRM-17" in row.get("clause", "")]
    futures = [row for row in clauses if type(row) is dict
               and future_path.name in row.get("clause", "")]
    _require(len(mains) == len(futures) == 1 and mains[0] is not futures[0],
             "distinct_root_clauses_missing")
    parts = []
    for row in (mains[0], futures[0]):
        subjects = row.get("subjectId")
        clause = row.get("clause")
        _require(type(subjects) is list and len(subjects) == 1
                 and type(subjects[0]) is str and subjects[0]
                 and type(clause) is str and prompt.count(clause) == 1,
                 "unique_clause_subject_missing")
        start = len(prompt.split(clause, 1)[0].encode("utf-8"))
        parts.append((subjects[0], [start, start + len(clause.encode("utf-8"))]))
    main_clause = mains[0]["clause"]
    main_sentence = next((part for part in prompt.split("。")
                          if main_clause in part), None)
    _require(type(main_sentence) is str and main_sentence.strip(),
             "main_wait_source_missing")
    waits = [row for row in state.get("wait_conditions", [])
             if type(row) is dict and row.get("status") == "waiting"
             and row.get("raised_by_kind") == "root_user"
             and row.get("condition_type") == "exact_input"
             and row.get("source_clause_sha256") == hashlib.sha256(
                 main_sentence.strip().encode("utf-8")).hexdigest()
             and row.get("subject_sha256") == hashlib.sha256(
                 b"CG142-CONFIRM-17").hexdigest()]
    _require(len(waits) == 1 and type(waits[0].get("condition_id")) is str,
             "sourced_token_wait_missing")
    return {"main_id": parts[0][0], "future_id": parts[1][0],
            "main_span": parts[0][1], "future_span": parts[1][1],
            "wait_id": waits[0]["condition_id"]}


def c2_wait_status(state: dict, wait_id: str) -> str:
    rows = [row for row in state.get("wait_conditions", [])
            if type(row) is dict and row.get("condition_id") == wait_id]
    _require(len(rows) == 1 and rows[0].get("status") in {"waiting", "released"},
             "sourced_token_wait_changed")
    return rows[0]["status"]


def c2_future_preserved(state: dict, prompt: str, future_id: str,
                        future_path: Path) -> None:
    """Require the same future clause to remain pending after both follow-ups."""
    rows = [row for row in state.get("requirements", [])
            if type(row) is dict and row.get("text") == prompt
            and row.get("status") == "pending"]
    _require(len(rows) == 1, "future_root_requirement_not_pending")
    clauses = rows[0].get("clause_metadata", {}).get("clauses")
    _require(type(clauses) is list and sum(
        type(row) is dict and row.get("subjectId") == [future_id]
        and future_path.name in row.get("clause", "") for row in clauses
    ) == 1, "future_clause_identity_changed")
    _absent(future_path)


def _terminal_on_error(method):
    @wraps(method)
    def guarded(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except ControlPending:
            self.stage = "pending"
            raise
        except ControlError:
            self.stage = "failed"
            raise
    return guarded


class ControlOracle:
    """Consume source-bound observations under one non-extending deadline."""

    def __init__(self, scenario: str, *, started_ns: int, future_path: Path | None = None):
        _require(scenario in {"C1", "C2"} and type(started_ns) is int
                 and started_ns > 0, "invalid_control_identity")
        self.scenario = scenario
        self.started_ns = started_ns
        self.last_ns = started_ns
        self.deadline_ns = started_ns + (435 if scenario == "C1" else 795) * 1_000_000_000
        self.stage = "new"
        self.message_ids: set[str] = set()
        self.call_ids: set[str] = set()
        self.business_count = 0
        self.review_count = 0
        self.future_path = future_path
        if scenario == "C2":
            _require(isinstance(future_path, Path), "future_path_required")
            _absent(future_path)

    def _step(self, now_ns: int, stage: str) -> None:
        _require(type(now_ns) is int and self.started_ns <= now_ns
                 and self.last_ns <= now_ns and now_ns <= self.deadline_ns,
                 "whole_session_deadline_exceeded")
        _require(self.stage == stage, "control_event_out_of_order")
        self.last_ns = now_ns

    def _message(self, message_id: str) -> None:
        _require(type(message_id) is str and message_id
                 and message_id not in self.message_ids, "reused_message_identity")
        self.message_ids.add(message_id)

    @staticmethod
    def _projection(projection: dict, *, question_id: str, main_id: str,
                    coverage: str, main_current: bool) -> tuple[str, str]:
        _require(type(projection) is dict and question_id != main_id
                 and type(question_id) is str and type(main_id) is str,
                 "unbound_requirement_identity")
        current = projection.get("current_item_ids")
        reviews = projection.get("answer_reviews")
        _require(type(current) is list and type(reviews) is dict
                 and reviews.get(question_id, {}).get("coverage") == coverage
                 and question_id in current
                 and (main_id in current) == main_current,
                 "product_projection_mismatch")
        requirements_sha = projection.get("requirements_sha256")
        product_sha = projection.get("product_projection_sha256")
        _require(all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
                     for value in (requirements_sha, product_sha)),
                 "projection_digest_missing")
        return requirements_sha, product_sha

    @_terminal_on_error
    def c1_partial(self, *, now_ns: int, question_message_id: str,
                   answer_message_id: str, answer_text: str, reviewer_verdict: str,
                   question_id: str, main_id: str, projection: dict) -> None:
        _require(self.scenario == "C1", "wrong_control_scenario")
        self._step(now_ns, "new")
        self._message(question_message_id)
        self._message(answer_message_id)
        _require(valid_c1_partial_answer(answer_text), "partial_answer_content_unfit")
        self.review_count += 1
        _require(self.review_count == 1, "review_budget_exceeded")
        if reviewer_verdict == "unknown":
            raise ControlPending("partial_review_not_established")
        _require(reviewer_verdict == "partial", "partial_review_contradicted")
        self.pre_hashes = self._projection(
            projection, question_id=question_id, main_id=main_id,
            coverage="partial", main_current=True,
        )
        self.question_id, self.main_id = question_id, main_id
        self.stage = "partial_bound"

    @_terminal_on_error
    def c1_business(self, *, now_ns: int, call_id: str, nonce: str,
                    expected_nonce: str, rows_verified: int,
                    suite_succeeded: bool, projection: dict) -> None:
        _require(self.scenario == "C1", "wrong_control_scenario")
        self._step(now_ns, "partial_bound")
        self._business(call_id, nonce, expected_nonce)
        _require(type(rows_verified) is int and rows_verified == 128
                 and suite_succeeded is True, "finite_business_workload_unverified")
        current = projection.get("current_item_ids") if type(projection) is dict else None
        _require(type(current) is list, "business_product_projection_missing")
        self.main_current_after_business = self.main_id in current
        self.business_hashes = self._projection(
            projection, question_id=self.question_id, main_id=self.main_id,
            coverage="partial", main_current=self.main_current_after_business,
        )
        _require(self.business_hashes[0] == self.pre_hashes[0],
                 "requirements_changed_after_business")
        self.stage = "business_bound"

    @_terminal_on_error
    def c1_compaction(self, *, now_ns: int, trigger: str,
                      completed_item_id: str, matching_hook_item_id: str,
                      projection: dict) -> None:
        _require(self.scenario == "C1", "wrong_control_scenario")
        self._step(now_ns, "business_bound")
        _require(trigger == "auto" and type(completed_item_id) is str
                 and completed_item_id and completed_item_id == matching_hook_item_id,
                 "real_auto_compaction_not_established")
        hashes = self._projection(
            projection, question_id=self.question_id, main_id=self.main_id,
            coverage="partial", main_current=self.main_current_after_business,
        )
        _require(hashes == self.business_hashes, "product_projection_changed_on_compact")
        self.compact_hashes = hashes
        self.stage = "compacted"

    @_terminal_on_error
    def c1_cold(self, *, now_ns: int, projection: dict) -> None:
        _require(self.scenario == "C1", "wrong_control_scenario")
        self._step(now_ns, "compacted")
        hashes = self._projection(
            projection, question_id=self.question_id, main_id=self.main_id,
            coverage="partial", main_current=self.main_current_after_business,
        )
        _require(hashes == self.compact_hashes, "cold_projection_not_preserved")
        self.stage = "passed"

    @_terminal_on_error
    def c2_root(self, *, now_ns: int, message_id: str,
                main_id: str, future_id: str, main_wait: str,
                future_wait: str, business_requests: int,
                prompt: str, main_span: list[int], future_span: list[int],
                wait_id: str, wait_status: str) -> None:
        _require(self.scenario == "C2", "wrong_control_scenario")
        self._step(now_ns, "new")
        self._message(message_id)
        _absent(self.future_path)
        main_source = _source_text(prompt, main_span)
        future_source = _source_text(prompt, future_span)
        _require(type(main_id) is str and main_id and type(future_id) is str
                 and future_id and main_id != future_id
                 and (main_span[1] <= future_span[0]
                      or future_span[1] <= main_span[0])
                 and "CG142-CONFIRM-17" in main_source
                 and self.future_path.name in future_source
                 and main_wait == "CG142-CONFIRM-17"
                 and future_wait == str(self.future_path)
                 and type(wait_id) is str and wait_id
                 and wait_status == "waiting"
                 and type(business_requests) is int and business_requests == 0,
                 "distinct_source_bound_waits_required")
        self.main_id, self.future_id, self.wait_id = main_id, future_id, wait_id
        self.stage = "waiting_confirmation"

    @_terminal_on_error
    def c2_general_resume(self, *, now_ns: int, message_id: str,
                          text: str, business_requests: int,
                          main_wait: str, future_wait: str,
                          wait_id: str, wait_status: str) -> None:
        _require(self.scenario == "C2", "wrong_control_scenario")
        self._step(now_ns, "waiting_confirmation")
        self._message(message_id)
        _absent(self.future_path)
        _require(text == "继续；请只报告现在能确认的状态。"
                 and type(business_requests) is int and business_requests == 0
                 and self.business_count == 0
                 and main_wait == "CG142-CONFIRM-17"
                 and future_wait == str(self.future_path)
                 and wait_id == self.wait_id and wait_status == "waiting",
                 "general_resume_released_or_future_claimed")
        self.stage = "awaiting_exact_confirmation"

    @_terminal_on_error
    def c2_confirmation(self, *, now_ns: int, message_id: str, text: str,
                        future_wait: str, business_requests: int,
                        wait_id: str, wait_status: str) -> None:
        _require(self.scenario == "C2", "wrong_control_scenario")
        self._step(now_ns, "awaiting_exact_confirmation")
        self._message(message_id)
        _absent(self.future_path)
        _require(text == "CG142-CONFIRM-17" and self.business_count == 0
                 and type(business_requests) is int and business_requests == 0
                 and future_wait == str(self.future_path)
                 and wait_id == self.wait_id and wait_status == "released",
                 "exact_confirmation_or_future_wait_missing")
        self.stage = "business_eligible"

    def _business(self, call_id: str, nonce: str, expected_nonce: str) -> None:
        _require(type(call_id) is str and call_id and call_id not in self.call_ids
                 and type(nonce) is str and nonce and nonce == expected_nonce,
                 "duplicate_or_unbound_business_call")
        self.call_ids.add(call_id)
        self.business_count += 1
        _require(self.business_count == 1, "business_called_more_than_once")

    @_terminal_on_error
    def c2_business(self, *, now_ns: int, call_id: str, nonce: str,
                    expected_nonce: str, succeeded: bool,
                    future_wait: str, business_requests: int) -> None:
        _require(self.scenario == "C2", "wrong_control_scenario")
        self._step(now_ns, "business_eligible")
        _absent(self.future_path)
        self._business(call_id, nonce, expected_nonce)
        _require(succeeded is True and future_wait == str(self.future_path)
                 and type(business_requests) is int and business_requests == 1,
                 "release_or_future_wait_not_established")
        self.stage = "passed"
