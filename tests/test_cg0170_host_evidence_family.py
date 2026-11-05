"""0.17.0 F02/F03: terminal evidence family regressions.

Covers the observed Desktop ``aggregated_output`` shape (F02) and the bounded
unrelated-record isolation (F03) around ``_host_transcript_items`` and
``host_terminal_result``. Identity, status, exit-code and input bindings keep
their rejections; only the authoritative output field and the oversized-row
handling change.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import context_guard as cg


class HostEvidenceFamilyTests(unittest.TestCase):
    """Synthetic transcripts shaped like the observed Host producer."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cg-0170-evidence-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(strict=True)
        self.home = self.root / "home"
        self.work = self.root / "work"
        self.work.mkdir()

    def transcript_path(self, name="synthetic.jsonl"):
        transcript = self.home / "sessions/2026/01/01" / name
        transcript.parent.mkdir(parents=True, exist_ok=True)
        return transcript

    def command_item(self, call_id, *, code=0, output=None, drop_stdout=False,
                     status=None, **overrides):
        item = {
            "type": "CommandExecution",
            "id": call_id,
            "command": (["pwsh.exe", "-Command", "echo sample"] if os.name == "nt"
                        else ["/bin/zsh", "-lc", "echo sample"]),
            "parsed_cmd": [{"type": "unknown", "cmd": "echo sample"}],
            "cwd": self.work.as_uri(),
            "exit_code": code,
            "status": status or ("completed" if code == 0 else "failed"),
        }
        if not drop_stdout:
            item["stdout"] = output
        return {**item, **overrides}

    def build(self, rows, *, cwd=None, call_id="synthetic-read",
              tool_input=None):
        transcript = self.transcript_path()
        transcript.write_bytes(
            ("\n".join(json.dumps(row) for row in rows) + "\n").encode("utf-8"))
        state = {"session": {"id": "synthetic-session",
                             "transcript_path": str(transcript)}}
        payload = {
            "session_id": "synthetic-session",
            "turn_id": "synthetic-turn",
            "transcript_path": str(transcript),
            "cwd": str(cwd or self.work),
            "tool_use_id": call_id,
            "tool_name": "Bash",
            "tool_input": tool_input or {"command": "echo sample"},
            "tool_response": "sample\n",
        }
        return state, payload

    def event_row(self, item, *, call_id="synthetic-read", turn="synthetic-turn"):
        return {"type": "event_msg", "payload": {
            "type": "item_completed", "thread_id": "synthetic-session",
            "turn_id": turn, "item": {"id": call_id, **item}}}

    def meta_row(self):
        return {"type": "session_meta", "payload": {
            "id": "synthetic-session", "session_id": "synthetic-session"}}

    def result(self, rows, **kwargs):
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(self.home)}):
            state, payload = self.build(rows, **kwargs)
            return cg.host_terminal_result(state, payload)

    # ---- F02: authoritative output field ----

    def test_aggregated_output_success_and_failure_are_recognized(self):
        item = self.command_item("synthetic-read", output=None)
        item["aggregated_output"] = "sample\n"
        value = self.result([self.meta_row(), self.event_row(item)])
        self.assertIsNotNone(value)
        self.assertEqual(value["outcome"], "success")
        self.assertEqual(value["stdout"], "sample\n")
        item["exit_code"] = 1
        item["status"] = "failed"
        value = self.result([self.meta_row(), self.event_row(item)])
        self.assertIsNotNone(value)
        self.assertEqual(value["outcome"], "failed")

    def test_conflicting_dual_output_fields_stay_rejected(self):
        item = self.command_item("synthetic-read", output="stdout-value")
        item["aggregated_output"] = "aggregated-value"
        self.assertIsNone(self.result([self.meta_row(), self.event_row(item)]))

    def test_equal_dual_output_fields_are_accepted(self):
        item = self.command_item("synthetic-read", output="same\n")
        item["aggregated_output"] = "same\n"
        value = self.result([self.meta_row(), self.event_row(item)])
        self.assertIsNotNone(value)
        self.assertEqual(value["stdout"], "same\n")

    def test_empty_aggregated_output_stays_a_process_result(self):
        item = self.command_item("synthetic-read", output=None)
        item["aggregated_output"] = ""
        value = self.result([self.meta_row(), self.event_row(item)])
        self.assertIsNotNone(value)
        self.assertEqual(value["outcome"], "success")
        self.assertEqual(value["stdout"], "")

    def test_non_string_aggregated_output_stays_rejected(self):
        item = self.command_item("synthetic-read", output=None)
        item["aggregated_output"] = {"text": "sample"}
        self.assertIsNone(self.result([self.meta_row(), self.event_row(item)]))

    def test_oversized_aggregated_output_stays_rejected(self):
        item = self.command_item("synthetic-read", output=None)
        item["aggregated_output"] = "x" * (cg.HOST_TRANSCRIPT_LINE_LIMIT + 1)
        self.assertIsNone(self.result([self.meta_row(), self.event_row(item)]))

    def test_missing_both_output_fields_stays_rejected(self):
        item = self.command_item("synthetic-read", output=None, drop_stdout=True)
        self.assertIsNone(self.result([self.meta_row(), self.event_row(item)]))

    # ---- F03: bounded unrelated-record isolation ----

    def oversized_row(self, record):
        filler = '"filler": "' + "x" * (cg.HOST_TRANSCRIPT_LINE_LIMIT + 8) + '"'
        raw = json.dumps(record)[:-1] + ", " + filler + "}"
        return (raw + "\n").encode("utf-8")

    def write_mixed(self, extra_bytes_rows):
        transcript = self.transcript_path()
        parts = []
        for row in extra_bytes_rows:
            parts.append(row if isinstance(row, bytes) else
                         (json.dumps(row) + "\n").encode("utf-8"))
        transcript.write_bytes(b"".join(parts))

    def run_mixed(self, extra_rows, **kwargs):
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(self.home)}):
            self.write_mixed(extra_rows)
            transcript = self.transcript_path()
            state = {"session": {"id": "synthetic-session",
                                 "transcript_path": str(transcript)}}
            payload = {
                "session_id": "synthetic-session",
                "turn_id": "synthetic-turn",
                "transcript_path": str(transcript),
                "cwd": str(self.work),
                "tool_use_id": "synthetic-read",
                "tool_name": "Bash",
                "tool_input": {"command": "echo sample"},
                "tool_response": "sample\n",
            }
            return cg.host_terminal_result(state, payload)

    def test_large_unrelated_response_item_does_not_poison_the_snapshot(self):
        item = self.command_item("synthetic-read", output="sample\n")
        big_other = {"type": "response_item", "payload": {
            "type": "custom_tool_call_output", "call_id": "other-call",
            "output": "x" * (cg.HOST_TRANSCRIPT_LINE_LIMIT + 16)}}
        value = self.run_mixed(
            [self.meta_row(), big_other, self.event_row(item)])
        self.assertIsNotNone(value)
        self.assertEqual(value["outcome"], "success")

    def test_oversized_turn_context_row_is_skippable(self):
        item = self.command_item("synthetic-read", output="sample\n")
        big_turn = {"type": "turn_context", "payload": {
            "turn_id": "synthetic-turn",
            "context": "y" * (cg.HOST_TRANSCRIPT_LINE_LIMIT + 16)}}
        value = self.run_mixed(
            [self.meta_row(), big_turn, self.event_row(item)])
        self.assertIsNotNone(value)

    def test_oversized_event_msg_keeps_the_snapshot_unavailable(self):
        item = self.command_item("synthetic-read", output="sample\n")
        big_event = {"type": "event_msg", "payload": {
            "type": "item_completed", "thread_id": "synthetic-session",
            "turn_id": "synthetic-turn",
            "item": {"id": "other-event", "output":
                     "z" * (cg.HOST_TRANSCRIPT_LINE_LIMIT + 16)}}}
        self.assertIsNone(self.run_mixed(
            [self.meta_row(), big_event, self.event_row(item)]))

    def test_oversized_unknown_type_keeps_the_snapshot_unavailable(self):
        item = self.command_item("synthetic-read", output="sample\n")
        big_unknown = {"type": "mystery_record", "payload": {
            "blob": "z" * (cg.HOST_TRANSCRIPT_LINE_LIMIT + 16)}}
        self.assertIsNone(self.run_mixed(
            [self.meta_row(), big_unknown, self.event_row(item)]))

    def test_oversized_broken_noncandidate_row_is_skipped_by_design(self):
        # A broken oversized row whose outer type is provably never a
        # candidate cannot hide a conflicting terminal event, so the bounded
        # isolation skips it; candidacy only needs the outer type member.
        item = self.command_item("synthetic-read", output="sample\n")
        broken = b'{"type": "response_item", "payload": [broken' + \
            b"x" * (cg.HOST_TRANSCRIPT_LINE_LIMIT + 8) + b"\n"
        value = self.run_mixed(
            [self.meta_row(), broken, self.event_row(item)])
        self.assertIsNotNone(value)

    def test_oversized_broken_event_head_keeps_the_snapshot_unavailable(self):
        item = self.command_item("synthetic-read", output="sample\n")
        broken = b'{"type": "event_msg", "payload": [broken' + \
            b"x" * (cg.HOST_TRANSCRIPT_LINE_LIMIT + 8) + b"\n"
        self.assertIsNone(self.run_mixed(
            [self.meta_row(), broken, self.event_row(item)]))

    def test_embedded_fake_type_inside_a_string_is_not_skippable(self):
        item = self.command_item("synthetic-read", output="sample\n")
        tricky = ('{"payload": "see \\"type\\": \\"response_item\\" inside", '
                  '"data": "' + "x" * (cg.HOST_TRANSCRIPT_LINE_LIMIT + 16) + '"}'
                  "\n").encode("utf-8")
        self.assertIsNone(self.run_mixed(
            [self.meta_row(), tricky, self.event_row(item)]))

    def test_oversized_duplicate_candidate_keeps_the_snapshot_unavailable(self):
        item = self.command_item("synthetic-read", output="sample\n")
        big_duplicate = {"type": "event_msg", "payload": {
            "type": "item_completed", "thread_id": "synthetic-session",
            "turn_id": "synthetic-turn",
            "item": {"id": "synthetic-read", "output":
                     "z" * (cg.HOST_TRANSCRIPT_LINE_LIMIT + 16)}}}
        self.assertIsNone(self.run_mixed(
            [self.meta_row(), self.event_row(item), big_duplicate]))

    def test_oversized_session_meta_head_keeps_identity_unverified(self):
        item = self.command_item("synthetic-read", output="sample\n")
        big_meta = {"type": "session_meta", "payload": {
            "id": "synthetic-session", "session_id": "synthetic-session",
            "blob": "z" * (cg.HOST_TRANSCRIPT_LINE_LIMIT + 16)}}
        self.assertIsNone(self.run_mixed(
            [big_meta, self.event_row(item)]))

    def test_small_unrelated_rows_never_changed_behavior(self):
        item = self.command_item("synthetic-read", output="sample\n")
        small_other = {"type": "response_item", "payload": {
            "type": "custom_tool_call_output", "call_id": "other-call",
            "output": "x" * 64}}
        value = self.run_mixed(
            [self.meta_row(), small_other, self.event_row(item)])
        self.assertIsNotNone(value)
        self.assertEqual(value["outcome"], "success")


if __name__ == "__main__":
    unittest.main()
