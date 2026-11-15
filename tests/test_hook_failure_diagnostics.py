import hashlib
import json
import unittest

from tools.validation.hook_failure_diagnostics import (
    MAX_ENTRIES,
    MAX_TEXT_BYTES,
    message_pattern,
    project_failed,
)

SOURCE = "/synthetic/home/plugins/cache/codex-context-guard/context-guard/0.18.0/hooks/hooks.json"
EVENT = "stop"


def key(raw, sources):
    matches = [source for source in sources if raw == source]
    return matches[0] if len(matches) == 1 else None


def inventory():
    return {
        (EVENT, SOURCE): {
            "sourcePath": SOURCE,
            "eventName": EVENT,
            "source": "plugin",
            "handlerType": "command",
            "displayOrder": 0,
            "enabled": True,
            "trustStatus": "trusted",
            "key": "synthetic-key",
            "currentHash": "digest",
        }
    }


def message(text="synthetic failure", kind="warning"):
    return {
        "method": "hook/completed",
        "params": {
            "threadId": "synthetic-thread",
            "turnId": "synthetic-turn",
            "run": {
                "id": "synthetic-run",
                "eventName": EVENT,
                "sourcePath": SOURCE,
                "source": "plugin",
                "handlerType": "command",
                "displayOrder": 0,
                "executionMode": "sync",
                "status": "failed",
                "entries": [{"kind": kind, "text": text}],
            },
        },
    }


class DiagnosticTests(unittest.TestCase):
    def test_redacts_and_does_not_assert_success_or_reason(self):
        raw = "synthetic secret /path/to/private 认证"
        result = project_failed(message(raw), inventory(), key)
        self.assertEqual(result["status"], "redacted")
        self.assertEqual(
            result["entries"][0],
            {
                "kind": "warning",
                "utf8_bytes": len(raw.encode()),
                "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                "classification": "unknown",
            },
        )
        self.assertNotIn(raw, json.dumps(result, ensure_ascii=False))

    def test_foreign_or_mismatched_never_reads_entries(self):
        class TrapDict(dict):
            def get(self, name, default=None):
                if name == "entries":
                    raise AssertionError("out-of-scope entries accessed")
                return super().get(name, default)

        for changed in (
            {"sourcePath": "/other-plugin/hooks.json"},
            {"eventName": "postToolUse"},
            {"handlerType": "prompt"},
            {"displayOrder": True},
            {"executionMode": "async"},
            {"source": "other"},
        ):
            m = message()
            m["params"]["run"] = TrapDict(m["params"]["run"])
            m["params"]["run"].update(changed)
            # Exact built-in dict check refuses the trapping subclass before any access.
            self.assertIsNone(project_failed(m, inventory(), key))
            m["params"]["run"] = dict(m["params"]["run"])
            self.assertIsNone(project_failed(m, inventory(), key))

    def test_untrusted_or_wrong_inventory_refuses(self):
        for k, v in (
            ("trustStatus", "untrusted"),
            ("enabled", False),
            ("currentHash", ""),
            ("sourcePath", "/other"),
            ("async", "false"),
        ):
            entries = inventory()
            entries[(EVENT, SOURCE)][k] = v
            self.assertIsNone(project_failed(message(), entries, key))

    def test_only_failed_completion_is_inspected(self):
        for status in ("completed", "blocked", None):
            m = message()
            m["params"]["run"]["status"] = status
            self.assertIsNone(project_failed(m, inventory(), key))
        m = message()
        m["method"] = "hook/started"
        self.assertIsNone(project_failed(m, inventory(), key))
        for where, name in (
            ("params", "threadId"),
            ("params", "turnId"),
            ("run", "id"),
        ):
            m = message()
            target = m["params"] if where == "params" else m["params"]["run"]
            target.pop(name)
            self.assertIsNone(project_failed(m, inventory(), key))

    def test_missing_unknown_and_large_fail_closed_without_text(self):
        for value, reason in [
            (None, "missing_or_invalid_entries"),
            ([], "empty_entries"),
            ([{"kind": "other", "text": "private"}], "unknown_entry_shape"),
            (
                [{"kind": "warning", "text": "x", "extra": "private"}],
                "unknown_entry_shape",
            ),
            (
                [{"kind": "warning", "text": "x" * (MAX_TEXT_BYTES + 1)}],
                "entry_too_large",
            ),
            ([{"kind": "warning", "text": "\ud800"}], "invalid_utf8_text"),
            (
                [{"kind": "warning", "text": "x"}] * (MAX_ENTRIES + 1),
                "too_many_entries",
            ),
        ]:
            m = message()
            m["params"]["run"]["entries"] = value
            self.assertEqual(
                project_failed(m, inventory(), key),
                {"status": "unavailable", "reason": reason},
            )

    def test_session_hook_without_a_turn_keeps_only_redacted_diagnostic(self):
        m = message("synthetic session failure", "error")
        m["params"]["turnId"] = None
        m["params"]["run"]["eventName"] = "sessionStart"
        row = inventory().pop((EVENT, SOURCE))
        row["eventName"] = "sessionStart"
        result = project_failed(m, {("sessionStart", SOURCE): row}, key)
        self.assertEqual(result["status"], "redacted")
        self.assertEqual(result["entries"][0]["classification"], "unknown")
        self.assertNotIn("synthetic session failure", json.dumps(result))

    def test_multiple_known_entries_retain_only_redacted_summaries(self):
        m = message()
        m["params"]["run"]["entries"].append({"kind": "feedback", "text": "y"})
        result = project_failed(m, inventory(), key)
        self.assertEqual(len(result["entries"]), 2)
        self.assertTrue(
            all(x["classification"] == "unknown" for x in result["entries"])
        )

    def test_error_message_patterns_are_bounded_not_causal(self):
        samples = {
            "plugin contents changed; hook approval required": "message_matches_plugin_content_approval",
            "hook timed out after 15s": "message_matches_timeout",
            "failed to write hook stdin: synthetic": "message_matches_stdin_write_error",
            "hook exited with code 13": "message_matches_nonzero_exit",
            "hook exited without a status code": "message_matches_exit_without_status",
        }
        for text, expected in samples.items():
            with self.subTest(expected=expected):
                result = project_failed(
                    message(text, "error"),
                    inventory(),
                    key,
                )
                self.assertEqual(result["entries"][0]["classification"], expected)
                self.assertNotIn(text, json.dumps(result))
                self.assertEqual(message_pattern("feedback", text, EVENT), "unknown")
                self.assertEqual(message_pattern("warning", text, EVENT), "unknown")
                self.assertEqual(
                    message_pattern("error", text, "preToolUse"), "unknown"
                )

    def test_lookalikes_and_unproved_os_reasons_remain_unknown(self):
        for text in (
            "prefix plugin contents changed; hook approval required",
            "plugin contents changed; hook approval required\nprivate suffix",
            "hook timed out after 15s trailing",
            "failed to write hook stdin: ",
            "hook exited with code 0",
            "hook exited with code 9999999999999999",
            "No such file or directory (os error 2)",
            "Permission denied (os error 13)",
        ):
            self.assertEqual(message_pattern("error", text, EVENT), "unknown")

    def test_known_kind_enum_cannot_introduce_arbitrary_fields(self):
        for kind in ("warning", "stop", "feedback", "context", "error"):
            result = project_failed(message("synthetic", kind), inventory(), key)
            self.assertEqual(result["entries"][0]["kind"], kind)
            self.assertEqual(result["entries"][0]["classification"], "unknown")


if __name__ == "__main__":
    unittest.main()
