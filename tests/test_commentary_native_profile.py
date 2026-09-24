"""Fail-closed raw-input checks for the zero-model commentary profile."""

import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from tools.validation import commentary_native_profile as profile


class CommentaryNativeProfileTests(unittest.TestCase):
    def test_codex_version_comes_from_official_initialize_not_reviewer_policy(self):
        self.assertEqual(profile._official_codex_version(
            {"codexHome": "/isolated", "userAgent":
             "Codex Desktop/0.153.4 (Mac OS; arm64)"}, "/isolated"), "0.153.4")
        self.assertEqual(profile._official_codex_version(
            {"codexHome": "/isolated", "userAgent":
             "cg142-independent-review"}, "/isolated"), "unknown")
        with self.assertRaises(profile.ReplayError):
            profile._official_codex_version(
                {"codexHome": "/other", "userAgent": "Codex/0.153.4"},
                "/isolated")

    def test_owned_cleanup_requires_original_collector_shape_and_all_positive_facts(self):
        result = {"status": "source_chain_observed",
                  "phase": "offline_chain_checked",
                  "cleanup": {"owned_process_exited": True,
                              "process_group_kill_attempted": True,
                              "process_group_cleanup_error": None,
                              "owned_tree_empty": True,
                              "owned_tree_no_running_members": True,
                              "process_group_absent": True,
                              "process_group_signal_denied": False,
                              "process_group_query_denied": False,
                              "escaped_descendants": "not_established"}}
        profile._verify_owned_cleanup(result)
        for field, value in (("owned_tree_empty", False),
                             ("process_group_cleanup_error", "denied"),
                             ("escaped_descendants", "passed")):
            changed = deepcopy(result)
            changed["cleanup"][field] = value
            with self.subTest(field=field), self.assertRaises(profile.ReplayError):
                profile._verify_owned_cleanup(changed)

    def test_official_hook_readback_requires_roles_events_and_trust(self):
        product_events = ("preToolUse", "postToolUse", "preCompact",
                          "sessionStart", "sessionEnd", "userPromptSubmit",
                          "subagentStart", "subagentStop", "stop")
        rows = []
        for index, event in enumerate(product_events):
            rows.append({"source": "plugin", "sourcePath": "/plugin/hooks.json",
                         "eventName": event, "key": f"product-{index}",
                         "currentHash": f"sha256:{index:064x}",
                         "trustStatus": "trusted", "enabled": True})
        for index, event in enumerate(("preCompact", "sessionStart")):
            rows.append({"source": "sessionFlags", "sourcePath": "/capture/config.toml",
                         "eventName": event, "command": "capture --digest-echo",
                         "key": f"capture-{index}",
                         "currentHash": f"sha256:{index + 9:064x}",
                         "trustStatus": "trusted", "enabled": True})
        plan = {"cwd": "/work", "hook_source": "/plugin/hooks.json",
                "capture_hook_source": "/capture/config.toml",
                "selected_hook_hashes": {h["key"]: h["currentHash"] for h in rows}}
        data = {"cwd": "/work", "errors": [], "warnings": [], "hooks": rows}
        profile._verify_hook_readback(data, plan)
        for index, field, value in ((0, "source", "sessionFlags"),
                                    (1, "eventName", "wrong"),
                                    (9, "command", "capture"),
                                    (10, "trustStatus", "untrusted")):
            changed = deepcopy(data)
            changed["hooks"][index][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(profile.ReplayError):
                profile._verify_hook_readback(changed, plan)

    def test_rpc_rejects_duplicate_or_reordered_host_records(self):
        good = [
            {"direction": "send", "raw": {"id": 1, "method": "initialize"},
             "monotonic_ns": 10},
            {"direction": "receive", "raw": {"id": 1, "result": {}},
             "monotonic_ns": 11},
        ]
        def encode(rows):
            return ("\n".join(json.dumps(row) for row in rows) + "\n").encode()
        self.assertEqual(len(profile._rpc(encode(good))), 2)
        for changed in (good + [good[-1]], list(reversed(good)),
                        [dict(good[0], direction="forged"), good[1]]):
            with self.subTest(changed=changed), self.assertRaises(profile.ReplayError):
                profile._rpc(encode(changed))

    def test_bounded_file_read_rejects_symlink_and_changed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source.json"
            source.write_bytes(b"{}")
            digest = hashlib.sha256(b"{}").hexdigest()
            self.assertEqual(profile._read(source, digest, 2), b"{}")
            with self.assertRaises(profile.ReplayError):
                profile._read(source, "0" * 64, 2)
            with self.assertRaises(profile.ReplayError):
                profile._read(source, digest, 1)
            link = root / "link.json"
            link.symlink_to(source)
            with self.assertRaises(profile.ReplayError):
                profile._read(link, digest, 2)

    def test_rpc_reply_must_follow_completed_send_even_when_ids_match(self):
        request = {"id": 7, "method": "initialize", "params": {}}
        reply = {"id": 7, "result": {}}
        def row(direction, raw, stamp):
            return {"direction": direction, "raw": raw,
                    "monotonic_ns": stamp}
        good = [row("send", request, 10), row("send_complete", request, 11),
                row("receive", reply, 12)]
        self.assertEqual(profile._response(good, "initialize"), (request, reply))
        for changed in (
            [row("receive", reply, 10), row("send", request, 11),
             row("send_complete", request, 12)],
            [row("send", request, 10), row("receive", reply, 11),
             row("send_complete", request, 12)],
        ):
            with self.subTest(changed=changed), self.assertRaises(profile.ReplayError):
                profile._response(changed, "initialize")

    def test_evidence_tree_digest_detects_changed_or_linked_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first = root / "capture.raw"
            first.write_bytes(b"original")
            original = profile._tree_digest(root)
            first.write_bytes(b"changed")
            self.assertNotEqual(profile._tree_digest(root), original)
            linked = root / "linked.raw"
            linked.symlink_to(first)
            with self.assertRaisesRegex(profile.ReplayError, "linked_tree_member"):
                profile._tree_digest(root)

    def test_manifest_cannot_claim_success_without_exact_raw_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"schema": profile.SCHEMA,
                                            "status": "passed"}))
            with self.assertRaisesRegex(profile.ReplayError, "invalid_replay_manifest"):
                profile.replay(manifest)
            manifest.write_text('{"schema":"x","schema":"y"}')
            with self.assertRaisesRegex(profile.ReplayError, "duplicate_json_key"):
                profile.replay(manifest)

    def test_versioned_result_schema_declares_profile_and_required_gate_facts(self):
        schema = json.loads((Path(__file__).parents[1] / "tools/validation"
                             / "native-acceptance-v2.schema.json").read_text())
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertIn(profile.PROFILE, schema["properties"]["gate_profile"]["enum"])
        required = schema["properties"]["gates"]["items"]["required"]
        self.assertIn("evidence", required)
        self.assertIn("mode", schema["properties"]["gates"]["items"]
                      ["properties"]["evidence"]["required"])


if __name__ == "__main__":
    unittest.main()
