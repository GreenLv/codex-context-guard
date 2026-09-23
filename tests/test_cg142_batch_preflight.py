import copy
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.validation import batch_preflight as batch


class BatchPreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        artifact = self.root / "input.json"
        artifact.write_text('{"fixture":"无凭据"}\n', encoding="utf-8")
        self.plan = {
            "schema": batch.SCHEMA, "source_commit": "a" * 40,
            "runtime_tree_sha256": "b" * 64, "plan_sha256": "c" * 64,
            "fixtures": [{"repo": str(self.root), "initial_head": "d" * 40,
                          "changed_paths": ["module.py"]}],
            "sessions": [{"id": "git-session", "role": "git_trust"},
                         {"id": "continuity-session", "role": "continuity"}],
            "inputs": [{"role": role, "path": str(artifact),
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}
                       for role in sorted(batch.INPUT_ROLES)],
            "expectations": [{"contract": "INV-07", "kind": "current_contract",
                              "assertion": "ordinary_tools_are_host_owned"}],
            "budget": {"turns": 6, "turn_seconds": 2100, "startup": 180,
                       "compact": 300, "cleanup": 180},
            "permission_route": "same_restricted_route",
        }
        self.plan["driver_timeouts"] = batch.wait_budget(**self.plan["budget"])
        git = patch.object(batch.subprocess, "run")
        self.git = git.start()
        self.addCleanup(git.stop)
        self.git.return_value.returncode = 0
        self.git.return_value.stdout = ("d" * 40 + "\n").encode("ascii")

    def test_valid_static_inputs_do_not_claim_host_acceptance(self):
        result = batch.validate_batch(self.plan)
        self.assertEqual(result["status"], "inputs_ready")
        self.assertEqual(result["model_requests"], 0)
        self.assertEqual(result["acceptance"], "not_run")
        self.assertIn("effective_child_permissions", result["unknown"])
        self.assertIn("commentary_answer_binding", result["unknown"])

    def test_no_head_and_same_session_fail_before_model(self):
        self.plan["fixtures"][0]["initial_head"] = None
        self.plan["sessions"][1]["id"] = "git-session"
        result = batch.validate_batch(self.plan)
        self.assertIn("initial_head_required_root_commit_unsupported", result["errors"])
        self.assertIn("independent_sessions_required", result["errors"])
        self.git.assert_not_called()

    def test_inner_timeout_cannot_keep_old_budget(self):
        self.plan["driver_timeouts"]["inner_turn"] = 240
        self.assertIn("driver_timeout_chain_mismatch", batch.validate_batch(self.plan)["errors"])
        with self.assertRaises(ValueError):
            batch.wait_budget(1, True, startup=1, compact=1, cleanup=1)

    def test_extra_expectation_does_not_expand_product_contract(self):
        for assertion in ("typed_phase_wait", "root_controls_nonempty"):
            with self.subTest(assertion=assertion):
                self.plan["expectations"][0]["assertion"] = assertion
                self.assertIn("withdrawn_expectation_not_a_product_failure",
                              batch.validate_batch(self.plan)["errors"])

    def test_wrong_digest_missing_inputs_and_permission_escalation(self):
        self.plan["inputs"][0]["sha256"] = "e" * 64
        self.plan["inputs"].pop()
        self.plan["permission_route"] = "unsandboxed"
        errors = batch.validate_batch(self.plan)["errors"]
        self.assertIn("input_digest_mismatch", errors)
        self.assertIn("incomplete_input_inventory", errors)
        self.assertIn("permission_route_unverified", errors)

    def test_utf8_and_duplicate_key_handling(self):
        path = self.root / "plan.json"
        path.write_bytes('{"name":"样本"}'.encode("utf-8"))
        self.assertEqual(batch.read_json(path), {"name": "样本"})
        path.write_bytes(b'{"schema":"one","schema":"two"}')
        with self.assertRaisesRegex(ValueError, "duplicate_key"):
            batch.read_json(path)

    def test_all_checks_are_read_only(self):
        before = copy.deepcopy(self.plan)
        batch.validate_batch(self.plan)
        self.assertEqual(self.plan, before)


if __name__ == "__main__":
    unittest.main()
