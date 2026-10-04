"""Protect the scan gate and the absence of default external submission."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class HolWorkflowContractTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / ".github/workflows/hol-plugin-scanner.yml").read_text()

    def test_scan_gate_and_pinned_inputs_are_preserved(self):
        for expected in (
            "hashgraph-online/ai-plugin-scanner-action@edec9ae765c5bbd01bca060359acc3d2e90bea09",
            'plugin_dir: "."', "mode: scan", "install_cisco: true",
            'cisco_skill_scan: "on"', "min_score: 80", "fail_on_severity: high",
            "format: sarif", "upload_sarif: true", "output: ai-plugin-scanner.sarif",
            "registry_payload_output: hol-registry-payload.json"):
            self.assertIn(expected, self.workflow)
        for forbidden in ("continue-on-error", "mode: submit", "trust_repository_policy: true"):
            self.assertNotIn(forbidden, self.workflow)

    def test_submission_remains_explicit_manual_opt_in_with_restricted_secret(self):
        self.assertIn("type: boolean\n        default: false", self.workflow)
        self.assertIn("submission_enabled: ${{ github.event_name == 'workflow_dispatch' && inputs.refresh_registry }}", self.workflow)
        self.assertIn("submission_token: ${{ github.event_name == 'workflow_dispatch' && inputs.refresh_registry && secrets.AWESOME_CODEX_PLUGINS_TOKEN || '' }}", self.workflow)
        self.assertEqual(self.workflow.count("secrets."), 1)
        self.assertNotIn("issues: write", self.workflow)
        self.assertNotIn("pull-requests: write", self.workflow)

    def test_failed_scan_cannot_be_promoted_by_always_upload(self):
        self.assertIn("SCANNER_OUTCOME: ${{ steps.scanner.outcome }}", self.workflow)
        self.assertIn('--scanner-outcome "$SCANNER_OUTCOME"', self.workflow)
        self.assertIn("set -euo pipefail", self.workflow)
        self.assertIn("if: ${{ always() && steps.checkout.outcome == 'success' }}", self.workflow)
        self.assertIn("if: ${{ always() && steps.evidence.outputs.companion_path != '' }}", self.workflow)

    def test_upload_is_pinned_and_only_uses_validated_whitelist_outputs(self):
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", self.workflow)
        block = self.workflow.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]
        self.assertEqual(block.strip().splitlines(), [
            "${{ steps.evidence.outputs.companion_path }}",
            "            ${{ steps.evidence.outputs.sarif_path }}",
            "            ${{ steps.evidence.outputs.payload_path }}"])
        self.assertIn("if-no-files-found: error", self.workflow)
        self.assertIn("retention-days: 30", self.workflow)
        self.assertNotIn("path: .", self.workflow)

    def test_identity_arguments_are_bound_to_workflow_not_payload_rewrites(self):
        self.assertIn("SOURCE_SHA: ${{ github.sha }}", self.workflow)
        self.assertIn("SOURCE_REPOSITORY: ${{ github.repository }}", self.workflow)
        self.assertIn('--expected-source-sha "$SOURCE_SHA"', self.workflow)
        self.assertIn('--expected-repository "$SOURCE_REPOSITORY"', self.workflow)
        self.assertIn('--expected-scanner-version "3.12.1"', self.workflow)
        self.assertNotIn("gh ", self.workflow)
        self.assertNotIn("workflow run", self.workflow)


if __name__ == "__main__":
    unittest.main()
