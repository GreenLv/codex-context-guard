"""Offline controls for full-timeline retention and path redaction."""
import codecs
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools/validation"))
import module_timeline_probe as probe  # noqa: E402


class TimelineControls(unittest.TestCase):
    def test_other_system_module_and_unfinished_interval_are_retained(self):
        text = ("Modules Information: 0 : Started analysis: C:\\Program Files\\WindowsPowerShell\\Modules\\AzureRM\\1.0\\AzureRM.psd1\n"
                "DateTime=2026-11-01T00:00:00Z\n"
                "Modules Information: 0 : unknown private-message\n"
                "DateTime=2026-11-01T00:00:12Z\n")
        for raw in (text.encode(), codecs.BOM_UTF16_LE + text.encode("utf-16-le")):
            result = probe.summarize(raw, r"C:\Windows\PS")
            self.assertEqual(result["counts"]["analysis_start"], 1)
            self.assertEqual(result["largest_gaps"][0]["seconds"], 12)
            self.assertEqual(len(result["unfinished_analyses"]), 1)
            self.assertIn("azurerm.psd1", result["unfinished_analyses"][0]["system_relative_file"])
            self.assertNotIn("private-message", str(result))
            self.assertNotIn("C:\\", str(result))

    def test_head_events_survive_long_trace_and_completed_analysis_closes(self):
        text = "Modules Information: 0 : Started analysis: C:\\Windows\\PS\\Modules\\Foo\\Foo.psd1\n"
        text += "Modules Verbose: 0 : unknown message\n" * 3000
        text += "Modules Information: 0 : Finished analysis: C:\\Windows\\PS\\Modules\\Foo\\Foo.psd1\n"
        result = probe.summarize(text.encode(), r"C:\Windows\PS")
        self.assertGreater(result["total_bytes"], 65536)
        self.assertEqual(result["counts"]["analysis_start"], 1)
        self.assertEqual(result["counts"]["analysis_end"], 1)
        self.assertFalse(result["unfinished_analyses"])
        self.assertEqual(result["trace_headers"]["Modules:Verbose"], 3000)

    def test_non_system_paths_remain_opaque_and_unknown_is_not_known(self):
        row = probe.classify("Started analysis: C:\\private-user\\module.psd1", r"C:\Windows\PS")
        self.assertIsNone(row["system_relative_file"])
        self.assertNotIn("private-user", str(row))
        result = probe.summarize(b"private-unknown-format\n", "system")
        self.assertEqual(result["state"], "unrecognized")
        self.assertNotIn("private-unknown-format", str(result))


if __name__ == "__main__":
    unittest.main()
