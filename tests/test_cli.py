import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from case_analyzer import cli, explain_cli


class ExplainCliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.case_path = Path(self.directory.name) / "case.json"
        self.case_path.write_text(json.dumps({"id": "1", "title": "Example"}), encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    @patch("case_analyzer.cli.analyze_case")
    def test_explain_dry_run_does_not_invoke_llm(self, analyze_case):
        output = io.StringIO()
        with redirect_stdout(output):
            status = cli.main([str(self.case_path), "--explain", "--dry-run"])

        self.assertEqual(0, status)
        analyze_case.assert_not_called()
        self.assertIn("SystemMessage:", output.getvalue())
        self.assertIn("Stop without invoking the LLM", output.getvalue())

    def test_legacy_command_forwards_to_explain_dry_run(self):
        output = io.StringIO()
        errors = io.StringIO()
        with patch("case_analyzer.explain_cli.case_analyzer_main", return_value=0) as forwarded:
            with redirect_stdout(output), redirect_stderr(errors):
                status = explain_cli.main([str(self.case_path)])

        self.assertEqual(0, status)
        self.assertIn("deprecated", errors.getvalue())
        self.assertIn("--explain", forwarded.call_args.args[0])
        self.assertIn("--dry-run", forwarded.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
