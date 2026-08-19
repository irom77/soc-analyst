import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from case_analyzer import cli, explain_cli
from case_analyzer.analyzer import LLMProviderError
from case_analyzer.schemas import (
    AnalyzedReport,
    AnalyzedSummary,
    CaseAnalyzerRun,
    EvidenceFinding,
    RunChecks,
)


def _run_block(checks: RunChecks | None = None) -> CaseAnalyzerRun:
    """A stand-in for what `build_run_metadata` attaches; contents are not under test here."""
    return CaseAnalyzerRun(
        generated_at=datetime(2026, 8, 19, 12, 0, tzinfo=UTC),
        package_version="0.1.0",
        model="test-model",
        system_prompt_sha256="0" * 64,
        payload_sha256="1" * 64,
        checks=checks or RunChecks(ran=True),
    )


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

    @patch("case_analyzer.cli.analyze_case")
    def test_llm_provider_error_is_clean_and_has_distinct_exit_code(self, analyze_case):
        analyze_case.side_effect = LLMProviderError("LLM rate limit or quota was exceeded.", 4)
        errors = io.StringIO()
        with redirect_stderr(errors):
            status = cli.main([str(self.case_path)])

        self.assertEqual(4, status)
        self.assertEqual(
            "case-analyzer: LLM error: LLM rate limit or quota was exceeded.\n",
            errors.getvalue(),
        )

    def test_output_file_receives_the_result_json(self):
        target = Path(self.directory.name) / "report.json"
        output = io.StringIO()
        with redirect_stdout(output):
            status = cli.main([str(self.case_path), "--dry-run", "--output", str(target)])

        self.assertEqual(0, status)
        self.assertEqual("", output.getvalue())
        self.assertEqual("Example", json.loads(target.read_text(encoding="utf-8"))["case"]["title"])

    @staticmethod
    def _report_citing(path: str, checks: RunChecks | None = None) -> AnalyzedReport:
        return AnalyzedReport(
            verdict="Suspicious",
            severity="medium",
            impact="none",
            priority="medium",
            confidence="low",
            digest="d",
            evidence_findings=[
                EvidenceFinding(
                    title="Beaconing",
                    finding_type="network",
                    subject="host",
                    evidence="e",
                    conclusion="c",
                    source_paths=[path],
                )
            ],
            case_analyzer_run=_run_block(checks),
        )

    @patch("case_analyzer.cli.analyze_case")
    def test_a_recorded_check_problem_warns_without_withholding_the_report(self, analyze_case):
        """The report is the user's; a self-description defect is stderr's problem."""
        analyze_case.return_value = self._report_citing(
            "artifacts[0].cef.invented",
            RunChecks(ran=True, problems=["'Beaconing' cites 'artifacts[0].cef.invented'"]),
        )
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = cli.main([str(self.case_path)])

        self.assertEqual(0, status)
        self.assertIn("report check", errors.getvalue())
        self.assertIn("artifacts[0].cef.invented", errors.getvalue())
        # stdout stays pure result JSON, so a piped caller is unaffected.
        self.assertEqual("Suspicious", json.loads(output.getvalue())["verdict"])

    @patch("case_analyzer.cli.analyze_case")
    def test_a_clean_check_produces_no_warning_and_still_lands_in_the_result(self, analyze_case):
        analyze_case.return_value = self._report_citing("title")
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = cli.main([str(self.case_path)])

        self.assertEqual(0, status)
        self.assertNotIn("report check", errors.getvalue())
        # Silence on stderr is not the record; the saved result says the check ran.
        run = json.loads(output.getvalue())["case_analyzer_run"]
        self.assertEqual({"ran": True, "problems": []}, run["checks"])

    @patch("case_analyzer.cli.analyze_case")
    def test_the_input_file_hash_reaches_the_analyzer(self, analyze_case):
        analyze_case.return_value = self._report_citing("title")
        with redirect_stdout(io.StringIO()):
            cli.main([str(self.case_path)])

        expected = hashlib.sha256(self.case_path.read_bytes()).hexdigest()
        self.assertEqual(expected, analyze_case.call_args.kwargs["input_file_sha256"])

    @patch("case_analyzer.cli.analyze_case")
    @patch("case_analyzer.cli.summarize_case")
    def test_summary_returns_a_digest_and_never_requests_a_report(self, summarize_case, analyze_case):
        summarize_case.return_value = AnalyzedSummary(
            summary="One paragraph about the case.", case_analyzer_run=_run_block(RunChecks())
        )
        output = io.StringIO()
        with redirect_stdout(output):
            status = cli.main([str(self.case_path), "--summary"])

        self.assertEqual(0, status)
        analyze_case.assert_not_called()
        result = json.loads(output.getvalue())
        self.assertEqual("One paragraph about the case.", result["summary"])
        # A summary has nothing to check, and says so rather than looking clean.
        self.assertFalse(result["case_analyzer_run"]["checks"]["ran"])

    @patch("case_analyzer.cli.summarize_case")
    def test_summary_dry_run_previews_the_summary_prompt_without_calling_the_llm(self, summarize_case):
        output = io.StringIO()
        with redirect_stdout(output):
            status = cli.main([str(self.case_path), "--summary", "--dry-run", "--explain"])

        self.assertEqual(0, status)
        summarize_case.assert_not_called()
        self.assertIn("structured case-summary request", output.getvalue())
        self.assertIn("Remove --dry-run to request a case summary.", output.getvalue())

    def test_malformed_knowledge_file_is_rejected_before_enrichment_runs(self):
        knowledge_path = Path(self.directory.name) / "knowledge.json"
        knowledge_path.write_text(json.dumps({"not": "an array"}), encoding="utf-8")
        errors = io.StringIO()
        with patch("case_analyzer.cli.enrich_case") as enrich, redirect_stderr(errors):
            status = cli.main(
                [
                    str(self.case_path),
                    "--enrich",
                    "--dry-run",
                    "--allow-enrichment-in-dry-run",
                    "--knowledge",
                    str(knowledge_path),
                ]
            )

        self.assertEqual(2, status)
        enrich.assert_not_called()
        self.assertIn("must contain a JSON array", errors.getvalue())

    def test_dry_run_refuses_enrichment_without_an_explicit_opt_in(self):
        errors = io.StringIO()
        with patch("case_analyzer.cli.enrich_case") as enrich, redirect_stderr(errors):
            status = cli.main([str(self.case_path), "--enrich", "--dry-run"])

        self.assertEqual(2, status)
        enrich.assert_not_called()
        self.assertIn("--allow-enrichment-in-dry-run", errors.getvalue())

    def test_dry_run_opt_in_warns_that_providers_are_still_contacted(self):
        output = io.StringIO()
        errors = io.StringIO()
        with patch("case_analyzer.cli.enrich_case") as enrich:
            enrich.return_value = SimpleNamespace(observations=[], truncated=False, stopped_early=False)
            with redirect_stdout(output), redirect_stderr(errors):
                status = cli.main(
                    [str(self.case_path), "--enrich", "--dry-run", "--allow-enrichment-in-dry-run"]
                )

        self.assertEqual(0, status)
        self.assertIn("even with --dry-run", errors.getvalue())

    def test_enrichment_passes_configured_abuseipdb_key(self):
        with patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test-abuse-key"}, clear=False):
            with patch("case_analyzer.cli.enrich_case") as enrich:
                enrich.return_value = SimpleNamespace(observations=[], truncated=False, stopped_early=False)
                status = cli.main(
                    [str(self.case_path), "--enrich", "--dry-run", "--allow-enrichment-in-dry-run"]
                )

        self.assertEqual(0, status)
        self.assertEqual("test-abuse-key", enrich.call_args.kwargs["abuseipdb_api_key"])

    def test_enrichment_prints_summary_without_corrupting_json_stdout(self):
        self.case_path.write_text(
            json.dumps({"id": "1", "title": "Example", "destinationAddress": "999.1.1.1"}),
            encoding="utf-8",
        )
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = cli.main(
                [str(self.case_path), "--enrich", "--dry-run", "--allow-enrichment-in-dry-run"]
            )

        self.assertEqual(0, status)
        json.loads(output.getvalue())
        self.assertIn("found=0 not_found=0 skipped=1 error=0", errors.getvalue())
        self.assertIn("stopped_early=no", errors.getvalue())

    def test_oversized_input_is_rejected_before_it_is_parsed(self):
        errors = io.StringIO()
        with redirect_stderr(errors):
            status = cli.main([str(self.case_path), "--dry-run", "--max-input-bytes", "10"])

        self.assertEqual(2, status)
        self.assertIn("input limit", errors.getvalue())

    def test_size_limit_can_be_disabled(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = cli.main([str(self.case_path), "--dry-run", "--max-input-bytes", "0"])

        self.assertEqual(0, status)


if __name__ == "__main__":
    unittest.main()
