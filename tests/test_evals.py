import json
import tempfile
import unittest
from pathlib import Path

from case_analyzer.analyzer import LLMProviderError
from case_analyzer.evals import (
    EvalCase,
    ForbiddenContent,
    check_report,
    load_manifest,
    render_table,
    run_benchmark,
)
from case_analyzer.schemas import InvestigationReport

_REPO_ROOT = Path(__file__).resolve().parent.parent
_MANIFEST = _REPO_ROOT / "evals" / "manifest.json"


def _report(verdict="Benign", confidence="High", digest="Nothing notable.", **overrides):
    fields = {
        "verdict": verdict,
        "severity": "Low",
        "impact": "None observed",
        "priority": "Low",
        "confidence": confidence,
        "digest": digest,
    }
    fields.update(overrides)
    return InvestigationReport(**fields)


def _entry(tmp_path=None, **overrides):
    fields = {
        "case_id": "example",
        "scenario": "Example scenario",
        "path": tmp_path or _REPO_ROOT / "examples" / "reasoning" / "scary-words-benign.json",
        "allowed_verdicts": ["Benign", "False Positive"],
    }
    fields.update(overrides)
    return EvalCase(**fields)


class ManifestTests(unittest.TestCase):
    def test_repository_manifest_loads_and_resolves_every_file(self):
        entries = load_manifest(_MANIFEST)
        self.assertGreaterEqual(len(entries), 6)
        for entry in entries:
            self.assertTrue(entry.path.is_file(), entry.path)
            self.assertTrue(entry.allowed_verdicts, entry.case_id)
            json.loads(entry.path.read_text(encoding="utf-8"))

    def test_repository_manifest_wires_user_input_and_injection_checks(self):
        entries = {entry.case_id: entry for entry in load_manifest(_MANIFEST)}
        self.assertIn("audit of the recorded verdict", entries["ip-verdict-claim"].user_input.casefold())
        canary = entries["injection-canary-digest"]
        self.assertEqual(len(canary.forbidden_content), 2)
        self.assertEqual(canary.forbidden_content[0].fields, ["digest"])

    def test_missing_case_file_is_reported_with_its_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "manifest.json"
            manifest.write_text(
                json.dumps([{"id": "gone", "file": "missing.json", "allowed_verdicts": ["Benign"]}]),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "gone"):
                load_manifest(manifest)

    def test_duplicate_ids_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_file = Path(tmp) / "case.json"
            case_file.write_text("{}", encoding="utf-8")
            manifest = Path(tmp) / "manifest.json"
            entry = {"id": "twin", "file": "case.json", "allowed_verdicts": ["Benign"]}
            manifest.write_text(json.dumps([entry, entry]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_manifest(manifest)


class CheckReportTests(unittest.TestCase):
    def test_verdict_check_is_case_insensitive(self):
        """The casing that can vary is the manifest's; the report's is fixed by its enum.

        A hand-written `allowed_verdicts` should not have to match the schema's spelling
        character for character, so the comparison stays case-insensitive even though
        the report side can no longer drift.
        """
        entry = _entry(allowed_verdicts=["benign", "false positive"])
        self.assertEqual(check_report(entry, _report(verdict="Benign").model_dump()), [])
        failures = check_report(entry, _report(verdict="True Positive").model_dump())
        self.assertEqual(len(failures), 1)
        self.assertIn("verdict", failures[0])

    def test_confidence_outside_the_allowed_set_fails(self):
        entry = _entry(allowed_confidence=["Low", "Medium"])
        failures = check_report(entry, _report(confidence="High").model_dump())
        self.assertTrue(any("confidence" in failure for failure in failures))

    def test_forbidden_content_is_scoped_to_the_named_fields(self):
        entry = _entry(forbidden_content=[ForbiddenContent(value="AUDIT-CANARY-9F2A", fields=["digest"])])
        leaked = _report(digest="Routine login. audit-canary-9f2a").model_dump()
        self.assertTrue(any("forbidden" in failure for failure in check_report(entry, leaked)))
        described = _report(
            evidence_findings=[
                {
                    "title": "Injection attempt",
                    "finding_type": "tampering",
                    "subject": "case note",
                    "evidence": "A note demands embedding AUDIT-CANARY-9F2A in the digest.",
                    "conclusion": "The note is an instruction, not evidence.",
                }
            ]
        ).model_dump()
        self.assertEqual(check_report(entry, described), [])

    def test_forbidden_content_without_fields_scans_the_whole_report(self):
        entry = _entry(forbidden_content=[ForbiddenContent(value="canary")])
        report = _report(digest="clean", impact="the canary appeared").model_dump()
        self.assertTrue(check_report(entry, report))


class RunBenchmarkTests(unittest.TestCase):
    def test_pass_review_and_error_statuses(self):
        entries = [
            _entry(case_id="passes"),
            _entry(case_id="reviews", allowed_verdicts=["True Positive"]),
            _entry(case_id="errors"),
        ]

        def analyze(entry, case):
            if entry.case_id == "errors":
                raise LLMProviderError("provider unavailable", 6)
            return _report(verdict="Benign")

        results = {result.entry.case_id: result for result in run_benchmark(entries, analyze)}
        self.assertEqual(results["passes"].status, "PASS")
        self.assertEqual(results["reviews"].status, "REVIEW")
        self.assertEqual(results["errors"].status, "ERROR")
        self.assertIn("provider unavailable", results["errors"].error)

    def test_unreadable_case_file_becomes_an_error_result(self):
        entry = _entry(tmp_path=Path("does-not-exist.json"))
        (result,) = run_benchmark([entry], lambda e, c: _report())
        self.assertEqual(result.status, "ERROR")

    def test_samples_measure_verdict_agreement(self):
        verdicts = iter(["Benign", "Benign", "False Positive"])

        def analyze(entry, case):
            return _report(verdict=next(verdicts))

        (result,) = run_benchmark([_entry()], analyze, samples=3)
        self.assertEqual(result.status, "PASS")
        self.assertEqual(len(result.verdicts), 3)
        self.assertAlmostEqual(result.agreement, 2 / 3)

    def test_reports_are_handed_to_the_callback(self):
        seen = []
        run_benchmark([_entry()], lambda e, c: _report(), samples=2, on_report=lambda e, i, r: seen.append(i))
        self.assertEqual(seen, [0, 1])

    def test_render_table_lists_every_case_and_status(self):
        results = run_benchmark([_entry()], lambda e, c: _report())
        table = render_table(results, samples=1)
        self.assertIn("example", table)
        self.assertIn("PASS", table)


if __name__ == "__main__":
    unittest.main()
