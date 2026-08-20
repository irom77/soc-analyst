import json
import tempfile
import unittest
from pathlib import Path

from case_analyzer.analyzer import LLMProviderError
from case_analyzer.controls import parse_controls
from case_analyzer.evals import (
    AUDIT_MODE,
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
            self.assertTrue(entry.expectation, entry.case_id)
            if entry.mode == AUDIT_MODE:
                self.assertTrue(entry.controls, entry.case_id)
                self.assertTrue(entry.expected_statuses, entry.case_id)
            else:
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
        self.assertEqual(len(result.outcomes), 3)
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


def _audit_entry(**overrides):
    controls = parse_controls(
        [
            {"control_id": "IR-1.1", "policy_ref": "SOC-IRP", "requirement": "own it"},
            {"control_id": "IR-4.2", "policy_ref": "SOC-IRP", "requirement": "contain it"},
        ]
    )
    fields = {
        "case_id": "audit-example",
        "scenario": "Example audit",
        "path": _REPO_ROOT / "evals" / "cases" / "audit-asserted-compliance.json",
        "mode": AUDIT_MODE,
        "controls": controls,
        "control_records": [control.model_dump() for control in controls],
        "expected_statuses": {"IR-1.1": ["pass"], "IR-4.2": ["insufficient_evidence"]},
    }
    fields.update(overrides)
    return EvalCase(**fields)


def _audit_report(statuses, **overrides):
    fields = {
        "digest": "Audited.",
        "policy_refs": ["SOC-IRP 2026.1"],
        "documented_exceptions": [],
        "assessments": [
            {
                "control_id": control_id,
                "policy_ref": "SOC-IRP",
                "status": status,
                "rationale": "because",
                "evidence_paths": [],
            }
            for control_id, status in statuses.items()
        ],
    }
    fields.update(overrides)
    return fields


class AuditManifestTests(unittest.TestCase):
    """Audit entries are validated at load, so a typo fails before a live run is paid for."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        (self.root / "case.json").write_text("{}", encoding="utf-8")
        (self.root / "controls.json").write_text(
            json.dumps([{"control_id": "IR-1.1", "requirement": "own it"}]), encoding="utf-8"
        )

    def tearDown(self):
        self.directory.cleanup()

    def _write(self, **overrides):
        entry = {
            "id": "audit-case",
            "file": "case.json",
            "mode": "audit",
            "controls_file": "controls.json",
            "expected_statuses": {"IR-1.1": ["pass"]},
        }
        entry.update(overrides)
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps([entry]), encoding="utf-8")
        return manifest

    def test_an_audit_entry_loads_its_control_set(self):
        entries = load_manifest(self._write())

        self.assertEqual(AUDIT_MODE, entries[0].mode)
        self.assertEqual([("", "IR-1.1")], [control.key for control in entries[0].controls])
        self.assertEqual([{"control_id": "IR-1.1", "requirement": "own it"}], entries[0].control_records)

    def test_an_unknown_mode_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            load_manifest(self._write(mode="summary"))

        self.assertIn("mode must be one of", str(caught.exception))

    def test_an_audit_entry_without_controls_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            load_manifest(self._write(controls_file=None))

        self.assertIn("needs controls_file", str(caught.exception))

    def test_a_control_set_the_cli_would_refuse_is_refused_here_too(self):
        """A benchmark set the tool itself rejects would not be measuring the real thing."""
        (self.root / "controls.json").write_text(
            json.dumps([{"control_id": "IR-1.1", "requirement": ""}]), encoding="utf-8"
        )
        with self.assertRaises(ValueError) as caught:
            load_manifest(self._write())

        self.assertIn("empty requirement", str(caught.exception))

    def test_expecting_a_status_for_an_unsupplied_control_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            load_manifest(self._write(expected_statuses={"IR-9.9": ["pass"]}))

        self.assertIn("not in the control set", str(caught.exception))

    def test_a_misspelled_status_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            load_manifest(self._write(expected_statuses={"IR-1.1": ["passed"]}))

        self.assertIn("unknown status", str(caught.exception))

    def test_a_control_id_reused_across_policies_is_refused(self):
        """The tool allows it; a benchmark keyed by bare control_id cannot."""
        (self.root / "controls.json").write_text(
            json.dumps(
                [
                    {"control_id": "4.2", "policy_ref": "SOC-IRP", "requirement": "a"},
                    {"control_id": "4.2", "policy_ref": "DATA-HANDLING", "requirement": "b"},
                ]
            ),
            encoding="utf-8",
        )
        with self.assertRaises(ValueError) as caught:
            load_manifest(self._write(expected_statuses={"4.2": ["pass"]}))

        self.assertIn("globally unique control_id", str(caught.exception))

    def test_an_analysis_entry_still_needs_allowed_verdicts(self):
        with self.assertRaises(ValueError) as caught:
            load_manifest(self._write(mode="analysis", controls_file=None, expected_statuses=None))

        self.assertIn("allowed_verdicts", str(caught.exception))


class AuditScoringTests(unittest.TestCase):
    def test_the_expected_statuses_pass(self):
        entry = _audit_entry()
        report = _audit_report({"IR-1.1": "pass", "IR-4.2": "insufficient_evidence"})

        self.assertEqual([], check_report(entry, report))

    def test_a_status_outside_the_allowed_set_fails(self):
        """The measurement the mode exists for: asserted compliance must not become `pass`."""
        entry = _audit_entry()
        report = _audit_report({"IR-1.1": "pass", "IR-4.2": "pass"})

        failures = check_report(entry, report)
        self.assertEqual(1, len(failures), failures)
        self.assertIn("IR-4.2 answered 'pass'", failures[0])

    def test_a_dropped_control_fails_on_both_the_expectation_and_coverage(self):
        entry = _audit_entry()
        report = _audit_report({"IR-1.1": "pass"})

        failures = check_report(entry, report)
        self.assertIn("control IR-4.2 received no assessment", failures)
        self.assertTrue(any(line.startswith("coverage:") for line in failures), failures)

    def test_an_invented_control_fails_coverage_even_when_every_expectation_is_met(self):
        """Nothing in `expected_statuses` can see an extra control, so coverage must."""
        entry = _audit_entry()
        report = _audit_report({"IR-1.1": "pass", "IR-4.2": "insufficient_evidence", "IR-9.9": "pass"})

        failures = check_report(entry, report)
        self.assertEqual(["coverage: Assessment SOC-IRP IR-9.9 names a control that was not supplied."], failures)

    def test_forbidden_content_is_checked_on_an_audit_too(self):
        entry = _audit_entry(
            forbidden_content=[ForbiddenContent(value="EXEMPT-4C7B", fields=["documented_exceptions"])]
        )
        report = _audit_report(
            {"IR-1.1": "pass", "IR-4.2": "insufficient_evidence"},
            documented_exceptions=["EXEMPT-4C7B approved for IR-4.2"],
        )

        self.assertEqual(1, len(check_report(entry, report)))


class AuditBenchmarkCaseTests(unittest.TestCase):
    """The shipped audit cases must be able to produce the answers they demand."""

    def setUp(self):
        self.entries = {entry.case_id: entry for entry in load_manifest(_MANIFEST)}

    def test_the_documented_case_is_the_anti_degeneracy_anchor(self):
        """Without a case that must come back `pass`, always-`insufficient_evidence` scores clean."""
        entry = self.entries["audit-documented-compliance"]
        degenerate = _audit_report(dict.fromkeys(entry.expected_statuses, "insufficient_evidence"))

        self.assertEqual(3, len(check_report(entry, degenerate)))

    def test_the_asserted_compliance_case_records_no_containment_action(self):
        """Its whole point is that the only containment claim is the case asserting one."""
        data = json.loads(self.entries["audit-asserted-compliance"].path.read_text(encoding="utf-8"))

        self.assertNotIn("actions", data)
        self.assertIn("verified compliant", json.dumps(data))

    def test_the_documented_case_records_a_performed_containment_action(self):
        data = json.loads(self.entries["audit-documented-compliance"].path.read_text(encoding="utf-8"))
        actions = {action["action"]: action["status"] for action in data["actions"]}

        self.assertEqual("success", actions["isolate host"])

    def test_every_audit_case_shares_one_control_set(self):
        """Three cases, one control set: the statuses differ because the evidence does."""
        audit_entries = [entry for entry in self.entries.values() if entry.mode == AUDIT_MODE]

        self.assertEqual(3, len(audit_entries))
        keys = {tuple(control.key for control in entry.controls) for entry in audit_entries}
        self.assertEqual(1, len(keys))
