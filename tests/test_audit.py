"""Improvement-plan item 8: `--audit` control assessment.

Everything here is offline. The mode ships without a live run, matching how `--summary`
was rolled out: the schema, the control validation, and the coverage check are all
deterministic, and they are the parts an audit's credibility rests on.
"""

import json
import unittest
from importlib.resources import files

from case_analyzer.checks import (
    check_audit,
    control_coverage,
    missing_rationales,
    unresolved_audit_citations,
)
from case_analyzer.controls import Control, describe, parse_controls
from case_analyzer.schemas import CaseAuditReport, ControlAssessment

_CASE = {
    "case_id": "1",
    "title": "Example",
    "status": "open",
    "source_data": {"owner_name": "a.analyst", "comments": [{"comment": "isolation approved"}]},
}


def _control(control_id: str, **overrides) -> Control:
    base = {"control_id": control_id, "requirement": "must do the thing"}
    return Control(**{**base, **overrides})


def _assessment(control_id: str, **overrides) -> ControlAssessment:
    base = {
        "control_id": control_id,
        "status": "insufficient_evidence",
        "rationale": "the export does not record it",
    }
    return ControlAssessment(**{**base, **overrides})


def _report(assessments) -> CaseAuditReport:
    return CaseAuditReport(digest="d", assessments=assessments)


class ControlParsingTests(unittest.TestCase):
    """Validation that runs *before* the request, so a bad set costs nothing."""

    def test_a_well_formed_set_parses(self):
        controls = parse_controls(
            [
                {"control_id": "IR-1.1", "requirement": "own it", "policy_ref": "SOC-IRP"},
                {"record_type": "control", "control_id": "IR-2.3", "requirement": "rate it"},
            ]
        )

        self.assertEqual(["IR-1.1", "IR-2.3"], [control.control_id for control in controls])

    def test_an_empty_control_set_is_refused(self):
        """Auditing against nothing would report vacuous full coverage."""
        with self.assertRaises(ValueError) as caught:
            parse_controls([])

        self.assertIn("--audit needs a control set", str(caught.exception))

    def test_duplicate_identities_are_refused(self):
        """`exactly one assessment per control` is unmatchable when two controls share a key."""
        with self.assertRaises(ValueError) as caught:
            parse_controls(
                [
                    {"control_id": "IR-1.1", "requirement": "a"},
                    {"control_id": "IR-1.1", "requirement": "b"},
                ]
            )

        self.assertIn("appears 2 times", str(caught.exception))

    def test_the_same_id_in_two_policies_is_allowed(self):
        """Identity is `(policy_ref, control_id)`, so two policies can both number a control 4.2.

        This is the decision most likely to be revisited against a real policy export, so
        it is pinned: if identity ever narrows to `control_id` alone, this test fails
        rather than the behavior changing quietly.
        """
        controls = parse_controls(
            [
                {"control_id": "4.2", "requirement": "a", "policy_ref": "SOC-IRP"},
                {"control_id": "4.2", "requirement": "b", "policy_ref": "DATA-HANDLING"},
            ]
        )

        self.assertEqual(2, len(controls))
        self.assertEqual([("SOC-IRP", "4.2"), ("DATA-HANDLING", "4.2")], [c.key for c in controls])

    def test_an_empty_control_id_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            parse_controls([{"control_id": "  ", "requirement": "a"}])

        self.assertIn("empty control_id", str(caught.exception))

    def test_a_control_without_a_requirement_is_refused(self):
        """Inferring a requirement from a title invites inventing the standard being judged."""
        with self.assertRaises(ValueError) as caught:
            parse_controls([{"control_id": "IR-1.1", "title": "Ownership"}])

        self.assertIn("IR-1.1", str(caught.exception))

    def test_a_record_declaring_another_type_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            parse_controls([{"record_type": "policy", "control_id": "X", "requirement": "a"}])

        self.assertIn("record_type", str(caught.exception))

    def test_a_non_object_record_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            parse_controls(["IR-1.1"])

        self.assertIn("not an object", str(caught.exception))

    def test_every_problem_is_reported_not_only_the_first(self):
        """An operator fixing a control file should see the whole list in one pass."""
        with self.assertRaises(ValueError) as caught:
            parse_controls([{"control_id": "", "requirement": "a"}, "nope"])

        message = str(caught.exception)
        self.assertIn("empty control_id", message)
        self.assertIn("not an object", message)

    def test_unknown_fields_survive_for_the_model_to_read(self):
        """A real policy export carries fields this schema cannot anticipate."""
        controls = parse_controls(
            [{"control_id": "IR-1.1", "requirement": "a", "framework": "NIST 800-61"}]
        )

        self.assertEqual("NIST 800-61", controls[0].framework)

    def test_describe_names_the_policies(self):
        controls = parse_controls(
            [
                {"control_id": "A", "requirement": "a", "policy_ref": "SOC-IRP"},
                {"control_id": "B", "requirement": "b", "policy_ref": "DATA-HANDLING"},
            ]
        )

        self.assertEqual("2 control(s) from DATA-HANDLING, SOC-IRP", describe(controls))


class CoverageTests(unittest.TestCase):
    """The claim an audit rests on, checked in Python rather than asked of the model."""

    def test_one_assessment_per_control_is_clean(self):
        controls = [_control("A"), _control("B")]
        report = _report([_assessment("A"), _assessment("B")])

        self.assertEqual([], control_coverage(report, controls))

    def test_a_dropped_control_is_reported(self):
        """Silently omitted, a control reads as one that raised no concern."""
        controls = [_control("A"), _control("B")]
        report = _report([_assessment("A")])

        self.assertEqual(
            ["Control B was supplied but received no assessment."],
            control_coverage(report, controls),
        )

    def test_a_duplicated_control_is_reported(self):
        controls = [_control("A")]
        report = _report([_assessment("A"), _assessment("A", status="pass")])

        self.assertEqual(
            ["Control A received 2 assessments; expected exactly one."],
            control_coverage(report, controls),
        )

    def test_an_invented_control_is_reported(self):
        controls = [_control("A")]
        report = _report([_assessment("A"), _assessment("Z")])

        self.assertEqual(
            ["Assessment Z names a control that was not supplied."],
            control_coverage(report, controls),
        )

    def test_reordered_assessments_are_still_matched(self):
        """Matching is by identity, never by list position."""
        controls = [_control("A"), _control("B")]
        report = _report([_assessment("B"), _assessment("A")])

        self.assertEqual([], control_coverage(report, controls))

    def test_policy_ref_participates_in_matching(self):
        """An assessment naming the right id under the wrong policy is not coverage."""
        controls = [_control("4.2", policy_ref="SOC-IRP")]
        report = _report([_assessment("4.2", policy_ref="DATA-HANDLING")])

        problems = control_coverage(report, controls)
        self.assertIn("Control SOC-IRP 4.2 was supplied but received no assessment.", problems)
        self.assertIn(
            "Assessment DATA-HANDLING 4.2 names a control that was not supplied.", problems
        )

    def test_surrounding_whitespace_does_not_break_matching(self):
        controls = [_control("A", policy_ref="SOC-IRP")]
        report = _report([_assessment(" A ", policy_ref=" SOC-IRP ")])

        self.assertEqual([], control_coverage(report, controls))


class RationaleTests(unittest.TestCase):
    def test_a_blank_rationale_is_reported(self):
        """Otherwise `not_applicable` is the cheapest exit from a control that lacks evidence."""
        report = _report([_assessment("A", status="not_applicable", rationale="   ")])

        self.assertEqual(
            ["Assessment A has status 'not_applicable' with no rationale."],
            missing_rationales(report),
        )

    def test_a_present_rationale_is_clean(self):
        self.assertEqual([], missing_rationales(_report([_assessment("A")])))


class AuditCitationTests(unittest.TestCase):
    def test_an_unresolvable_evidence_path_is_reported(self):
        report = _report([_assessment("A", evidence_paths=["source_data.nope"])])

        self.assertEqual(1, len(unresolved_audit_citations(report, _CASE)))

    def test_a_resolvable_evidence_path_is_clean(self):
        report = _report([_assessment("A", evidence_paths=["source_data.owner_name"])])

        self.assertEqual([], unresolved_audit_citations(report, _CASE))

    def test_no_citation_is_acceptable(self):
        """`insufficient_evidence` usually has nothing to cite, and that is correct."""
        report = _report([_assessment("A", evidence_paths=[])])

        self.assertEqual([], unresolved_audit_citations(report, _CASE))

    def test_check_audit_composes_every_check(self):
        controls = [_control("A"), _control("B")]
        report = _report([_assessment("A", rationale="", evidence_paths=["source_data.nope"])])

        problems = check_audit(report, _CASE, controls)
        self.assertEqual(3, len(problems), problems)


class AuditPromptTests(unittest.TestCase):
    """The prompt carries the guarantees the schema cannot express."""

    def setUp(self):
        self.prompt = files("case_analyzer.prompts").joinpath("audit.md").read_text(encoding="utf-8")

    def test_the_prompt_states_every_status(self):
        for status in ("pass", "fail", "not_applicable", "insufficient_evidence"):
            self.assertIn(f"`{status}`", self.prompt)

    def test_the_prompt_separates_absence_from_non_compliance(self):
        """The distinction the mode exists for: not documented is not the same as not done."""
        self.assertIn("does not mean the action did not happen", self.prompt)

    def test_the_prompt_carries_the_untrusted_data_rule(self):
        """A case asserting its own compliance must not be able to grant itself a pass."""
        self.assertIn("untrusted data", self.prompt)
        self.assertIn("audited", self.prompt)

    def test_the_prompt_requires_verbatim_identifiers(self):
        """Coverage matching depends on the model echoing both halves of the identity."""
        self.assertIn("verbatim", self.prompt)
        self.assertIn("policy_ref", self.prompt)

    def test_the_prompt_states_it_does_not_close_a_case(self):
        self.assertIn("human reviewer", self.prompt)


class ExampleControlSetTests(unittest.TestCase):
    def test_the_recorded_example_control_set_is_valid(self):
        """The shipped example must survive the same validation an operator's set does."""
        records = json.loads(
            (files("case_analyzer").joinpath("../../examples/audit/controls.json"))
            .resolve()
            .read_text(encoding="utf-8")
        )
        controls = parse_controls(records)

        self.assertEqual(6, len(controls))
        self.assertEqual({"SOC-IRP", "DATA-HANDLING"}, {c.policy_ref for c in controls})


if __name__ == "__main__":
    unittest.main()
