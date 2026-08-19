import unittest
from importlib.resources import files

from case_analyzer.checks import (
    check_report,
    inconsistent_truncation,
    resolve_case_path,
    unresolved_citations,
)
from case_analyzer.schemas import LIST_CAPS, EvidenceFinding, InvestigationReport, TruncationNote

_CASE = {
    "case_id": "1",
    "title": "Example",
    "artifacts": [{"cef": {"destinationDnsDomain": "evil.example"}}, {"cef": {}}],
    "source_data": {"grid": [[{"leaf": "value"}]]},
    "description": None,
}


def _report(**overrides) -> InvestigationReport:
    base = {
        "verdict": "Suspicious",
        "severity": "medium",
        "impact": "none",
        "priority": "medium",
        "confidence": "Low",
        "digest": "d",
    }
    return InvestigationReport(**{**base, **overrides})


def _finding(title: str, paths: list[str]) -> EvidenceFinding:
    return EvidenceFinding(
        title=title, finding_type="t", subject="s", evidence="e", conclusion="c", source_paths=paths
    )


class PathResolutionTests(unittest.TestCase):
    """The grammar is the one enrichment already emits, so both sides agree on a path."""

    def test_paths_that_resolve(self):
        for path in (
            "title",
            "artifacts[0].cef.destinationDnsDomain",
            "source_data.grid[0][0].leaf",
            # A trailing marker records where a derived observable came from; it is not
            # a traversable segment, so it is stripped before resolving.
            "artifacts[0].cef.destinationDnsDomain#host",
        ):
            with self.subTest(path=path):
                self.assertTrue(resolve_case_path(_CASE, path))

    def test_the_redundant_case_prefix_is_accepted(self):
        """A live run cited every path as `case.…`; the check should not read as 16 defects."""
        self.assertTrue(resolve_case_path(_CASE, "case.artifacts[0].cef.destinationDnsDomain"))

    def test_a_real_top_level_case_key_wins_over_the_prefix_rescue(self):
        """The unprefixed form is canonical, so stripping must never shadow a real key."""
        case = {"case": {"nested": "own key"}, "nested": "root key"}

        self.assertTrue(resolve_case_path(case, "case.nested"))
        self.assertFalse(resolve_case_path(case, "case.absent"))

    def test_a_key_present_but_null_still_resolves(self):
        """The path exists and the export left it empty — not the same as a wrong path."""
        self.assertTrue(resolve_case_path(_CASE, "description"))

    def test_paths_that_do_not_resolve(self):
        for path in (
            "no_such_key",
            "artifacts[0].cef.no_such_field",
            "artifacts[9].cef",  # index past the end
            "title[0]",  # index into a string
            "title.deeper",  # traverse into a scalar
            "",
            "#host",  # nothing but a marker
        ):
            with self.subTest(path=path):
                self.assertFalse(resolve_case_path(_CASE, path))


class CitationCheckTests(unittest.TestCase):
    def test_a_fabricated_path_is_reported_with_its_finding(self):
        report = _report(evidence_findings=[_finding("Beaconing", ["artifacts[0].cef.invented"])])

        problems = unresolved_citations(report, _CASE)

        self.assertEqual(1, len(problems))
        self.assertIn("Beaconing", problems[0])
        self.assertIn("artifacts[0].cef.invented", problems[0])

    def test_a_resolving_path_is_silent(self):
        report = _report(
            evidence_findings=[_finding("Beaconing", ["artifacts[0].cef.destinationDnsDomain"])]
        )

        self.assertEqual([], unresolved_citations(report, _CASE))

    def test_an_uncited_finding_is_not_a_problem(self):
        """Absence means "uncited", which the schema permits; flagging it punishes honesty."""
        report = _report(evidence_findings=[_finding("Cross-case reasoning", [])])

        self.assertEqual([], unresolved_citations(report, _CASE))


class TruncationCheckTests(unittest.TestCase):
    def test_a_list_at_its_cap_may_claim_truncation(self):
        report = _report(
            unknowns=[f"u{index}" for index in range(LIST_CAPS["unknowns"])],
            truncated_fields=[TruncationNote(field="unknowns", omitted_count=12)],
        )

        self.assertEqual([], inconsistent_truncation(report))

    def test_a_list_below_its_cap_cannot_have_been_truncated(self):
        report = _report(unknowns=["only one"], truncated_fields=[TruncationNote(field="unknowns")])

        problems = inconsistent_truncation(report)

        self.assertEqual(1, len(problems))
        self.assertIn("unknowns", problems[0])
        self.assertIn(f"1 of a possible {LIST_CAPS['unknowns']}", problems[0])

    def test_both_check_families_are_reported_together(self):
        report = _report(
            evidence_findings=[_finding("Beaconing", ["nope"])],
            truncated_fields=[TruncationNote(field="unknowns")],
        )

        self.assertEqual(2, len(check_report(report, _CASE)))


class CapDocumentationTests(unittest.TestCase):
    """`LIST_CAPS` and the prompt state the same numbers, in different words.

    The prompt is what actually constrains the model; `LIST_CAPS` is what the check
    measures against. If they drift, the check silently starts asking the wrong question.
    """

    LABELS = {
        "affected_assets": "affected assets",
        "evidence_findings": "evidence findings",
        "attack_chain": "attack-chain steps",
        "attack_timeline": "timeline events",
        "ioc_indicators": "IOCs",
        "remediations": "remediations",
        "unknowns": "unknowns",
    }

    def test_every_cap_appears_in_the_prompt(self):
        prompt = files("case_analyzer.prompts").joinpath("investigation.md").read_text(encoding="utf-8")
        for field, cap in LIST_CAPS.items():
            with self.subTest(field=field):
                self.assertIn(f"{self.LABELS[field]} {cap}", prompt)

    def test_every_capped_list_on_the_report_has_an_entry(self):
        """A list field added without a cap would be unreportable as truncated."""
        list_fields = {
            name
            for name, info in InvestigationReport.model_fields.items()
            if name != "truncated_fields" and getattr(info.annotation, "__origin__", None) is list
        }

        self.assertEqual(list_fields, set(LIST_CAPS))


if __name__ == "__main__":
    unittest.main()
