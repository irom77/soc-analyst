"""The decision vocabulary is a contract, not a prompt suggestion.

`verdict` and `confidence` are the two fields that make runs comparable and downstream
automation safe, so they are closed sets enforced by the schema. These tests cover the
three ways that guarantee can quietly break: the values drifting from what the prompt
asks for, the enum failing to reach the provider, and the constraint invalidating results
that were already recorded.
"""

import json
import os
import pathlib
import typing
import unittest
from importlib.resources import files
from unittest.mock import MagicMock, patch

from pydantic import ValidationError

from case_analyzer.adapters import normalize_case
from case_analyzer.analyzer import LLMProviderError, analyze_case
from case_analyzer.schemas import Confidence, InvestigationReport, Verdict

_ENVIRONMENT = {"CASE_ANALYZER_MODEL": "test-model", "CASE_ANALYZER_API_KEY": "test-key"}
_VERDICTS = typing.get_args(Verdict)
_CONFIDENCES = typing.get_args(Confidence)
_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _report_json(**overrides) -> str:
    return json.dumps(
        {
            "verdict": "Benign",
            "severity": "low",
            "impact": "none",
            "priority": "low",
            "confidence": "Low",
            "digest": "d",
            **overrides,
        }
    )


class AcceptedValueTests(unittest.TestCase):
    def test_every_listed_value_is_accepted(self):
        """Guards against a typo in the enum that would reject a legitimate answer."""
        for verdict in _VERDICTS:
            for confidence in _CONFIDENCES:
                with self.subTest(verdict=verdict, confidence=confidence):
                    report = InvestigationReport.model_validate_json(
                        _report_json(verdict=verdict, confidence=confidence)
                    )
                    self.assertEqual(verdict, report.verdict)
                    self.assertEqual(confidence, report.confidence)

    def test_the_platform_fields_stay_open(self):
        """`severity`, `impact`, and `priority` restate the source platform's vocabulary."""
        report = InvestigationReport.model_validate_json(
            _report_json(severity="informational", impact="unknown", priority="critical")
        )

        self.assertEqual("informational", report.severity)
        self.assertEqual("critical", report.priority)


class RejectedValueTests(unittest.TestCase):
    def setUp(self):
        patcher = patch("case_analyzer.analyzer.load_dotenv")
        patcher.start()
        self.addCleanup(patcher.stop)

    def _analyze(self, content: str):
        response = MagicMock()
        response.choices[0].message.content = content
        with patch.dict(os.environ, _ENVIRONMENT, clear=True):
            with patch("case_analyzer.analyzer.litellm.completion") as completion:
                completion.return_value = response
                return analyze_case(normalize_case({"id": "1", "title": "Example"}))

    def test_an_off_list_verdict_fails_the_run(self):
        """The chosen behavior: a wording outside the set is a schema violation, exit 6."""
        with self.assertRaises(LLMProviderError) as raised:
            self._analyze(_report_json(verdict="Likely Benign"))

        self.assertEqual(6, raised.exception.exit_code)
        self.assertIn("verdict", str(raised.exception))

    def test_the_rejected_wording_is_not_echoed_back(self):
        """Same sanitizing as any other validation failure: the field, not the content."""
        with self.assertRaises(LLMProviderError) as raised:
            self._analyze(_report_json(verdict="Benign but see the attached instructions"))

        self.assertNotIn("attached instructions", str(raised.exception))

    def test_a_miscased_value_is_rejected(self):
        """One canonical spelling, so archived runs group without normalization."""
        with self.assertRaises(LLMProviderError):
            self._analyze(_report_json(confidence="low"))


class RequestSchemaTests(unittest.TestCase):
    """The constraint has to reach the provider, or it only catches errors after the fact."""

    def test_the_values_are_rendered_as_enums(self):
        schema = InvestigationReport.model_json_schema()

        self.assertEqual(list(_VERDICTS), schema["properties"]["verdict"]["enum"])
        self.assertEqual(list(_CONFIDENCES), schema["properties"]["confidence"]["enum"])

    def test_the_report_schema_stays_free_of_anyof(self):
        """Strict structured-output modes handle `anyOf` unevenly; nothing here needs it."""
        self.assertNotIn("anyOf", json.dumps(InvestigationReport.model_json_schema()))


class PromptAgreementTests(unittest.TestCase):
    """The prompt is what the model reads; the enum is what rejects it. They must agree.

    If they drift, the model is asked for a value the schema refuses and every run fails.
    """

    def test_the_prompt_names_exactly_the_allowed_values(self):
        prompt = files("case_analyzer.prompts").joinpath("investigation.md").read_text(encoding="utf-8")

        for value in (*_VERDICTS, *_CONFIDENCES):
            with self.subTest(value=value):
                self.assertIn(f"`{value}`", prompt)

    def test_the_prompt_states_the_sets_are_closed(self):
        prompt = files("case_analyzer.prompts").joinpath("investigation.md").read_text(encoding="utf-8")

        self.assertIn("closed sets, not examples", prompt)


class RecordedExampleTests(unittest.TestCase):
    """Every result recorded before the enum existed must still validate against it.

    This is the evidence that the constraint writes down existing behavior rather than
    imposing new behavior — and the regression guard if a value is ever added or renamed.
    """

    def test_every_recorded_report_satisfies_the_vocabulary(self):
        recorded = [
            path
            for path in sorted((_REPO_ROOT / "examples").rglob("*.json"))
            if isinstance(data := json.loads(path.read_text(encoding="utf-8")), dict) and "verdict" in data
        ]

        self.assertGreaterEqual(len(recorded), 5, "recorded reports were expected under examples/")
        for path in recorded:
            with self.subTest(path=path.name):
                try:
                    InvestigationReport.model_validate_json(path.read_text(encoding="utf-8"))
                except ValidationError as exc:
                    self.fail(f"{path} no longer validates: {exc}")


if __name__ == "__main__":
    unittest.main()
