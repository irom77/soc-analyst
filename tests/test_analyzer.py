import json
import os
import unittest
from unittest.mock import MagicMock, patch

from pydantic import ValidationError

from case_analyzer.adapters import normalize_case
from case_analyzer.analyzer import (
    LLMProviderError,
    analyze_case,
    build_analysis_messages,
    build_analysis_payload,
)
from case_analyzer.enrichment import enrich_case
from case_analyzer.schemas import InvestigationReport

_ENVIRONMENT = {"CASE_ANALYZER_MODEL": "test-model", "CASE_ANALYZER_API_KEY": "test-key"}


def _case():
    return normalize_case({"id": "1", "title": "Example"})


class PayloadTests(unittest.TestCase):
    def test_enrichment_reaches_the_model_payload(self):
        case = normalize_case({"id": "1", "title": "Example", "destinationDnsDomain": "example.com"})
        enrich_case(case, domain_lookup=lambda value, timeout: ("found", "test-dns", {}))

        payload = build_analysis_payload(case, knowledge_records=[{"a": 1}], user_input="focus")

        self.assertEqual([{"a": 1}], payload["knowledge"]["records"])
        self.assertEqual("focus", payload["user_input"])
        self.assertEqual(1, len(payload["case"]["case_analyzer_enrichment"]["observations"]))

    def test_messages_carry_the_system_prompt_and_json_payload(self):
        messages = build_analysis_messages(_case())

        self.assertIn("case_analyzer_enrichment", messages[0].content)
        self.assertEqual("Example", json.loads(messages[1].content)["case"]["title"])


class AnalyzeCaseTests(unittest.TestCase):
    def setUp(self):
        patcher = patch("case_analyzer.analyzer.load_dotenv")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_missing_model_is_an_actionable_input_error(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError) as raised:
                analyze_case(_case())

        self.assertIn("CASE_ANALYZER_MODEL", str(raised.exception))

    def test_missing_api_key_is_an_actionable_input_error(self):
        with patch.dict(os.environ, {"CASE_ANALYZER_MODEL": "test-model"}, clear=True):
            with self.assertRaises(ValueError) as raised:
                analyze_case(_case())

        self.assertIn("CASE_ANALYZER_API_KEY", str(raised.exception))

    def test_case_analyzer_model_configures_the_openai_compatible_client(self):
        environment = {
            "CASE_ANALYZER_MODEL": "openai-compatible-model",
            "CASE_ANALYZER_BASE_URL": "https://llm.example.test/v1",
            "CASE_ANALYZER_API_KEY": "test-key",
        }
        with patch.dict(os.environ, environment, clear=True):
            with patch("case_analyzer.analyzer.ChatOpenAI") as chat:
                chat.return_value.with_structured_output.return_value.invoke.return_value = (
                    InvestigationReport(
                        verdict="Benign",
                        severity="low",
                        impact="none",
                        priority="low",
                        confidence="low",
                        digest="d",
                    )
                )
                analyze_case(_case())

        self.assertEqual("openai-compatible-model", chat.call_args.kwargs["model"])
        self.assertEqual("https://llm.example.test/v1", chat.call_args.kwargs["base_url"])

    def test_request_timeout_is_forwarded_to_the_client(self):
        with patch.dict(os.environ, _ENVIRONMENT, clear=True):
            with patch("case_analyzer.analyzer.ChatOpenAI") as chat:
                chat.return_value.with_structured_output.return_value.invoke.return_value = (
                    InvestigationReport(
                        verdict="Benign",
                        severity="low",
                        impact="none",
                        priority="low",
                        confidence="low",
                        digest="d",
                    )
                )
                report = analyze_case(_case(), timeout=12.5)

        self.assertEqual("Benign", report.verdict)
        self.assertEqual(12.5, chat.call_args.kwargs["timeout"])
        self.assertEqual(0, chat.call_args.kwargs["max_retries"])

    def test_schema_mismatch_is_reported_without_the_raw_model_output(self):
        try:
            InvestigationReport.model_validate({"verdict": "Benign", "secret": "leaked value"})
        except ValidationError as exc:
            mismatch = exc

        with patch.dict(os.environ, _ENVIRONMENT, clear=True):
            with patch("case_analyzer.analyzer.ChatOpenAI") as chat:
                structured = MagicMock()
                structured.invoke.side_effect = mismatch
                chat.return_value.with_structured_output.return_value = structured
                with self.assertRaises(LLMProviderError) as raised:
                    analyze_case(_case())

        self.assertEqual(6, raised.exception.exit_code)
        self.assertIn("InvestigationReport schema", str(raised.exception))
        self.assertNotIn("leaked value", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
