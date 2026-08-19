import hashlib
import json
import os
import unittest
from unittest.mock import MagicMock, patch

from case_analyzer.adapters import normalize_case
from case_analyzer.analyzer import analyze_case, build_analysis_messages, summarize_case
from case_analyzer.enrichment import enrich_case
from case_analyzer.provenance import endpoint_host
from case_analyzer.schemas import (
    REPORT_SCHEMA_VERSION,
    AnalyzedReport,
    CaseSummary,
    InvestigationReport,
)

_ENVIRONMENT = {"CASE_ANALYZER_MODEL": "test-model", "CASE_ANALYZER_API_KEY": "test-key"}

_REPORT_JSON = json.dumps(
    {
        "verdict": "Benign",
        "severity": "low",
        "impact": "none",
        "priority": "low",
        "confidence": "low",
        "digest": "d",
    }
)


def _case():
    return normalize_case({"id": "1", "title": "Example"})


def _completion_response(content: str) -> MagicMock:
    response = MagicMock()
    response.choices[0].message.content = content
    return response


class _CallsProvider(unittest.TestCase):
    def setUp(self):
        patcher = patch("case_analyzer.analyzer.load_dotenv")
        patcher.start()
        self.addCleanup(patcher.stop)

    def _analyze(self, case=None, environment=None, **kwargs) -> AnalyzedReport:
        with patch.dict(os.environ, environment or _ENVIRONMENT, clear=True):
            with patch("case_analyzer.analyzer.litellm.completion") as completion:
                completion.return_value = _completion_response(kwargs.pop("content", _REPORT_JSON))
                self.completion = completion
                return analyze_case(case or _case(), **kwargs)


class ModelFacingSchemaTests(unittest.TestCase):
    """The run block is generated locally, so the model must never be asked for it.

    This is the first of the plan's pre-implementation review points. The separation is
    structural — `InvestigationReport` is the request schema, `AnalyzedReport` the saved
    one — and these tests are what keeps it from being undone by a convenient edit.
    """

    def test_the_request_schemas_do_not_carry_a_run_block(self):
        for schema in (InvestigationReport, CaseSummary):
            with self.subTest(schema=schema.__name__):
                self.assertNotIn("case_analyzer_run", schema.model_json_schema()["properties"])

    def test_the_saved_schemas_extend_the_request_schemas(self):
        """Additive by construction: a reader of `verdict` keeps working."""
        self.assertTrue(issubclass(AnalyzedReport, InvestigationReport))


class RequestSchemaTests(_CallsProvider):
    def test_the_provider_is_asked_for_the_model_facing_schema(self):
        self._analyze()

        self.assertIs(InvestigationReport, self.completion.call_args.kwargs["response_format"])

    def test_a_summary_request_is_asked_for_the_model_facing_schema(self):
        with patch.dict(os.environ, _ENVIRONMENT, clear=True):
            with patch("case_analyzer.analyzer.litellm.completion") as completion:
                completion.return_value = _completion_response('{"summary": "s"}')
                summarize_case(_case())

        self.assertIs(CaseSummary, completion.call_args.kwargs["response_format"])


class GuaranteedProvenanceTests(_CallsProvider):
    """The second review point: the guarantee belongs to the public call, not a helper.

    Nothing here opts in. `analyze_case` and `summarize_case` are the only supported
    entry points, and both attach the run block themselves, so the eval harness and
    library callers are provenanced without knowing the feature exists.
    """

    def test_analyze_case_returns_a_provenanced_report(self):
        report = self._analyze()

        self.assertEqual("Benign", report.verdict)
        self.assertEqual("test-model", report.case_analyzer_run.model)
        self.assertEqual(REPORT_SCHEMA_VERSION, report.case_analyzer_run.report_schema_version)

    def test_summarize_case_returns_a_provenanced_summary(self):
        with patch.dict(os.environ, _ENVIRONMENT, clear=True):
            with patch("case_analyzer.analyzer.litellm.completion") as completion:
                completion.return_value = _completion_response('{"summary": "s"}')
                summary = summarize_case(_case())

        self.assertEqual("s", summary.summary)
        self.assertEqual("test-model", summary.case_analyzer_run.model)

    def test_the_recorded_model_is_the_one_resolved_from_the_environment(self):
        """A value that came from `.env` must be recorded, not the empty flag."""
        report = self._analyze(environment={**_ENVIRONMENT, "CASE_ANALYZER_MODEL": "from-env"})

        self.assertEqual("from-env", report.case_analyzer_run.model)
        self.assertEqual("from-env", self.completion.call_args.kwargs["model"])


class PayloadHashTests(_CallsProvider):
    """The hashes identify the complete effective input, which the case file does not."""

    def test_the_hashes_match_the_messages_actually_sent(self):
        report = self._analyze()
        messages = build_analysis_messages(_case())

        run = report.case_analyzer_run
        self.assertEqual(hashlib.sha256(messages[0]["content"].encode()).hexdigest(), run.system_prompt_sha256)
        self.assertEqual(hashlib.sha256(messages[1]["content"].encode()).hexdigest(), run.payload_sha256)

    def test_analyst_guidance_changes_the_payload_hash(self):
        """The case file is identical in both runs; only the effective input differs."""
        plain = self._analyze().case_analyzer_run.payload_sha256
        guided = self._analyze(user_input="focus on lateral movement").case_analyzer_run.payload_sha256

        self.assertNotEqual(plain, guided)

    def test_enrichment_changes_the_payload_hash_and_sets_the_flag(self):
        case = normalize_case({"id": "1", "title": "Example", "destinationDnsDomain": "example.com"})
        enrich_case(case, domain_lookup=lambda value, timeout: ("found", "test-dns", {}))

        report = self._analyze(case=case)

        self.assertTrue(report.case_analyzer_run.has_enrichment)
        self.assertNotEqual(self._analyze().case_analyzer_run.payload_sha256, report.case_analyzer_run.payload_sha256)

    def test_the_convenience_flags_describe_the_payload(self):
        report = self._analyze(knowledge_records=[{"a": 1}], user_input="focus")

        run = report.case_analyzer_run
        self.assertTrue(run.has_knowledge)
        self.assertTrue(run.has_user_input)
        self.assertFalse(run.has_enrichment)

    def test_the_input_file_hash_is_optional(self):
        """A caller passing an already-parsed case has no file to hash."""
        self.assertEqual("", self._analyze().case_analyzer_run.input_file_sha256)

    def test_a_supplied_input_file_hash_is_recorded_separately(self):
        report = self._analyze(input_file_sha256="a" * 64)

        self.assertEqual("a" * 64, report.case_analyzer_run.input_file_sha256)
        self.assertNotEqual("a" * 64, report.case_analyzer_run.payload_sha256)


class EndpointHostTests(unittest.TestCase):
    """Provenance records where a request went, never what authorized it."""

    def test_credentials_in_the_url_are_dropped(self):
        self.assertEqual("gateway.example", endpoint_host("https://user:sk-secret@gateway.example/v1"))

    def test_a_path_or_query_is_dropped(self):
        self.assertEqual("gateway.example", endpoint_host("https://gateway.example/v1?token=sk-secret"))

    def test_a_non_default_port_is_kept(self):
        """A local gateway is only identified by its port."""
        self.assertEqual("localhost:4000", endpoint_host("http://localhost:4000"))

    def test_a_bare_host_and_port_without_a_scheme_still_parses(self):
        self.assertEqual("localhost:4000", endpoint_host("localhost:4000"))

    def test_no_endpoint_records_nothing(self):
        self.assertEqual("", endpoint_host(None))
        self.assertEqual("", endpoint_host(""))


class RecordedApiKeyTests(_CallsProvider):
    def test_no_part_of_the_run_block_echoes_the_api_key(self):
        environment = {
            **_ENVIRONMENT,
            "CASE_ANALYZER_API_KEY": "sk-do-not-record",
            "CASE_ANALYZER_BASE_URL": "https://user:sk-do-not-record@gateway.example/v1",
        }

        report = self._analyze(environment=environment)

        rendered = json.dumps(report.case_analyzer_run.model_dump(mode="json"))
        self.assertNotIn("sk-do-not-record", rendered)
        self.assertEqual("gateway.example", report.case_analyzer_run.endpoint_host)


class RecordedChecksTests(_CallsProvider):
    """The post-check result now travels with the report instead of only on stderr."""

    def test_a_clean_report_records_that_the_check_ran(self):
        checks = self._analyze().case_analyzer_run.checks

        self.assertTrue(checks.ran)
        self.assertEqual([], checks.problems)

    def test_an_unresolvable_citation_is_recorded_in_the_result(self):
        content = json.dumps(
            {
                **json.loads(_REPORT_JSON),
                "evidence_findings": [
                    {
                        "title": "Beaconing",
                        "finding_type": "network",
                        "subject": "host",
                        "evidence": "e",
                        "conclusion": "c",
                        "source_paths": ["artifacts[0].cef.invented"],
                    }
                ],
            }
        )

        checks = self._analyze(content=content).case_analyzer_run.checks

        self.assertTrue(checks.ran)
        self.assertEqual(1, len(checks.problems))
        self.assertIn("artifacts[0].cef.invented", checks.problems[0])

    def test_a_summary_reports_that_no_check_ran(self):
        """Distinguished from a clean result: a summary has nothing to check."""
        with patch.dict(os.environ, _ENVIRONMENT, clear=True):
            with patch("case_analyzer.analyzer.litellm.completion") as completion:
                completion.return_value = _completion_response('{"summary": "s"}')
                summary = summarize_case(_case())

        self.assertFalse(summary.case_analyzer_run.checks.ran)


if __name__ == "__main__":
    unittest.main()
