import unittest

from case_analyzer.adapters import normalize_case
from case_analyzer.enrichment import enrich_case


class EnrichmentTests(unittest.TestCase):
    def test_enrichment_is_separate_deduplicated_and_preserves_source(self):
        exported = {
            "id": "case-1",
            "title": "Example",
            "artifacts": [
                {
                    "cef": {"destinationAddress": "8.8.8.8", "destinationDnsDomain": "Example.COM"},
                    "cef_types": {"destinationAddress": ["ip"], "destinationDnsDomain": ["domain"]},
                    "notes": [{"title": "Threat Intelligence Enrichment", "content": "Existing reputation is malicious."}],
                },
                {"destinationAddress": "8.8.8.8"},
            ],
        }
        case = normalize_case(exported)

        enrich_case(
            case,
            domain_lookup=lambda value, timeout: ("found", "test-dns", {"answers": [value]}),
            ip_lookup=lambda value, timeout: ("found", "test-rdap", {"handle": value}),
        )

        self.assertEqual(exported, case.source_data)
        self.assertEqual(2, len(case.case_analyzer_enrichment.observations))
        ip = next(item for item in case.case_analyzer_enrichment.observations if item.observable_type == "ip")
        self.assertEqual(2, len(ip.source_paths))
        self.assertEqual("not_comparable", ip.comparison_with_case.status)
        self.assertIn("Existing reputation", ip.existing_case_context[0])

    def test_invalid_values_are_not_sent_to_providers(self):
        case = normalize_case({"id": "case-2", "title": "Invalid", "destinationAddress": "999.1.1.1"})

        result = enrich_case(
            case,
            ip_lookup=lambda value, timeout: self.fail("provider must not be called"),
        )

        self.assertFalse(result.observations[0].valid)
        self.assertEqual("local-validation", result.observations[0].provider)
        self.assertEqual("skipped", result.observations[0].lookup_status)
        self.assertEqual("conflicting", result.observations[0].comparison_with_case.status)

    def test_limit_marks_output_truncated(self):
        case = normalize_case(
            {"id": "case-3", "title": "Limit", "sourceAddress": "8.8.8.8", "destinationAddress": "1.1.1.1"}
        )

        result = enrich_case(case, limit=1, ip_lookup=lambda value, timeout: ("found", "test", {}))

        self.assertEqual(1, len(result.observations))
        self.assertTrue(result.truncated)

    def test_virustotal_runs_only_when_api_key_is_provided(self):
        case = normalize_case({"id": "case-4", "title": "VT", "destinationDnsDomain": "example.com"})
        calls = []

        result = enrich_case(
            case,
            domain_lookup=lambda value, timeout: ("found", "test-dns", {}),
            virustotal_lookup=lambda kind, value, timeout, key: (
                calls.append((kind, value, key)) or ("found", "virustotal", {"reputation": 1})
            ),
            virustotal_api_key="test-key",
        )

        self.assertEqual([("domain", "example.com", "test-key")], calls)
        self.assertEqual(["test-dns", "virustotal"], [item.provider for item in result.observations])

        no_key_case = normalize_case(
            {"id": "case-5", "title": "No VT", "destinationDnsDomain": "example.com"}
        )
        no_key_result = enrich_case(
            no_key_case,
            domain_lookup=lambda value, timeout: ("found", "test-dns", {}),
            virustotal_lookup=lambda *args: self.fail("VirusTotal must not be called without a key"),
            virustotal_api_key="",
        )
        self.assertEqual(["test-dns"], [item.provider for item in no_key_result.observations])


if __name__ == "__main__":
    unittest.main()
