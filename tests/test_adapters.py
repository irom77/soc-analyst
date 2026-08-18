import unittest

from case_analyzer.adapters import detect_format, normalize_case


class DetectFormatTests(unittest.TestCase):
    def test_source_field_selects_soar(self):
        self.assertEqual("soar", detect_format({"source": "Example SOAR"}))
        self.assertEqual("soar", detect_format({"platform": "acme-soar"}))

    def test_container_keys_select_soar(self):
        self.assertEqual("soar", detect_format({"container_type": "case"}))
        self.assertEqual("soar", detect_format({"observables": []}))

    def test_unrecognized_export_falls_back_to_generic(self):
        self.assertEqual("generic", detect_format({"id": 1, "title": "t"}))


class NormalizeCaseTests(unittest.TestCase):
    def test_non_object_input_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_case([{"id": "1", "title": "t"}])

    def test_unsupported_format_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_case({"id": "1", "title": "t"}, "splunk")

    def test_generic_requires_an_identifier_and_a_title(self):
        with self.assertRaises(ValueError):
            normalize_case({"title": "No identifier"}, "generic")
        with self.assertRaises(ValueError):
            normalize_case({"id": "1"}, "generic")

    def test_generic_maps_alternate_field_names_and_keeps_the_export(self):
        exported = {
            "caseId": "C-1",
            "name": "Phishing",
            "summary": "Something happened",
            "priority": "high",
            "state": "open",
            "createdAt": "2026-08-14T18:22:10Z",
            "updatedAt": "2026-08-14T19:00:00Z",
            "tags": ["phish"],
            "events": [{"title": "alert"}],
            "observables": [{"destinationAddress": "8.8.8.8"}],
            "notes": [{"comment": "triaged"}],
            "timeline": [{"ts": "now"}],
        }

        case = normalize_case(exported, "generic")

        self.assertEqual("C-1", case.case_id)
        self.assertEqual("Phishing", case.title)
        self.assertEqual("Something happened", case.description)
        self.assertEqual("high", case.severity)
        self.assertEqual("open", case.status)
        self.assertEqual("2026-08-14T18:22:10Z", case.created_at)
        self.assertEqual([{"title": "alert"}], case.alerts)
        self.assertEqual([{"destinationAddress": "8.8.8.8"}], case.artifacts)
        self.assertEqual([{"comment": "triaged"}], case.comments)
        self.assertEqual("generic", case.source)
        self.assertEqual(exported, case.source_data)

    def test_soar_synthesizes_an_alert_from_artifacts(self):
        case = normalize_case(
            {"container_id": 1042, "container_status": "open", "artifacts": [{"cef": {}}]},
            "soar",
        )

        self.assertEqual("1042", case.case_id)
        self.assertEqual("Untitled SOAR case", case.title)
        self.assertEqual("open", case.status)
        self.assertEqual([{"title": "SOAR case artifacts", "artifacts": [{"cef": {}}]}], case.alerts)

    def test_soar_falls_back_to_platform_specific_collections(self):
        case = normalize_case(
            {
                "id": 7,
                "name": "Beaconing",
                "detections": [{"rule": "c2"}],
                "observables": [{"ip": "8.8.8.8"}],
                "activities": [{"action": "isolate"}],
                "product": "Acme SOAR",
            },
            "soar",
        )

        self.assertEqual([{"rule": "c2"}], case.alerts)
        self.assertEqual([{"ip": "8.8.8.8"}], case.artifacts)
        self.assertEqual([{"action": "isolate"}], case.timeline)
        self.assertEqual("Acme SOAR", case.source)

    def test_scalar_collections_are_wrapped_in_lists(self):
        case = normalize_case({"id": "1", "title": "t", "tags": "single"}, "generic")

        self.assertEqual(["single"], case.tags)


if __name__ == "__main__":
    unittest.main()
