import pathlib
import re
import unittest

from case_analyzer import adapters
from case_analyzer.adapters import (
    CONSUMED_SOURCE_KEYS,
    detect_format,
    normalize_case,
    source_data_residue,
)


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


class SourceDataResidueTests(unittest.TestCase):
    """Improvement-plan item 10: send only what normalization did not already lift."""

    def test_a_generic_case_naming_its_product_is_not_reduced_as_soar(self):
        """The format came from `case.source`, which holds whatever the export calls itself.

        A generic export with `"source": "splunk"` is normalized by the generic adapter,
        but the residue used to apply the SOAR key set to it and delete `product` and
        `data` -- two fields generic never lifted. That silently removes evidence from the
        payload while the stored case still looks complete.
        """
        case = normalize_case(
            {
                "id": "1",
                "name": "C",
                "source": "splunk",
                "product": "EDR-only evidence",
                "data": "more evidence",
            }
        )
        residue = source_data_residue(case)

        self.assertEqual("splunk", case.source)
        self.assertEqual("EDR-only evidence", residue.get("product"))
        self.assertEqual("more evidence", residue.get("data"))

    def test_an_explicit_format_choice_decides_the_residue(self):
        """`--format soar` must reduce as SOAR even when detection would say otherwise."""
        data = {"id": "1", "name": "C", "data": "lifted into description", "extra": "kept"}
        case = normalize_case(data, source_format="soar")
        residue = source_data_residue(case)

        self.assertNotIn("data", residue)
        self.assertEqual("kept", residue.get("extra"))

    def test_residue_drops_lifted_keys_and_keeps_the_rest(self):
        case = normalize_case(
            {
                "id": "42",
                "name": "Case",
                "description": "d",
                "artifacts": [{"cef": {"sourceAddress": "8.8.8.8"}}],
                "sensitivity": "amber",
                "custom_fields": {"queue": "tier2"},
            },
            "soar",
        )
        residue = source_data_residue(case)

        # Lifted, so resending them is the duplication the item is about.
        self.assertNotIn("id", residue)
        self.assertNotIn("description", residue)
        self.assertNotIn("artifacts", residue)
        # Never lifted by any adapter, so the model would lose them entirely.
        self.assertEqual("amber", residue["sensitivity"])
        self.assertEqual({"queue": "tier2"}, residue["custom_fields"])

    def test_child_containers_survive_because_nothing_else_carries_them(self):
        """The SOAR adapter never descends into `child_containers`.

        For four of the six benchmark cases it is the only carrier of the artifacts, so
        a residue that dropped it would delete the evidence rather than deduplicate it.
        """
        raw = {
            "id": "7",
            "name": "Case",
            "child_containers": [{"artifacts": [{"cef": {"sourceAddress": "8.8.8.8"}}]}],
        }
        case = normalize_case(raw, "soar")

        self.assertEqual([], case.artifacts)
        self.assertEqual(raw["child_containers"], source_data_residue(case)["child_containers"])

    def test_the_stored_case_is_not_reduced(self):
        """Enrichment walks `case.source_data` and roots `source_paths` there."""
        case = normalize_case({"id": "1", "name": "Case", "description": "d"}, "soar")

        source_data_residue(case)

        self.assertEqual("d", case.source_data["description"])

    def test_every_alias_group_is_listed_as_consumed(self):
        """Guards the one way these two can drift apart.

        `CONSUMED_SOURCE_KEYS` is written by hand next to the adapters; a key added to a
        `_first(...)` alias group but not here would be lifted and then resent anyway,
        silently undoing the saving for that field.
        """
        source = pathlib.Path(adapters.__file__).read_text(encoding="utf-8")
        for adapter_name, marker in (("generic", "def _generic"), ("soar", "def _soar")):
            body = source[source.index(marker) :]
            body = body[: body.index("source_data=dict(data)")]
            quoted = set(re.findall(r'_first\(\s*data,\s*([^)]*?)(?:,\s*default=[^)]*)?\)', body))
            names = {name.strip().strip('"\'') for group in quoted for name in group.split(",")}
            names |= {match for match in re.findall(r'data\.get\("([a-z_]+)"\)', body)}
            names.discard("")
            missing = names - CONSUMED_SOURCE_KEYS[adapter_name]
            self.assertEqual(set(), missing, f"{adapter_name} alias keys missing from CONSUMED_SOURCE_KEYS")
