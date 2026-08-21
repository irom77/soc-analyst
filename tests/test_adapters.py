import json
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
        for adapter_name, marker in (("generic", "def _generic_record"), ("soar", "def _soar")):
            body = source[source.index(marker) :]
            body = body[: body.index("source_data=dict(data)")]
            quoted = set(
                re.findall(r'_first\(\s*(?:data|record),\s*([^)]*?)(?:,\s*default=[^)]*)?\)', body)
            )
            names = {name.strip().strip('"\'') for group in quoted for name in group.split(",")}
            names |= {match for match in re.findall(r'(?:data|record)\.get\("([a-z_]+)"\)', body)}
            names.discard("")
            missing = names - CONSUMED_SOURCE_KEYS[adapter_name]
            self.assertEqual(set(), missing, f"{adapter_name} alias keys missing from CONSUMED_SOURCE_KEYS")


class EnvelopeUnwrapTests(unittest.TestCase):
    """A case wrapped in an envelope is normalized from the record inside it.

    `examples/unknown.json` is `{id, name, type, parsed, raw}`: the platform's normalized
    view and the original record, with only identity at the top level. Before this, the
    generic adapter filled two of thirteen fields and everything the case said stayed
    buried in `source_data` -- the largest example here, and the only one that normalized
    to nothing.
    """

    WRAPPED = {
        "id": "4d03",
        "name": "Suspicious OAuth token activity",
        "parsed": {
            "title": "Suspicious OAuth token activity",
            "description": "A token was minted for the CFO account.",
            "severity": "HIGH",
            "status": "NEW",
            "createdAt": "2026-08-05T18:19:55Z",
            "entities": [{"entityType": "USER", "identifier": "jwhitfield"}],
        },
    }

    def test_a_wrapped_case_is_normalized_from_the_inner_record(self):
        case = normalize_case(self.WRAPPED)

        self.assertEqual(("parsed",), case._unwrapped_path)
        self.assertEqual("A token was minted for the CFO account.", case.description)
        self.assertEqual("HIGH", case.severity)
        self.assertEqual("NEW", case.status)
        self.assertEqual("2026-08-05T18:19:55Z", case.created_at)
        self.assertEqual([{"entityType": "USER", "identifier": "jwhitfield"}], case.artifacts)

    def test_identity_falls_back_to_the_outer_record(self):
        """The wrapper keeps the id; the inner view usually has only a title."""
        case = normalize_case(self.WRAPPED)

        self.assertEqual("4d03", case.case_id)
        self.assertEqual("Suspicious OAuth token activity", case.title)

    def test_source_data_still_holds_the_whole_export(self):
        """Enrichment walks `source_data` and roots every `source_paths` value there."""
        case = normalize_case(self.WRAPPED)

        self.assertEqual(self.WRAPPED, case.source_data)

    def test_a_case_with_content_at_the_top_level_is_never_unwrapped(self):
        """The trigger is a top level with no content at all.

        This is what makes the change safe for every export that normalizes today: a case
        that fills even one content field takes the same path it always did, whatever it
        happens to carry underneath.
        """
        case = normalize_case(
            {
                "id": "1",
                "name": "Case",
                "description": "the real one",
                "attachment": {
                    "description": "a richer nested record",
                    "severity": "high",
                    "status": "open",
                    "tags": ["a"],
                    "comments": [{"c": 1}],
                },
            }
        )

        self.assertEqual((), case._unwrapped_path)
        self.assertEqual("the real one", case.description)

    def test_the_record_is_found_two_levels_down(self):
        case = normalize_case(
            {
                "id": "1",
                "name": "Case",
                "raw": {
                    "uid": "1",
                    "content": {
                        "description": "d",
                        "severity": "high",
                        "status": "new",
                        "comments": [{"c": 1}],
                    },
                },
            }
        )

        self.assertEqual(("raw", "content"), case._unwrapped_path)
        self.assertEqual("d", case.description)

    def test_a_nested_body_carrying_a_field_or_two_is_not_mistaken_for_the_case(self):
        """An artifact body can hold a `description` and a `status` without being the case.

        The floor is what separates the two, so a hollow case stays hollow rather than
        being normalized from the wrong record -- which would be worse than not
        normalizing it, because the result would look complete.
        """
        case = normalize_case(
            {"id": "1", "name": "Case", "detail": {"description": "a file", "status": "seen"}}
        )

        self.assertEqual((), case._unwrapped_path)
        self.assertEqual("", case.description)

    def test_the_shallowest_of_equally_good_records_wins(self):
        inner = {"description": "d", "severity": "high", "status": "new"}
        case = normalize_case({"id": "1", "name": "C", "parsed": inner, "raw": {"content": inner}})

        self.assertEqual(("parsed",), case._unwrapped_path)

    def test_mapping_tags_do_not_reach_the_payload_as_python_reprs(self):
        case = normalize_case(
            {
                "id": "1",
                "name": "C",
                "parsed": {
                    "description": "d",
                    "severity": "high",
                    "status": "new",
                    "tags": [{"key": "SOURCE", "value": "manual"}, {"name": "bare"}, "plain"],
                },
            }
        )

        self.assertEqual(["SOURCE: manual", "bare", "plain"], case.tags)

    def test_the_recorded_examples_keep_their_shape(self):
        """Only the envelope example changes; the other three must take the old path."""
        root = pathlib.Path(adapters.__file__).parents[2] / "examples"
        expected = {
            "generic-case.json": (),
            "other-soar-case.json": (),
            "splunk-soar.json": (),
            "unknown.json": ("parsed",),
        }
        for name, path in expected.items():
            with self.subTest(name):
                data = json.loads((root / name).read_text(encoding="utf-8"))
                self.assertEqual(path, normalize_case(data)._unwrapped_path)

    def test_every_content_alias_is_listed_as_consumed(self):
        """The scoring table and the residue key set must name the same fields.

        An alias scored here but not consumed would be lifted out of the envelope and then
        resent inside it, which is the duplication this whole path exists to remove.
        """
        names = {name for group in adapters._GENERIC_CONTENT_ALIASES for name in group}

        self.assertEqual(set(), names - CONSUMED_SOURCE_KEYS["generic"])


class UnwrappedResidueTests(unittest.TestCase):
    """`--reduce-source-data` applies its rule at the depth the adapter actually read."""

    WRAPPED = {
        "id": "1",
        "name": "Case",
        "type": "incident",
        "parsed": {
            "description": "d",
            "severity": "high",
            "status": "new",
            "entities": [{"identifier": "8.8.8.8"}],
            "verdict": "UNKNOWN",
        },
        "raw": {"content": {"uid": "1", "techniques": ["T1078"]}},
    }

    def test_the_lifted_keys_are_dropped_from_the_record_they_came_from(self):
        residue = source_data_residue(normalize_case(self.WRAPPED))

        self.assertNotIn("description", residue["parsed"])
        self.assertNotIn("entities", residue["parsed"])

    def test_what_the_envelope_carries_but_no_adapter_lifts_survives(self):
        """Trimming key by key rather than dropping the subtree is the point.

        `verdict` is inside the record the adapter read from but is not a field any adapter
        lifts, so dropping `parsed` wholesale would delete it from the payload.
        """
        residue = source_data_residue(normalize_case(self.WRAPPED))

        self.assertEqual("UNKNOWN", residue["parsed"]["verdict"])

    def test_the_second_view_of_the_record_is_kept(self):
        """`raw` is a different view, not a copy of what was sent.

        It carries fields the normalized view omits, and the adapter never read from it, so
        the consumed-key rule has nothing to say about it.
        """
        residue = source_data_residue(normalize_case(self.WRAPPED))

        self.assertEqual({"uid": "1", "techniques": ["T1078"]}, residue["raw"]["content"])

    def test_trimming_does_not_touch_the_stored_case(self):
        """The residue shares the caller's nested objects until it copies them."""
        case = normalize_case(self.WRAPPED)

        source_data_residue(case)

        self.assertEqual("d", case.source_data["parsed"]["description"])
        self.assertEqual(self.WRAPPED, case.source_data)

    def test_an_unwrapped_case_reduces_like_any_other(self):
        """The measured symptom: this shape recovered 1.1% where every other case recovers
        a quarter to two fifths of the payload."""
        case = normalize_case(self.WRAPPED)

        whole = len(json.dumps(case.source_data))
        residue = len(json.dumps(source_data_residue(case)))

        self.assertLess(residue, whole * 0.75)
