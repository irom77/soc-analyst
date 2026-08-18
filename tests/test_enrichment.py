import io
import json
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from case_analyzer import enrichment as enrichment_module
from case_analyzer.adapters import normalize_case
from case_analyzer.enrichment import (
    _as_mapping,
    _http_json,
    _kind_from_hint,
    _validate,
    _walk_observables,
    enrich_case,
)


def _found_domain(value, timeout):
    return "found", "test-dns", {"answers": [value]}


def _found_ip(value, timeout):
    return "found", "test-rdap", {"handle": value}


class _FakeResponse:
    def __init__(self, payload, status=200, url="https://provider.test/x"):
        self._body = io.BytesIO(json.dumps(payload).encode("utf-8"))
        self.status = status
        self.url = url

    def read(self, *args):
        return self._body.read(*args)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class EnrichmentTests(unittest.TestCase):
    def test_enrichment_is_separate_deduplicated_and_preserves_source(self):
        exported = {
            "id": "case-1",
            "title": "Example",
            "artifacts": [
                {
                    "cef": {"destinationAddress": "8.8.8.8", "destinationDnsDomain": "Example.COM"},
                    "cef_types": {"destinationAddress": ["ip"], "destinationDnsDomain": ["domain"]},
                    "notes": [
                        {
                            "title": "Threat Intelligence Enrichment",
                            "content": "Existing reputation is malicious.",
                        }
                    ],
                },
                {"destinationAddress": "8.8.8.8"},
            ],
        }
        case = normalize_case(exported)

        enrich_case(case, domain_lookup=_found_domain, ip_lookup=_found_ip)

        self.assertEqual(exported, case.source_data)
        self.assertEqual(2, len(case.case_analyzer_enrichment.observations))
        ip = next(item for item in case.case_analyzer_enrichment.observations if item.observable_type == "ip")
        self.assertEqual(2, len(ip.source_paths))
        self.assertEqual("not_comparable", ip.comparison_with_case.status)
        self.assertIn("Existing reputation", ip.artifact_context[0])

    def test_invalid_inferred_value_is_not_reported_as_a_case_contradiction(self):
        case = normalize_case({"id": "case-2", "title": "Invalid", "destinationAddress": "999.1.1.1"})

        result = enrich_case(
            case,
            ip_lookup=lambda value, timeout: self.fail("provider must not be called"),
        )

        self.assertFalse(result.observations[0].valid)
        self.assertEqual("local-validation", result.observations[0].provider)
        self.assertEqual("skipped", result.observations[0].lookup_status)
        # The type was inferred from the field name, so the syntax failure is an
        # extractor limit rather than a contradiction inside the case.
        self.assertEqual("not_comparable", result.observations[0].comparison_with_case.status)

    def test_invalid_declared_value_conflicts_with_the_case(self):
        case = normalize_case(
            {
                "id": "case-2b",
                "title": "Declared",
                "artifacts": [
                    {"cef": {"deviceCustom1": "999.1.1.1"}, "cef_types": {"deviceCustom1": ["ip"]}}
                ],
            }
        )

        result = enrich_case(
            case,
            ip_lookup=lambda value, timeout: self.fail("provider must not be called"),
        )

        self.assertEqual("conflicting", result.observations[0].comparison_with_case.status)

    def test_netbios_host_name_is_not_reported_as_a_case_contradiction(self):
        case = normalize_case(
            {
                "id": "case-2c",
                "title": "Host name",
                "artifacts": [
                    {
                        "cef": {"sourceHostName": "WS-FIN-09"},
                        "cef_types": {"sourceHostName": ["host_name"]},
                    }
                ],
            }
        )

        result = enrich_case(case, domain_lookup=_found_domain)

        self.assertEqual(1, len(result.observations))
        self.assertEqual("domain", result.observations[0].observable_type)
        self.assertFalse(result.observations[0].valid)
        self.assertEqual("not_comparable", result.observations[0].comparison_with_case.status)

    def test_cef_is_walked_when_cef_types_is_missing(self):
        case = normalize_case(
            {
                "id": "case-6",
                "title": "No cef_types",
                "artifacts": [
                    {"cef": {"destinationAddress": "9.9.9.9", "destinationDnsDomain": "evil.test"}}
                ],
            }
        )

        result = enrich_case(case, domain_lookup=_found_domain, ip_lookup=_found_ip)

        self.assertEqual(
            {("ip", "9.9.9.9"), ("domain", "evil.test")},
            {(item.observable_type, item.value) for item in result.observations},
        )
        self.assertTrue(
            all(path.endswith((".cef.destinationAddress", ".cef.destinationDnsDomain"))
                for item in result.observations for path in item.source_paths)
        )

    def test_declared_fields_are_not_emitted_twice(self):
        case = normalize_case(
            {
                "id": "case-7",
                "title": "Declared once",
                "artifacts": [
                    {
                        "cef": {"destinationAddress": "9.9.9.9"},
                        "cef_types": {"destinationAddress": ["ip"]},
                    }
                ],
            }
        )

        result = enrich_case(case, ip_lookup=_found_ip)

        self.assertEqual(1, len(result.observations))
        self.assertEqual(1, len(result.observations[0].source_paths))

    def test_hint_matching_covers_spellings_and_rejects_lookalike_fields(self):
        self.assertEqual(("ip", True), _kind_from_hint("ip address"))
        self.assertEqual(("ip", True), _kind_from_hint("sourceAddress"))
        self.assertEqual(("ip", True), _kind_from_hint("src_ip"))
        self.assertEqual(("domain", True), _kind_from_hint("destinationDnsDomain"))
        self.assertEqual(("domain", True), _kind_from_hint("fqdn"))
        self.assertEqual(("domain", False), _kind_from_hint("host_name"))
        self.assertEqual(("domain", False), _kind_from_hint("sourceHostName"))
        self.assertEqual(("file_hash", True), _kind_from_hint("sha256"))
        self.assertEqual(("file_hash", True), _kind_from_hint("fileHash"))
        self.assertEqual(("url", True), _kind_from_hint("requestURL"))
        self.assertEqual(("email", True), _kind_from_hint("sourceUserEmail"))
        for hint in ("domainCreationDate", "registeredDomainAge", "port", "process_name",
                     "mac address", "fileName"):
            self.assertIsNone(_kind_from_hint(hint), hint)

    def test_artifact_context_is_collected_without_a_cef_block(self):
        case = normalize_case(
            {
                "id": "case-8",
                "title": "Generic artifact",
                "artifacts": [
                    {
                        "destinationAddress": "8.8.8.8",
                        "notes": [{"title": "Threat Intelligence Enrichment", "content": "malicious"}],
                    }
                ],
            }
        )

        result = enrich_case(case, ip_lookup=_found_ip)

        # No doubled separator between the joined note fields.
        self.assertEqual(["Threat Intelligence Enrichment malicious"], result.observations[0].artifact_context)

    def test_skipped_lookup_gets_its_own_comparison(self):
        case = normalize_case({"id": "case-9", "title": "Private", "sourceAddress": "10.20.4.115"})

        result = enrich_case(case)

        self.assertEqual("skipped", result.observations[0].lookup_status)
        self.assertEqual("inconclusive", result.observations[0].comparison_with_case.status)
        self.assertIn("No provider lookup", result.observations[0].comparison_with_case.explanation)

    def test_limit_keeps_the_most_informative_observables(self):
        case = normalize_case(
            {
                "id": "case-3",
                "title": "Limit",
                "artifacts": [
                    {"sourceAddress": "10.20.4.115"},
                    {"destinationAddress": "1.1.1.1"},
                    {"deviceAddress": "999.1.1.1"},
                ],
            }
        )

        result = enrich_case(case, limit=1, ip_lookup=_found_ip)

        self.assertEqual(1, len(result.observations))
        self.assertEqual("1.1.1.1", result.observations[0].value)
        self.assertTrue(result.truncated)

    def test_provider_failure_is_recorded_instead_of_raised(self):
        case = normalize_case({"id": "case-10", "title": "Broken", "destinationAddress": "8.8.8.8"})

        def broken(value, timeout):
            raise AttributeError("'list' object has no attribute 'get'")

        result = enrich_case(case, ip_lookup=broken)

        self.assertEqual("error", result.observations[0].lookup_status)
        self.assertIn("AttributeError", result.observations[0].details["error"])

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

    def test_virustotal_skips_private_addresses_and_can_double_the_observation_count(self):
        case = normalize_case(
            {
                "id": "case-11",
                "title": "VT eligibility",
                "artifacts": [{"sourceAddress": "10.20.4.115"}, {"destinationAddress": "8.8.8.8"}],
            }
        )
        calls = []

        result = enrich_case(
            case,
            limit=2,
            ip_lookup=_found_ip,
            virustotal_lookup=lambda kind, value, timeout, key: (
                calls.append(value) or ("found", "virustotal", {})
            ),
            virustotal_api_key="test-key",
        )

        self.assertEqual(["8.8.8.8"], calls)
        self.assertEqual(3, len(result.observations))
        self.assertFalse(result.truncated)

    def test_invalid_limit_and_timeout_are_rejected(self):
        case = normalize_case({"id": "case-12", "title": "Bounds"})
        with self.assertRaises(ValueError):
            enrich_case(case, limit=0)
        with self.assertRaises(ValueError):
            enrich_case(case, timeout=0)


class ValidationTests(unittest.TestCase):
    def test_domain_and_ip_validation(self):
        self.assertEqual((True, "example.com"), _validate("domain", "example.com."))
        self.assertEqual((True, "xn--bcher-kva.example"), _validate("domain", "Bücher.example"))
        self.assertEqual((False, "not a domain"), _validate("domain", "not a domain"))
        self.assertEqual((True, "8.8.8.8"), _validate("ip", " 8.8.8.8 "))
        self.assertEqual((True, "2001:db8::1"), _validate("ip", "2001:0db8:0000::1"))
        self.assertEqual((False, "999.1.1.1"), _validate("ip", "999.1.1.1"))


class HttpJsonTests(unittest.TestCase):
    def test_non_object_body_is_reported_as_absent(self):
        self.assertEqual({"a": 1}, _as_mapping({"a": 1}))
        self.assertIsNone(_as_mapping(["boom"]))

    def test_non_object_success_body_is_an_error_for_every_provider(self):
        with patch("case_analyzer.enrichment.urlopen", side_effect=lambda *a, **kw: _FakeResponse(["boom"])):
            dns = enrichment_module._domain_lookup("host.example.com", 1.0)
            virustotal = enrichment_module._virustotal_lookup("domain", "host.example.com", 1.0, "key")
        with patch("case_analyzer.enrichment._http_json", return_value=(200, None, "https://rdap.test/ip/8.8.8.8")):
            rdap = enrichment_module._ip_lookup("8.8.8.8", 1.0)

        for status, _, details in (dns, virustotal, rdap):
            self.assertEqual("error", status)
            self.assertIn("not an object", details["error"])

    def test_success_returns_status_body_and_answering_url(self):
        with patch(
            "case_analyzer.enrichment.urlopen",
            return_value=_FakeResponse({"handle": "NET-1"}, url="https://rdap.example.test/ip/1"),
        ):
            status, body, url = _http_json("https://provider.test", {}, 1.0)

        self.assertEqual((200, {"handle": "NET-1"}, "https://rdap.example.test/ip/1"), (status, body, url))

    def test_http_error_body_is_returned_with_its_status(self):
        error = HTTPError(
            "https://provider.test",
            429,
            "Too Many Requests",
            {},
            io.BytesIO(json.dumps({"error": {"message": "quota exceeded"}}).encode("utf-8")),
        )
        self.addCleanup(error.close)
        with patch("case_analyzer.enrichment.urlopen", side_effect=error):
            status, body, _ = _http_json("https://provider.test", {}, 1.0)

        self.assertEqual(429, status)
        self.assertEqual({"message": "quota exceeded"}, body["error"])

    def test_non_json_error_body_is_reported_as_an_error_string(self):
        error = HTTPError("https://provider.test", 502, "Bad Gateway", {}, io.BytesIO(b"<html>nope</html>"))
        self.addCleanup(error.close)
        with patch("case_analyzer.enrichment.urlopen", side_effect=error):
            status, body, _ = _http_json("https://provider.test", {}, 1.0)

        self.assertEqual(502, status)
        self.assertIn("502", body["error"])


class ExtractionCoverageTests(unittest.TestCase):
    def test_url_contributes_its_host(self):
        case = normalize_case(
            {
                "id": "case-20",
                "title": "URL",
                "artifacts": [
                    {
                        "cef": {"requestURL": "https://stage2.evil.test:8443/beacon?id=1"},
                        "cef_types": {"requestURL": ["url"]},
                    }
                ],
            }
        )

        result = enrich_case(case, domain_lookup=_found_domain)

        self.assertEqual(1, len(result.observations))
        observation = result.observations[0]
        self.assertEqual(("domain", "stage2.evil.test"), (observation.observable_type, observation.value))
        self.assertEqual(
            ["source_data.artifacts[0].cef.requestURL#host"], observation.source_paths
        )

    def test_url_with_a_literal_address_contributes_an_ip(self):
        case = normalize_case({"id": "case-21", "title": "URL", "requestUrl": "http://8.8.8.8/x"})

        result = enrich_case(case, ip_lookup=_found_ip)

        self.assertEqual(("ip", "8.8.8.8"), (result.observations[0].observable_type, result.observations[0].value))

    def test_email_contributes_its_domain(self):
        case = normalize_case(
            {"id": "case-22", "title": "Email", "sourceUserEmail": "Attacker@Evil.Test"}
        )

        result = enrich_case(case, domain_lookup=_found_domain)

        observation = result.observations[0]
        self.assertEqual(("domain", "evil.test"), (observation.observable_type, observation.value))
        self.assertTrue(observation.source_paths[0].endswith("#domain"))

    def test_file_hash_is_validated_and_enriched_only_through_virustotal(self):
        digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        case = normalize_case(
            {
                "id": "case-23",
                "title": "Hash",
                "artifacts": [
                    {"cef": {"fileHash": digest.upper()}, "cef_types": {"fileHash": ["sha256"]}}
                ],
            }
        )
        calls = []

        result = enrich_case(
            case,
            virustotal_lookup=lambda kind, value, timeout, key: (
                calls.append((kind, value)) or ("found", "virustotal", {"reputation": -5})
            ),
            virustotal_api_key="test-key",
        )

        self.assertEqual([("file_hash", digest)], calls)
        primary, vt = result.observations
        self.assertEqual("skipped", primary.lookup_status)
        self.assertEqual("sha256", primary.details["algorithm"])
        self.assertEqual("inconclusive", primary.comparison_with_case.status)
        self.assertEqual(("virustotal", "found"), (vt.provider, vt.lookup_status))

    def test_invalid_declared_hash_conflicts_with_the_case(self):
        case = normalize_case(
            {
                "id": "case-24",
                "title": "Hash",
                "artifacts": [
                    {"cef": {"fileHash": "not-a-hash"}, "cef_types": {"fileHash": ["sha256"]}}
                ],
            }
        )

        result = enrich_case(case)

        self.assertFalse(result.observations[0].valid)
        self.assertEqual("conflicting", result.observations[0].comparison_with_case.status)
        self.assertIn("file hash", result.observations[0].comparison_with_case.explanation)


class BudgetAndBreakerTests(unittest.TestCase):
    def test_exhausted_budget_skips_the_remaining_lookups(self):
        case = normalize_case(
            {
                "id": "case-30",
                "title": "Budget",
                "artifacts": [{"destinationDnsDomain": f"host{index}.example.com"} for index in range(3)],
            }
        )
        clock = iter([0.0] + [10.0] * 20)

        with patch("case_analyzer.enrichment.time.monotonic", lambda: next(clock)):
            result = enrich_case(
                case,
                budget=5.0,
                concurrency=1,
                domain_lookup=lambda value, timeout: self.fail("the budget was already exhausted"),
            )

        self.assertTrue(result.stopped_early)
        self.assertEqual(["skipped"] * 3, [item.lookup_status for item in result.observations])
        self.assertIn("time budget", result.observations[0].details["reason"])
        self.assertEqual("inconclusive", result.observations[0].comparison_with_case.status)

    def test_repeated_provider_failures_open_the_circuit(self):
        case = normalize_case(
            {
                "id": "case-31",
                "title": "Breaker",
                "artifacts": [{"destinationDnsDomain": f"host{index}.example.com"} for index in range(4)],
            }
        )
        calls = []

        def failing(value, timeout):
            calls.append(value)
            raise TimeoutError("provider is down")

        result = enrich_case(case, concurrency=1, failure_threshold=2, domain_lookup=failing)

        self.assertEqual(2, len(calls))
        self.assertTrue(result.stopped_early)
        self.assertEqual(
            ["error", "error", "skipped", "skipped"],
            [item.lookup_status for item in result.observations],
        )
        self.assertIn("consecutive failures", result.observations[-1].details["reason"])

    def test_budget_caps_the_request_timeout_and_bounds_the_wall_time(self):
        case = normalize_case(
            {"id": "case-34", "title": "Budget", "artifacts": [{"destinationDnsDomain": "host.example.com"}]}
        )
        offered = []

        def slow(value, timeout):
            offered.append(timeout)
            time.sleep(timeout)  # a real provider gives up when its timeout expires
            raise TimeoutError("timed out")

        started = time.monotonic()
        result = enrich_case(case, budget=0.05, timeout=30.0, concurrency=1, domain_lookup=slow)
        elapsed = time.monotonic() - started

        # Without the cap the single lookup would run for the full 30-second timeout.
        self.assertLessEqual(offered[0], 0.05)
        self.assertLess(elapsed, 1.0)
        # A request the budget cut short is not evidence against the provider, so it is skipped.
        self.assertTrue(result.stopped_early)
        self.assertEqual("skipped", result.observations[0].lookup_status)
        self.assertIn("time budget", result.observations[0].details["reason"])

    def test_concurrent_failures_bound_the_calls_made_to_a_dead_provider(self):
        case = normalize_case(
            {
                "id": "case-35",
                "title": "Breaker",
                "artifacts": [{"destinationDnsDomain": f"host{index}.example.com"} for index in range(12)],
            }
        )
        concurrency, threshold = 3, 1
        started = threading.Barrier(concurrency, timeout=5)
        calls = []
        lock = threading.Lock()

        def failing(value, timeout):
            with lock:
                calls.append(value)
                first_wave = len(calls) <= concurrency
            if first_wave:
                # Hold the first wave open, so every worker decides before any failure is recorded.
                started.wait()
            raise TimeoutError("provider is down")

        result = enrich_case(
            case, concurrency=concurrency, failure_threshold=threshold, domain_lookup=failing
        )

        # In-flight lookups cannot be recalled, so the worst case is one wave past the threshold.
        self.assertLessEqual(len(calls), threshold + concurrency - 1)
        self.assertTrue(result.stopped_early)
        self.assertEqual(len(calls), sum(1 for item in result.observations if item.lookup_status == "error"))
        self.assertIn("consecutive failures", result.observations[-1].details["reason"])

    def test_concurrent_lookups_keep_the_priority_order(self):
        case = normalize_case(
            {
                "id": "case-32",
                "title": "Concurrency",
                "artifacts": [{"destinationDnsDomain": f"host{index}.example.com"} for index in range(6)],
            }
        )

        result = enrich_case(case, concurrency=4, domain_lookup=_found_domain)

        values = [item.value for item in result.observations]
        self.assertEqual(sorted(values), values)
        self.assertFalse(result.stopped_early)

    def test_invalid_budget_concurrency_and_threshold_are_rejected(self):
        case = normalize_case({"id": "case-33", "title": "Bounds"})
        for kwargs in ({"budget": 0.0}, {"concurrency": 0}, {"failure_threshold": 0}):
            with self.assertRaises(ValueError):
                enrich_case(case, **kwargs)


class RdapBootstrapTests(unittest.TestCase):
    def setUp(self):
        enrichment_module._bootstrap_cache.clear()
        self.addCleanup(enrichment_module._bootstrap_cache.clear)

    def _responses(self, bootstrap_status=200):
        requested = []

        def fake_http_json(url, headers, timeout):
            requested.append(url)
            if "data.iana.org" in url:
                body = {
                    "services": [
                        [["8.0.0.0/8"], ["https://rdap.example-rir.test/rdap/"]],
                        [["0.0.0.0/0"], ["https://rdap.wrong.test/"]],
                    ]
                }
                return bootstrap_status, body if bootstrap_status == 200 else {"error": "down"}, url
            return 200, {"handle": "NET-8-0-0-0-1", "name": "EXAMPLE-NET"}, url

        return requested, fake_http_json

    def test_bootstrap_selects_the_most_specific_registry(self):
        requested, fake = self._responses()
        with patch("case_analyzer.enrichment._http_json", fake):
            status, provider, details = enrichment_module._ip_lookup("8.8.8.8", 1.0)

        self.assertEqual(("found", "rdap"), (status, provider))
        self.assertEqual("iana-bootstrap", details["rdap_source"])
        self.assertEqual("rdap.example-rir.test", details["rdap_authority"])
        self.assertIn("https://rdap.example-rir.test/rdap/ip/8.8.8.8", requested)

    def test_bootstrap_is_fetched_once_and_falls_back_when_unavailable(self):
        requested, fake = self._responses(bootstrap_status=503)
        with patch("case_analyzer.enrichment._http_json", fake):
            _, _, first = enrichment_module._ip_lookup("8.8.8.8", 1.0)
            _, _, second = enrichment_module._ip_lookup("9.9.9.9", 1.0)

        self.assertEqual(["arin-fallback", "arin-fallback"], [first["rdap_source"], second["rdap_source"]])
        self.assertEqual(1, len([url for url in requested if "data.iana.org" in url]))

    def test_bootstrap_is_refetched_once_the_cache_entry_expires(self):
        requested, fake = self._responses()
        with patch("case_analyzer.enrichment._http_json", fake):
            enrichment_module._ip_lookup("8.8.8.8", 1.0)
            stamp, entries = enrichment_module._bootstrap_cache[4]
            # Age the cached copy past its TTL instead of waiting an hour for it.
            enrichment_module._bootstrap_cache[4] = (stamp - enrichment_module._BOOTSTRAP_TTL_SECONDS, entries)
            enrichment_module._ip_lookup("8.8.4.4", 1.0)

        self.assertEqual(2, len([url for url in requested if "data.iana.org" in url]))

    def test_query_is_not_started_when_the_bootstrap_used_the_whole_timeout(self):
        requested, fake = self._responses()

        def slow_bootstrap(url, headers, timeout):
            if "data.iana.org" in url:
                time.sleep(timeout)
            return fake(url, headers, timeout)

        with patch("case_analyzer.enrichment._http_json", slow_bootstrap):
            with self.assertRaises(TimeoutError):
                enrichment_module._ip_lookup("8.8.8.8", 0.05)

        # Starting the query with a floor timeout would have run past the caller's bound.
        self.assertEqual([], [url for url in requested if "/ip/" in url])

    def test_concurrent_cold_lookups_share_one_bootstrap_fetch(self):
        requested, fake = self._responses()
        ready = threading.Barrier(2, timeout=5)

        def slow_bootstrap(url, headers, timeout):
            if "data.iana.org" in url:
                time.sleep(0.05)  # hold the fetch open long enough for the second thread to arrive
            return fake(url, headers, timeout)

        def run():
            ready.wait()
            enrichment_module._ip_lookup("8.8.8.8", 5.0)

        with patch("case_analyzer.enrichment._http_json", slow_bootstrap):
            threads = [threading.Thread(target=run) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual(1, len([url for url in requested if "data.iana.org" in url]))
        self.assertEqual(2, len([url for url in requested if "/ip/" in url]))

    def test_private_addresses_are_never_looked_up(self):
        with patch("case_analyzer.enrichment._http_json", side_effect=AssertionError("no request expected")):
            status, provider, details = enrichment_module._ip_lookup("10.20.4.115", 1.0)

        self.assertEqual(("skipped", "rdap"), (status, provider))
        self.assertIn("non-global", details["reason"])


class SerializationTests(unittest.TestCase):
    def test_timestamps_serialize_as_utc_with_a_z_suffix(self):
        case = normalize_case({"id": "case-40", "title": "Time", "destinationDnsDomain": "example.com"})
        enrich_case(case, domain_lookup=_found_domain)

        dumped = case.model_dump(mode="json")["case_analyzer_enrichment"]

        self.assertRegex(dumped["generated_at"], r"^\d{4}-\d{2}-\d{2}T[\d:.]+Z$")
        self.assertRegex(dumped["observations"][0]["retrieved_at"], r"Z$")


class WalkTests(unittest.TestCase):
    def test_nested_child_containers_are_walked(self):
        found = _walk_observables(
            {"child_containers": [{"artifacts": [{"cef": {"destinationAddress": "1.1.1.1"}}]}]}
        )

        self.assertEqual(
            [("ip", "1.1.1.1", "source_data.child_containers[0].artifacts[0].cef.destinationAddress")],
            [(item.kind, item.value, item.path) for item in found],
        )


if __name__ == "__main__":
    unittest.main()
