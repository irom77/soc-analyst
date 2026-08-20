import base64
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

    def test_a_unicode_domain_is_looked_up_and_both_spellings_are_recorded(self):
        """The Unicode form is provenance for a punycode name the reader cannot decode.

        Both spellings appear in the same case, and both encode to one observable, so the
        lookup happens once and every distinct spelling is kept.
        """
        looked_up = []

        def domain_lookup(value, timeout):
            looked_up.append(value)
            return "found", "test-dns", {"answers": [value]}

        case = normalize_case(
            {
                "id": "case-idn",
                "title": "Lookalike",
                "artifacts": [
                    {
                        "cef": {"destinationDnsDomain": "\u0430pple.com"},
                        "cef_types": {"destinationDnsDomain": ["domain"]},
                    },
                    {
                        "cef": {"destinationDnsDomain": "\u0430PPLE.com"},
                        "cef_types": {"destinationDnsDomain": ["domain"]},
                    },
                ],
            }
        )

        result = enrich_case(case, domain_lookup=domain_lookup)

        (observation,) = result.observations
        self.assertTrue(observation.valid)
        self.assertEqual("xn--pple-43d.com", observation.value)
        self.assertEqual(["\u0430pple.com", "\u0430PPLE.com"], observation.unicode_values)
        self.assertEqual(["xn--pple-43d.com"], looked_up)

    def test_an_ascii_domain_records_no_unicode_spelling(self):
        case = normalize_case({"id": "case-ascii", "title": "Plain", "destinationDnsDomain": "Example.COM"})

        result = enrich_case(case, domain_lookup=_found_domain)

        self.assertEqual("example.com", result.observations[0].value)
        self.assertEqual([], result.observations[0].unicode_values)

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

    def test_abuseipdb_runs_only_for_global_ips_when_api_key_is_provided(self):
        case = normalize_case(
            {
                "id": "case-11b",
                "title": "AbuseIPDB eligibility",
                "artifacts": [{"sourceAddress": "10.20.4.115"}, {"destinationAddress": "8.8.8.8"}],
            }
        )
        calls = []

        result = enrich_case(
            case,
            limit=2,
            ip_lookup=_found_ip,
            abuseipdb_lookup=lambda value, timeout, key: (
                calls.append((value, key))
                or ("found", "abuseipdb", {"abuse_confidence_score": 12})
            ),
            abuseipdb_api_key="test-key",
        )

        self.assertEqual([("8.8.8.8", "test-key")], calls)
        self.assertEqual(
            ["test-rdap", "abuseipdb", "test-rdap"],
            [item.provider for item in result.observations],
        )
        abuse = next(item for item in result.observations if item.provider == "abuseipdb")
        self.assertEqual("inconclusive", abuse.comparison_with_case.status)

    def test_abuseipdb_is_skipped_without_an_api_key(self):
        case = normalize_case({"id": "case-11c", "title": "No key", "destinationAddress": "8.8.8.8"})

        result = enrich_case(
            case,
            ip_lookup=_found_ip,
            abuseipdb_lookup=lambda *args: self.fail("AbuseIPDB must not be called without a key"),
            abuseipdb_api_key="",
        )

        self.assertEqual(["test-rdap"], [item.provider for item in result.observations])

    def test_invalid_limit_and_timeout_are_rejected(self):
        case = normalize_case({"id": "case-12", "title": "Bounds"})
        with self.assertRaises(ValueError):
            enrich_case(case, limit=0)
        with self.assertRaises(ValueError):
            enrich_case(case, timeout=0)


class ValidationTests(unittest.TestCase):
    def test_domain_and_ip_validation(self):
        self.assertEqual((True, "example.com", ""), _validate("domain", "example.com."))
        self.assertEqual((True, "xn--bcher-kva.example", "Bücher.example"), _validate("domain", "Bücher.example"))
        self.assertEqual((False, "not a domain", ""), _validate("domain", "not a domain"))
        self.assertEqual((True, "8.8.8.8", ""), _validate("ip", " 8.8.8.8 "))
        self.assertEqual((True, "2001:db8::1", ""), _validate("ip", "2001:0db8:0000::1"))
        self.assertEqual((False, "999.1.1.1", ""), _validate("ip", "999.1.1.1"))

    def test_a_unicode_domain_is_validated_rather_than_discarded(self):
        """The homograph shape: a Cyrillic lookalike must be looked up, not dropped."""
        checked = _validate("domain", "\u0430pple.com")
        self.assertTrue(checked.valid)
        self.assertEqual("xn--pple-43d.com", checked.value)
        self.assertEqual("\u0430pple.com", checked.unicode_form)
        self.assertNotEqual(_validate("domain", "apple.com").value, checked.value)

    def test_transitional_mapping_does_not_rewrite_the_domain(self):
        """IDNA 2003 encodes `faß.de` to `fass.de` — a name someone else may own.

        Under UTS #46 nontransitional it stays its own domain, so the lookup is about
        the observable the case actually recorded.
        """
        self.assertEqual("fass.de", "faß.de".encode("idna").decode("ascii"))
        self.assertEqual("xn--fa-hia.de", _validate("domain", "faß.de").value)

    def test_the_unicode_form_is_only_carried_when_the_case_was_not_ascii(self):
        """`unicode_form` records a spelling, not a normalization.

        Case folding and the trailing dot also change the value, but they are not
        something a reader needs the original characters to interpret.
        """
        self.assertEqual("", _validate("domain", "EXAMPLE.COM.").unicode_form)
        self.assertEqual("", _validate("domain", "xn--pple-43d.com").unicode_form)

    def test_an_undecodable_domain_is_invalid_and_keeps_its_original_text(self):
        checked = _validate("domain", "-lead.example")
        self.assertFalse(checked.valid)
        self.assertEqual("-lead.example", checked.value)

    def test_hostnames_that_are_not_domains_stay_invalid(self):
        """Guard against the stricter encoder changing the answer for ordinary values.

        These are the shapes `_HINT_KINDS` calls out as legitimately not domains, so a
        failure here would be a regression rather than a discovery.
        """
        for value in ("WORKSTATION01", "srv-dc01", "localhost", "192.168.1.1", "test_.example.com"):
            with self.subTest(value=value):
                self.assertFalse(_validate("domain", value).valid)

    def test_url_normalization_keeps_the_path_and_folds_only_the_host(self):
        self.assertEqual(
            (True, "https://evil.test/Beacon?Id=1#Frag", ""),
            _validate("url", " HTTPS://Evil.TEST:443/Beacon?Id=1#Frag "),
        )
        # A path that differs by case is a different resource, and the query and fragment
        # can carry the payload, so none of the three may be rewritten.
        self.assertNotEqual(
            _validate("url", "https://evil.test/A").value,
            _validate("url", "https://evil.test/a").value,
        )
        self.assertEqual("http://evil.test/", _validate("url", "http://evil.test").value)
        self.assertEqual("http://evil.test:8080/x", _validate("url", "http://evil.test:8080/x").value)

    def test_url_credentials_are_never_carried_into_a_lookup(self):
        """Userinfo must not reach a third-party API or the on-disk cache."""
        checked = _validate("url", "https://admin:hunter2@evil.test/payload.bin")

        self.assertTrue(checked.valid)
        self.assertEqual("https://evil.test/payload.bin", checked.value)
        self.assertNotIn("hunter2", checked.value)
        self.assertNotIn("hunter2", checked.unicode_form)

    def test_credentials_are_stripped_from_the_unicode_form_too(self):
        """Found by a live run: stripping only the looked-up value is not enough.

        `unicode_form` is populated from the original text so an analyst can read the
        host the case actually wrote, and it is recorded in the report and sent to the
        model. Taking it from the raw candidate put the password back into both, and no
        offline test caught it because the field is empty for an ASCII URL — the leak
        needed a URL that was internationalized *and* credential-bearing.
        """
        checked = _validate("url", "HTTPS://Admin:hunter2@B\u00fccher.DE:443/Katalog/Suche.php?q=1")

        self.assertEqual("https://xn--bcher-kva.de/Katalog/Suche.php?q=1", checked.value)
        # Scheme case and host spelling survive: this is what the case wrote, minus the secret.
        self.assertEqual("HTTPS://B\u00fccher.DE:443/Katalog/Suche.php?q=1", checked.unicode_form)
        self.assertNotIn("hunter2", checked.unicode_form)

    def test_credentials_are_stripped_from_an_invalid_url_as_well(self):
        """An unusable URL is still recorded, so it must not carry the secret either."""
        checked = _validate("url", "sftp://admin:hunter2@\u0431\u0430\u043d\u043a.test/x")

        self.assertFalse(checked.valid)
        self.assertNotIn("hunter2", checked.value)
        self.assertNotIn("hunter2", checked.unicode_form)

    def test_an_at_sign_outside_the_authority_is_not_userinfo(self):
        """`netloc` ends at the first `/`, `?` or `#`, so a query-string `@` is left alone."""
        checked = _validate("url", "https://\u0430pple.com/r?contact=user@example.test")

        self.assertEqual("https://xn--pple-43d.com/r?contact=user@example.test", checked.value)
        self.assertEqual("https://\u0430pple.com/r?contact=user@example.test", checked.unicode_form)

    def test_credentials_are_stripped_when_the_port_cannot_be_parsed(self):
        """`urlsplit` succeeds but `.port` raises, and that branch used to skip redaction.

        Found by review, not by the earlier tests: every credential fixture here happened
        to parse cleanly, so the one return that bypassed `_without_userinfo` was never
        reached. The value still ends up in the report and in the model payload, so an
        unusable port must not turn the redaction off.
        """
        checked = _validate("url", "https://alice:hunter2@example.com:notaport/x")

        self.assertFalse(checked.valid)
        self.assertNotIn("hunter2", checked.value)
        self.assertEqual("https://example.com:notaport/x", checked.value)

    def test_credentials_are_stripped_when_the_url_cannot_be_parsed_at_all(self):
        """A malformed IPv6 authority makes `urlsplit` itself raise, leaving no parse."""
        checked = _validate("url", "https://alice:hunter2@[::1/x")

        self.assertFalse(checked.valid)
        self.assertNotIn("hunter2", checked.value)
        self.assertEqual("https://[::1/x", checked.value)

    def test_a_scheme_relative_url_is_redacted_without_being_mangled(self):
        """The old splice assumed a scheme was present and ate three characters without one.

        `//alice:hunter2@example.com/x` came back as `//aexample.comx`: not a leak, but a
        corrupted value shown to the analyst as what the case contained.
        """
        checked = _validate("url", "//alice:hunter2@example.com/x")

        self.assertNotIn("hunter2", checked.value)
        self.assertEqual("//example.com/x", checked.value)

    def test_a_scheme_and_path_without_an_authority_is_left_alone(self):
        """Userinfo lives in an authority, and an authority only exists after `//`.

        RFC 3986 reads `mailto:user@example.com` as a scheme plus a path, and it reads
        `alice:secret@example.com/x` exactly the same way. Nothing distinguishes the two,
        so neither is rewritten: guessing would corrupt the first to strip the second.
        """
        self.assertEqual(
            "mailto:user@example.com", _validate("url", "mailto:user@example.com").value
        )

    def test_a_unicode_url_is_encoded_to_its_punycode_host(self):
        checked = _validate("url", "http://\u0430pple.com/login")

        self.assertEqual("http://xn--pple-43d.com/login", checked.value)
        self.assertEqual("http://\u0430pple.com/login", checked.unicode_form)

    def test_url_with_a_literal_address_keeps_the_address(self):
        self.assertEqual("http://8.8.8.8/x", _validate("url", "http://8.8.8.8/x").value)
        self.assertEqual("http://[2001:db8::1]/x", _validate("url", "http://[2001:0db8:0000::1]/x").value)

    def test_urls_without_a_usable_scheme_or_host_are_invalid(self):
        for value in ("mailto:a@evil.test", "evil.test/path", "https:///path", "javascript:alert(1)",
                      "https://not a host/x", "C:\\Windows\\notepad.exe"):
            with self.subTest(value=value):
                checked = _validate("url", value)
                self.assertFalse(checked.valid)
                self.assertEqual(value, checked.value)

    def test_email_folds_the_domain_and_leaves_the_local_part_alone(self):
        self.assertEqual((True, "Attacker@evil.test", ""), _validate("email", " Attacker@Evil.TEST "))
        checked = _validate("email", "user@\u043f\u0440\u0438\u043c\u0435\u0440.test")
        self.assertEqual("user@xn--e1afmkfd.test", checked.value)
        self.assertEqual("user@\u043f\u0440\u0438\u043c\u0435\u0440.test", checked.unicode_form)

    def test_addresses_without_a_local_part_or_a_real_domain_are_invalid(self):
        for value in ("@evil.test", "attacker@", "attacker", "attacker@WORKSTATION01", "a b@evil.test"):
            with self.subTest(value=value):
                checked = _validate("email", value)
                self.assertFalse(checked.valid)
                self.assertEqual(value, checked.value)


class HttpJsonTests(unittest.TestCase):
    def test_non_object_body_is_reported_as_absent(self):
        self.assertEqual({"a": 1}, _as_mapping({"a": 1}))
        self.assertIsNone(_as_mapping(["boom"]))

    def test_non_object_success_body_is_an_error_for_every_provider(self):
        with patch("case_analyzer.enrichment.urlopen", side_effect=lambda *a, **kw: _FakeResponse(["boom"])):
            dns = enrichment_module._domain_lookup("host.example.com", 1.0)
            virustotal = enrichment_module._virustotal_lookup("domain", "host.example.com", 1.0, "key")
            abuseipdb = enrichment_module._abuseipdb_lookup("8.8.8.8", 1.0, "key")
        with patch("case_analyzer.enrichment._http_json", return_value=(200, None, "https://rdap.test/ip/8.8.8.8")):
            rdap = enrichment_module._ip_lookup("8.8.8.8", 1.0)

        for status, _, details in (dns, virustotal, abuseipdb, rdap):
            self.assertEqual("error", status)
            self.assertIn("not an object", details["error"])

    def test_abuseipdb_lookup_uses_header_key_and_reduces_the_response(self):
        payload = {
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 4,
                "totalReports": 2,
                "lastReportedAt": "2026-08-01T00:00:00+00:00",
                "isWhitelisted": False,
                "countryCode": "US",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Example ISP",
                "domain": "example.test",
                "reports": [{"comment": "must not be retained"}],
            }
        }
        with patch("case_analyzer.enrichment._http_json", return_value=(200, payload, "unused")) as request:
            status, provider, details = enrichment_module._abuseipdb_lookup("8.8.8.8", 1.5, "secret")

        url, headers, timeout = request.call_args.args
        self.assertIn("ipAddress=8.8.8.8", url)
        self.assertIn("maxAgeInDays=30", url)
        self.assertEqual("secret", headers["Key"])
        self.assertNotIn("secret", url)
        self.assertEqual(1.5, timeout)
        self.assertEqual(("found", "abuseipdb"), (status, provider))
        self.assertEqual(4, details["abuse_confidence_score"])
        self.assertNotIn("reports", details)

    def test_abuseipdb_error_detail_is_recorded(self):
        body = {"errors": [{"detail": "Daily rate limit exceeded", "status": 429}]}
        with patch("case_analyzer.enrichment._http_json", return_value=(429, body, "unused")):
            status, provider, details = enrichment_module._abuseipdb_lookup("8.8.8.8", 1.0, "key")

        self.assertEqual(("error", "abuseipdb"), (status, provider))
        self.assertEqual(429, details["http_status"])
        self.assertEqual("Daily rate limit exceeded", details["error"])

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

        # Both, not one: DNS answers for the host and URLhaus answers for the whole URL,
        # so the derived host does not stand in for the URL the case actually recorded.
        self.assertEqual(2, len(result.observations))
        by_kind = {item.observable_type: item for item in result.observations}
        self.assertEqual("stage2.evil.test", by_kind["domain"].value)
        self.assertEqual(
            ["source_data.artifacts[0].cef.requestURL#host"], by_kind["domain"].source_paths
        )
        self.assertEqual("https://stage2.evil.test:8443/beacon?id=1", by_kind["url"].value)
        self.assertEqual(["source_data.artifacts[0].cef.requestURL"], by_kind["url"].source_paths)

    def test_url_with_a_literal_address_contributes_an_ip(self):
        case = normalize_case({"id": "case-21", "title": "URL", "requestUrl": "http://8.8.8.8/x"})

        result = enrich_case(case, ip_lookup=_found_ip)

        by_kind = {item.observable_type: item for item in result.observations}
        self.assertEqual("8.8.8.8", by_kind["ip"].value)
        self.assertTrue(by_kind["ip"].source_paths[0].endswith("#host"))
        self.assertEqual("http://8.8.8.8/x", by_kind["url"].value)

    def test_email_contributes_its_domain(self):
        case = normalize_case(
            {"id": "case-22", "title": "Email", "sourceUserEmail": "Attacker@Evil.Test"}
        )

        result = enrich_case(case, domain_lookup=_found_domain)

        by_kind = {item.observable_type: item for item in result.observations}
        self.assertEqual("evil.test", by_kind["domain"].value)
        self.assertTrue(by_kind["domain"].source_paths[0].endswith("#domain"))
        # The local part keeps its case; only the domain half is folded.
        self.assertEqual("Attacker@evil.test", by_kind["email"].value)

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


class UrlhausLookupTests(unittest.TestCase):
    def test_the_url_is_posted_as_a_form_body_with_the_auth_key_in_a_header(self):
        payload = {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["exe", "Loader"],
            "date_added": "2026-08-01 09:00:00 UTC",
            "reporter": "someone",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/1234/",
            "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"},
            "payloads": [
                {"signature": "Loader", "response_md5": "d4"},
                {"signature": "Loader", "response_md5": "e5"},
                {"signature": None},
            ],
        }
        with patch("case_analyzer.enrichment._http_json", return_value=(200, payload, "unused")) as request:
            status, provider, details = enrichment_module._urlhaus_lookup(
                "https://evil.test/beacon", 2.5, "secret"
            )

        url, headers, timeout = request.call_args.args
        self.assertEqual("https://urlhaus-api.abuse.ch/v1/url/", url)
        self.assertEqual("secret", headers["Auth-Key"])
        # The key belongs in a header and the URL in a body; neither may leak into the
        # request line, which is the part that ends up in proxy and server logs.
        self.assertNotIn("secret", url)
        self.assertEqual({"url": "https://evil.test/beacon"}, request.call_args.kwargs["form"])
        self.assertEqual(2.5, timeout)
        self.assertEqual(("found", "urlhaus"), (status, provider))
        self.assertEqual("malware_download", details["threat"])
        # Every payload is counted, including the one URLhaus could not name; the
        # signature list is deduplicated, so the two numbers are deliberately different.
        self.assertEqual(3, details["payload_count"])
        self.assertEqual(["Loader"], details["payload_signatures"])
        self.assertNotIn("response_md5", json.dumps(details))

    def test_a_form_body_makes_the_request_a_post(self):
        with patch("case_analyzer.enrichment.urlopen", return_value=_FakeResponse({"ok": True})) as opener:
            _http_json("https://provider.test", {}, 1.0, form={"url": "https://evil.test/a b"})

        request = opener.call_args.args[0]
        self.assertEqual("POST", request.get_method())
        self.assertEqual(b"url=https%3A%2F%2Fevil.test%2Fa+b", request.data)
        self.assertEqual("application/x-www-form-urlencoded", request.get_header("Content-type"))

    def test_a_miss_is_not_found_rather_than_an_error(self):
        with patch("case_analyzer.enrichment._http_json", return_value=(200, {"query_status": "no_results"}, "x")):
            status, _, details = enrichment_module._urlhaus_lookup("https://ok.test/", 1.0, "key")

        self.assertEqual("not_found", status)
        self.assertEqual("no_results", details["query_status"])

    def test_a_rejected_query_answered_with_http_200_is_an_error(self):
        """URLhaus answers 200 for a refused request too, so the status alone cannot decide."""
        for query_status in ("invalid_url", "http_post_expected", "unauthorized"):
            with self.subTest(query_status=query_status):
                with patch(
                    "case_analyzer.enrichment._http_json",
                    return_value=(200, {"query_status": query_status}, "x"),
                ):
                    status, _, details = enrichment_module._urlhaus_lookup("https://ok.test/", 1.0, "key")

                self.assertEqual("error", status)
                self.assertEqual(query_status, details["error"])


class UrlAndEmailEnrichmentTests(unittest.TestCase):
    def _case(self, value, field="requestURL", hint="url", case_id="case-url"):
        return normalize_case(
            {
                "id": case_id,
                "title": "URL",
                "artifacts": [{"cef": {field: value}, "cef_types": {field: [hint]}}],
            }
        )

    def test_the_url_itself_is_looked_up_when_an_abuse_ch_key_is_configured(self):
        calls = []

        result = enrich_case(
            self._case("https://Evil.test/beacon?id=1"),
            domain_lookup=_found_domain,
            urlhaus_lookup=lambda value, timeout, key: (
                calls.append((value, key)) or ("found", "urlhaus", {"threat": "malware_download"})
            ),
            abuse_ch_api_key="abuse-key",
        )

        self.assertEqual([("https://evil.test/beacon?id=1", "abuse-key")], calls)
        url = next(item for item in result.observations if item.observable_type == "url")
        self.assertEqual(("urlhaus", "found"), (url.provider, url.lookup_status))
        # A URLhaus hit is reputation, so it is recorded beside the case rather than
        # treated as resolving it.
        self.assertEqual("inconclusive", url.comparison_with_case.status)

    def test_without_a_key_the_url_is_recorded_as_skipped_with_the_variable_named(self):
        result = enrich_case(self._case("https://evil.test/beacon"), domain_lookup=_found_domain)

        url = next(item for item in result.observations if item.observable_type == "url")
        self.assertEqual(("local-validation", "skipped"), (url.provider, url.lookup_status))
        self.assertIn("ABUSE_CH_AUTH_KEY", url.details["reason"])
        self.assertEqual("inconclusive", url.comparison_with_case.status)

    def test_virustotal_looks_up_a_url_by_its_base64_identifier(self):
        identifier = base64.urlsafe_b64encode(b"https://evil.test/beacon").decode("ascii").rstrip("=")
        with patch(
            "case_analyzer.enrichment._http_json",
            return_value=(200, {"data": {"attributes": {"reputation": -7, "title": "Login"}}}, "x"),
        ) as request:
            status, _, details = enrichment_module._virustotal_lookup(
                "url", "https://evil.test/beacon", 1.0, "key"
            )

        self.assertEqual(f"https://www.virustotal.com/api/v3/urls/{identifier}", request.call_args.args[0])
        self.assertNotIn("=", request.call_args.args[0].rsplit("/", 1)[1])
        self.assertEqual(("found", -7, "Login"), (status, details["reputation"], details["title"]))

    def test_the_url_identifier_matches_virustotals_documented_example(self):
        """Pins the encoding against a value VirusTotal published, not one we computed.

        The test above derives its expectation with the same expression the
        implementation uses, so it confirms the identifier is placed in the request
        correctly but has no power over the encoding itself. Measured, not assumed:
        swapping the implementation to padded standard base64 leaves that test passing,
        because `https://evil.test/beacon` is exactly 24 bytes -- a multiple of 3, so no
        padding -- and its base64 happens to contain no `+` or `/`, making the two
        alphabets produce identical output for it.

        This literal is the worked example from VirusTotal's v3 URL documentation, which
        specifies "unpadded base64 encoding, as defined in RFC 4648 section 3.2". At 40
        bytes it needs two padding characters, so it does discriminate. A live call would
        still be better; VirusTotal's quota blocked one on 2026-08-20.
        """
        documented = "aHR0cDovL3d3dy5zb21lZG9tYWluLmNvbS90aGlzL2lzL215L3VybA"
        with patch(
            "case_analyzer.enrichment._http_json",
            return_value=(200, {"data": {"attributes": {}}}, "x"),
        ) as request:
            enrichment_module._virustotal_lookup(
                "url", "http://www.somedomain.com/this/is/my/url", 1.0, "key"
            )

        self.assertEqual(f"https://www.virustotal.com/api/v3/urls/{documented}", request.call_args.args[0])

    def test_a_url_reaches_both_urlhaus_and_virustotal_and_its_host_reaches_dns(self):
        result = enrich_case(
            self._case("https://evil.test/beacon"),
            domain_lookup=_found_domain,
            urlhaus_lookup=lambda value, timeout, key: ("found", "urlhaus", {"threat": "malware_download"}),
            abuse_ch_api_key="abuse-key",
            virustotal_lookup=lambda kind, value, timeout, key: ("found", "virustotal", {"reputation": -3}),
            virustotal_api_key="vt-key",
        )

        self.assertEqual(
            {
                ("url", "urlhaus"),
                ("url", "virustotal"),
                ("domain", "test-dns"),
                ("domain", "virustotal"),
            },
            {(item.observable_type, item.provider) for item in result.observations},
        )

    def test_an_email_address_is_recorded_but_never_sent_to_a_provider(self):
        def refuse(*args, **kwargs):
            self.fail("no provider answers for an email address")

        result = enrich_case(
            self._case("Attacker@Evil.test", field="sourceUserEmail", hint="email", case_id="case-email"),
            domain_lookup=_found_domain,
            urlhaus_lookup=refuse,
            abuse_ch_api_key="abuse-key",
            virustotal_lookup=lambda kind, value, timeout, key: (
                self.fail("VirusTotal has no endpoint for an address")
                if kind == "email"
                else ("found", "virustotal", {"reputation": 0})
            ),
            virustotal_api_key="vt-key",
        )

        email = next(item for item in result.observations if item.observable_type == "email")
        self.assertEqual(("local-validation", "skipped", True), (email.provider, email.lookup_status, email.valid))
        self.assertIn("#domain", email.details["reason"])

    def test_an_uncovered_url_never_displaces_a_lookup_the_limit_could_have_spent(self):
        """The limit counts observables, so a URL with no provider must sort behind one."""
        case = normalize_case(
            {
                "id": "case-limit",
                "title": "Limit",
                "artifacts": [
                    {
                        "cef": {"requestURL": "https://evil.test/beacon", "destinationAddress": "8.8.8.8"},
                        "cef_types": {"requestURL": ["url"], "destinationAddress": ["ip"]},
                    }
                ],
            }
        )

        result = enrich_case(case, limit=2, domain_lookup=_found_domain, ip_lookup=_found_ip)

        self.assertTrue(result.truncated)
        self.assertEqual(
            [("ip", "8.8.8.8"), ("domain", "evil.test")],
            [(item.observable_type, item.value) for item in result.observations],
        )

    def test_a_url_answer_is_cached_and_paced_under_its_own_fingerprint(self):
        """The URL and its host are different requests, so one may not answer for the other."""
        self.assertNotEqual(
            enrichment_module._REQUEST_IDS["urlhaus"], enrichment_module._REQUEST_IDS["cloudflare-dns"]
        )
        self.assertEqual(
            {"cloudflare-dns", "rdap", "virustotal", "abuseipdb", "urlhaus"},
            set(enrichment_module._REQUEST_IDS),
        )


if __name__ == "__main__":
    unittest.main()
