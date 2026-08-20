import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from case_analyzer.adapters import normalize_case
from case_analyzer.enrichment import enrich_case
from case_analyzer.enrichment_cache import (
    EnrichmentCache,
    ProviderPacer,
    default_cache_dir,
    request_fingerprint,
)


class _Clock:
    """A settable clock, so TTL and pacing are tested without sleeping through them."""

    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


def _case(**overrides):
    exported = {"id": "case-cache", "title": "Cache", "destinationDnsDomain": "example.com"}
    exported.update(overrides)
    return normalize_case(exported)


class FingerprintTests(unittest.TestCase):
    def test_the_same_value_under_different_providers_is_a_different_request(self):
        """`provider` plus value is not a key: the plan's collision cases must not collide."""
        base = request_fingerprint("virustotal", "vt|v1", "domain", "example.com")
        self.assertNotEqual(base, request_fingerprint("abuseipdb", "vt|v1", "domain", "example.com"))
        self.assertNotEqual(base, request_fingerprint("virustotal", "vt|v1", "file_hash", "example.com"))
        self.assertNotEqual(base, request_fingerprint("virustotal", "vt|v2", "domain", "example.com"))

    def test_a_bumped_request_id_retires_the_old_entry_rather_than_reading_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = EnrichmentCache(Path(tmp))
            old = request_fingerprint("virustotal", "vt|v1", "domain", "example.com")
            cache.put(old, "found", "virustotal", {"malicious": 3})
            new = request_fingerprint("virustotal", "vt|v2", "domain", "example.com")
            self.assertIsNone(cache.get(new))
            self.assertIsNotNone(cache.get(old))


class CacheTests(unittest.TestCase):
    def test_a_stored_answer_comes_back_with_its_original_time(self):
        clock = _Clock()
        with tempfile.TemporaryDirectory() as tmp:
            cache = EnrichmentCache(Path(tmp), clock=clock)
            fingerprint = request_fingerprint("cloudflare-dns", "dns|v1", "domain", "example.com")
            cache.put(fingerprint, "found", "cloudflare-dns", {"answers": [{"data": "93.184.216.34"}]})
            clock.now += 60
            hit = cache.get(fingerprint)
            self.assertEqual("found", hit.status)
            self.assertEqual("cloudflare-dns", hit.provider)
            self.assertEqual([{"data": "93.184.216.34"}], hit.details["answers"])
            self.assertEqual(clock.now - 60, hit.cached_at)

    def test_an_entry_expires_at_its_provider_ttl(self):
        """TTLs are per provider: DNS is short-lived, registration data is not."""
        clock = _Clock()
        with tempfile.TemporaryDirectory() as tmp:
            cache = EnrichmentCache(Path(tmp), clock=clock)
            dns = request_fingerprint("cloudflare-dns", "dns|v1", "domain", "example.com")
            rdap = request_fingerprint("rdap", "rdap|v1", "ip", "8.8.8.8")
            cache.put(dns, "found", "cloudflare-dns", {})
            cache.put(rdap, "found", "rdap", {})
            clock.now += 1800
            self.assertIsNone(cache.get(dns))
            self.assertIsNotNone(cache.get(rdap))

    def test_errors_and_skips_are_never_stored(self):
        """A 429 or an outage must not be frozen into every later run."""
        with tempfile.TemporaryDirectory() as tmp:
            cache = EnrichmentCache(Path(tmp))
            for status in ("error", "skipped"):
                fingerprint = request_fingerprint("virustotal", "vt|v1", "ip", f"1.1.1.{len(status)}")
                cache.put(fingerprint, status, "virustotal", {"http_status": 429})
                self.assertIsNone(cache.get(fingerprint))
            self.assertEqual([], sorted(Path(tmp).glob("*.json")))

    def test_a_corrupt_or_foreign_entry_reads_as_a_miss(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = EnrichmentCache(Path(tmp))
            fingerprint = request_fingerprint("rdap", "rdap|v1", "ip", "8.8.8.8")
            cache.put(fingerprint, "found", "rdap", {"handle": "GOOGLE"})
            (stored,) = list(Path(tmp).glob("*.json"))

            stored.write_text("{not json", encoding="utf-8")
            self.assertIsNone(cache.get(fingerprint))

            # A file whose name matches but whose recorded fingerprint does not is never
            # read back as an answer about this observable.
            entry = {
                "fingerprint": request_fingerprint("rdap", "rdap|v1", "ip", "9.9.9.9"),
                "cached_at": time.time(),
                "status": "found",
                "provider": "rdap",
                "details": {"handle": "OTHER"},
            }
            stored.write_text(json.dumps(entry), encoding="utf-8")
            self.assertIsNone(cache.get(fingerprint))

    def test_an_entry_from_a_clock_in_the_future_is_ignored(self):
        clock = _Clock()
        with tempfile.TemporaryDirectory() as tmp:
            writer = EnrichmentCache(Path(tmp), clock=_Clock(clock.now + 10_000))
            fingerprint = request_fingerprint("rdap", "rdap|v1", "ip", "8.8.8.8")
            writer.put(fingerprint, "found", "rdap", {})
            self.assertIsNone(EnrichmentCache(Path(tmp), clock=clock).get(fingerprint))

    def test_an_unwritable_directory_costs_requests_rather_than_the_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "not-a-directory"
            blocker.write_text("", encoding="utf-8")
            cache = EnrichmentCache(blocker / "cache")
            fingerprint = request_fingerprint("rdap", "rdap|v1", "ip", "8.8.8.8")
            cache.put(fingerprint, "found", "rdap", {})
            self.assertIsNone(cache.get(fingerprint))

    def test_no_partial_file_is_ever_left_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = EnrichmentCache(Path(tmp))
            for index in range(20):
                cache.put(request_fingerprint("rdap", "rdap|v1", "ip", f"8.8.8.{index}"), "found", "rdap", {})
            self.assertEqual([], list(Path(tmp).glob("*.tmp")))
            self.assertEqual(20, len(list(Path(tmp).glob("*.json"))))

    def test_the_default_directory_honors_the_cache_environment(self):
        self.assertEqual(("enrichment", "case-analyzer"), default_cache_dir().parts[-1:-3:-1])


class PacerTests(unittest.TestCase):
    def test_the_first_request_waits_and_the_next_is_spaced_by_the_interval(self):
        clock = _Clock()
        pacer = ProviderPacer(intervals={"virustotal": 15.0}, clock=clock)
        self.assertEqual(0.0, pacer.reserve("virustotal"))
        self.assertEqual(15.0, pacer.reserve("virustotal"))
        clock.now += 15
        self.assertEqual(15.0, pacer.reserve("virustotal"))

    def test_an_unpaced_provider_never_waits(self):
        pacer = ProviderPacer(intervals={"virustotal": 15.0}, clock=_Clock())
        for _ in range(5):
            self.assertEqual(0.0, pacer.reserve("cloudflare-dns"))

    def test_concurrent_workers_take_distinct_slots(self):
        """The failure a per-worker sleep allows: everyone waits, then everyone fires."""
        pacer = ProviderPacer(intervals={"virustotal": 15.0}, clock=_Clock())
        waits = []
        lock = threading.Lock()

        def reserve():
            wait = pacer.reserve("virustotal")
            with lock:
                waits.append(wait)

        threads = [threading.Thread(target=reserve) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([0.0, 15.0, 30.0, 45.0], sorted(waits))

    def test_a_wait_that_does_not_fit_the_budget_claims_no_slot(self):
        """Refusing must not consume the interval; the time stays for a lookup that fits."""
        clock = _Clock()
        pacer = ProviderPacer(intervals={"virustotal": 15.0}, clock=clock)
        self.assertEqual(0.0, pacer.reserve("virustotal", remaining=60.0))
        self.assertIsNone(pacer.reserve("virustotal", remaining=5.0))
        self.assertEqual(15.0, pacer.reserve("virustotal", remaining=60.0))

    def test_pacing_state_is_shared_across_processes_through_the_directory(self):
        clock = _Clock()
        with tempfile.TemporaryDirectory() as tmp:
            first = ProviderPacer(intervals={"virustotal": 15.0}, state_dir=Path(tmp), clock=clock)
            self.assertEqual(0.0, first.reserve("virustotal"))
            # A second pacer stands in for a second process: it has no in-memory history
            # and must still see the claim the first one wrote.
            second = ProviderPacer(intervals={"virustotal": 15.0}, state_dir=Path(tmp), clock=clock)
            self.assertEqual(15.0, second.reserve("virustotal"))

    def test_without_a_state_directory_pacing_is_process_local(self):
        clock = _Clock()
        first = ProviderPacer(intervals={"virustotal": 15.0}, clock=clock)
        self.assertEqual(0.0, first.reserve("virustotal"))
        self.assertEqual(0.0, ProviderPacer(intervals={"virustotal": 15.0}, clock=clock).reserve("virustotal"))


class EnrichCaseCachingTests(unittest.TestCase):
    def test_a_second_run_answers_from_the_cache_without_calling_the_provider(self):
        calls = []

        def domain_lookup(value, timeout):
            calls.append(value)
            return "found", "cloudflare-dns", {"answers": [{"data": "93.184.216.34"}]}

        with tempfile.TemporaryDirectory() as tmp:
            cache = EnrichmentCache(Path(tmp))
            first = enrich_case(_case(), domain_lookup=domain_lookup, cache=cache)
            second = enrich_case(_case(), domain_lookup=domain_lookup, cache=cache)

        self.assertEqual(["example.com"], calls)
        self.assertNotIn("cache", first.observations[0].details)
        self.assertIs(True, second.observations[0].details["cache"])
        self.assertEqual("found", second.observations[0].lookup_status)
        self.assertEqual(
            first.observations[0].details["answers"],
            second.observations[0].details["answers"],
        )

    def test_a_cached_observation_is_stamped_with_the_original_retrieval_time(self):
        """`retrieved_at` must not claim a fresh lookup of an old answer."""
        with tempfile.TemporaryDirectory() as tmp:
            cache = EnrichmentCache(Path(tmp))
            first = enrich_case(_case(), domain_lookup=lambda v, t: ("found", "cloudflare-dns", {}), cache=cache)
            time.sleep(0.01)
            second = enrich_case(
                _case(),
                domain_lookup=lambda v, t: self.fail("the cached answer must be used"),
                cache=cache,
            )
        self.assertLess(second.observations[0].retrieved_at, second.generated_at)
        self.assertAlmostEqual(
            first.observations[0].retrieved_at.timestamp(),
            second.observations[0].retrieved_at.timestamp(),
            delta=1.0,
        )

    def test_without_a_cache_every_run_contacts_the_provider(self):
        calls = []
        for _ in range(2):
            enrich_case(_case(), domain_lookup=lambda v, t: (calls.append(v), ("found", "x", {}))[1])
        self.assertEqual(["example.com", "example.com"], calls)

    def test_a_failed_lookup_is_retried_rather_than_cached(self):
        attempts = []

        def failing(value, timeout):
            attempts.append(value)
            return "error", "cloudflare-dns", {"http_status": 429, "error": "rate limited"}

        with tempfile.TemporaryDirectory() as tmp:
            cache = EnrichmentCache(Path(tmp))
            enrich_case(_case(), domain_lookup=failing, cache=cache)
            enrich_case(_case(), domain_lookup=failing, cache=cache)
        self.assertEqual(2, len(attempts))


class EnrichCasePacingTests(unittest.TestCase):
    def _ip_case(self, count):
        return normalize_case(
            {
                "id": "case-pacing",
                "title": "Pacing",
                "artifacts": [
                    {"cef": {"destinationAddress": f"8.8.8.{index}"}, "cef_types": {"destinationAddress": ["ip"]}}
                    for index in range(count)
                ],
            }
        )

    def test_a_pacing_wait_that_exceeds_the_budget_skips_rather_than_sleeps(self):
        """The decision recorded in review point 3: waits are spent from the budget.

        With a one-second budget and a fifteen-second interval, the first VirusTotal
        lookup fits and the rest cannot, so they are recorded as skipped with a reason
        that names pacing rather than a provider failure.
        """
        started = time.monotonic()
        result = enrich_case(
            self._ip_case(4),
            budget=1.0,
            concurrency=4,
            ip_lookup=lambda value, timeout: ("found", "rdap", {"handle": value}),
            virustotal_lookup=lambda kind, value, timeout, key: ("found", "virustotal", {"malicious": 0}),
            virustotal_api_key="test-key",
            pacer=ProviderPacer(intervals={"virustotal": 15.0}),
        )
        elapsed = time.monotonic() - started

        virustotal = [item for item in result.observations if item.provider == "virustotal"]
        skipped = [item for item in virustotal if item.lookup_status == "skipped"]
        self.assertEqual(4, len(virustotal))
        self.assertEqual(3, len(skipped))
        for item in skipped:
            self.assertIn("interval", item.details["reason"])
            self.assertIn("virustotal", item.details["reason"])
        self.assertTrue(result.stopped_early)
        # Nothing slept for an interval it could not afford.
        self.assertLess(elapsed, 5.0)

    def test_unpaced_providers_all_complete_before_any_paced_lookup_waits(self):
        """Pacing must not starve the providers that have no rate limit.

        The two-pass split is what guarantees this: every RDAP lookup has finished before
        the first VirusTotal reservation is made, so a sleeping worker cannot be holding a
        thread an RDAP lookup still needed.
        """
        order = []
        lock = threading.Lock()

        def ip_lookup(value, timeout):
            with lock:
                order.append("rdap")
            return "found", "rdap", {"handle": value}

        def virustotal_lookup(kind, value, timeout, key):
            with lock:
                order.append("virustotal")
            return "found", "virustotal", {"malicious": 0}

        enrich_case(
            self._ip_case(6),
            concurrency=3,
            ip_lookup=ip_lookup,
            virustotal_lookup=virustotal_lookup,
            virustotal_api_key="test-key",
            pacer=ProviderPacer(intervals={"virustotal": 0.0}),
        )

        self.assertEqual(["rdap"] * 6 + ["virustotal"] * 6, order)

    def test_a_cached_reputation_answer_never_reaches_the_pacer(self):
        """A cache hit costs no request, so it must cost no pacing slot either."""
        reservations = []

        class _CountingPacer(ProviderPacer):
            def reserve(self, provider, *, remaining=None):
                reservations.append(provider)
                return super().reserve(provider, remaining=remaining)

        def virustotal_lookup(kind, value, timeout, key):
            return "found", "virustotal", {"malicious": 0}

        with tempfile.TemporaryDirectory() as tmp:
            cache = EnrichmentCache(Path(tmp))
            runs = [
                enrich_case(
                    self._ip_case(1),
                    ip_lookup=lambda value, timeout: ("found", "rdap", {}),
                    virustotal_lookup=virustotal_lookup,
                    virustotal_api_key="test-key",
                    cache=cache,
                    pacer=_CountingPacer(intervals={"virustotal": 0.0}),
                )
                for _ in range(2)
            ]

        # The second run reserves nothing at all: both answers came from the cache, so
        # neither a request nor a rate-limit slot was spent on it.
        self.assertEqual(["rdap", "virustotal"], reservations)
        self.assertTrue(all(item.details["cache"] for item in runs[1].observations))


if __name__ == "__main__":
    unittest.main()
