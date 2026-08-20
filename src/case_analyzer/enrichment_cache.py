"""On-disk response cache and per-provider request pacing for enrichment.

The two live together because they share a directory: cross-process pacing state is kept
alongside the cached responses, so one `--cache-dir` governs both. They are not the same
switch, though. `--no-cache` turns off the cache; in-process pacing still applies,
because a rate limit is the provider's rule and not a local optimization.

Nothing here ever raises for a storage problem. A cache directory that cannot be read or
written degrades to no cache at all — the run still produces correct results, just at the
cost of the requests the cache would have saved.
"""

import hashlib
import json
import os
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from threading import Lock
from typing import Any, NamedTuple

# How long a provider's answer stays usable. DNS is the most volatile and gets the
# shortest life; registration data changes rarely; reputation sits in between, short
# enough that a verdict from a previous shift is not presented as current.
_TTL_SECONDS: dict[str, float] = {
    "cloudflare-dns": 900.0,
    "rdap": 86400.0,
    "virustotal": 3600.0,
    "abuseipdb": 3600.0,
    "urlhaus": 3600.0,
}
_DEFAULT_TTL_SECONDS = 900.0

# Minimum seconds between requests to one provider. Only providers with a documented
# per-minute limit appear here: VirusTotal's public tier allows 4 requests a minute.
# AbuseIPDB's free tier is a daily quota with no per-minute rule, and abuse.ch publishes
# a fair-use policy rather than a rate for URLhaus, so pacing either would only slow runs
# down without preventing anything. Add an entry here if a provider publishes a number.
_MIN_INTERVAL_SECONDS: dict[str, float] = {
    "virustotal": 15.0,
}

# Only settled answers are cached. An `error` is usually transient — a timeout, a 429, a
# provider outage — and caching it would freeze a bad minute into every later run. A
# `skipped` result records that no request was made at all, so there is nothing to store.
_CACHEABLE_STATUSES = frozenset({"found", "not_found"})


def default_cache_dir() -> Path:
    """The per-user cache location, honoring `XDG_CACHE_HOME` and `LOCALAPPDATA`."""
    override = os.getenv("XDG_CACHE_HOME") or os.getenv("LOCALAPPDATA")
    root = Path(override) if override else Path.home() / ".cache"
    return root / "case-analyzer" / "enrichment"


class CachedResponse(NamedTuple):
    status: str
    provider: str
    details: dict[str, Any]
    # Wall-clock time of the *original* request, not of the run reading it back.
    cached_at: float


def request_fingerprint(provider: str, request_id: str, kind: str, value: str) -> dict[str, str]:
    """What makes two lookups the same lookup.

    `provider` alone is not enough to key on: the same provider answers for more than one
    observable type, from more than one endpoint, and its request shape can change
    without its name changing. `request_id` carries the endpoint, the query parameters,
    and a version marker for the reduced detail set this code stores — bump it whenever
    any of those change, and every entry written by the older shape stops matching
    instead of being silently misread as current.
    """
    return {"provider": provider, "request": request_id, "kind": kind, "value": value}


class EnrichmentCache:
    """A flat directory of provider responses, one JSON file per request fingerprint.

    Writes are atomic (a temporary file in the same directory, then `os.replace`), so a
    concurrent reader sees either the previous entry or the complete new one and never a
    half-written file. Entries are plain JSON and are meant to be readable: a cache you
    cannot inspect is one you cannot audit.

    That readability is also the privacy cost, and it is deliberate rather than
    overlooked. Observable values from a case — addresses, domains, file hashes — and the
    provider's answers about them are written outside the case file, under the cache
    directory, in the clear. Where that is not acceptable, `--no-cache` is the answer.
    """

    def __init__(
        self,
        directory: Path,
        *,
        ttls: Mapping[str, float] | None = None,
        clock=time.time,
    ):
        self._directory = Path(directory)
        self._ttls = dict(_TTL_SECONDS if ttls is None else ttls)
        self._clock = clock

    def _path(self, fingerprint: Mapping[str, str]) -> Path:
        canonical = json.dumps(fingerprint, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return self._directory / f"{digest}.json"

    def _ttl(self, provider: str) -> float:
        return self._ttls.get(provider, _DEFAULT_TTL_SECONDS)

    def get(self, fingerprint: Mapping[str, str]) -> CachedResponse | None:
        """The stored answer, or `None` for a miss, an expired entry, or an unreadable one."""
        try:
            raw = self._path(fingerprint).read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(entry, Mapping):
            return None
        # The file name is a digest, so the stored fingerprint is re-checked rather than
        # trusted: a layout change or a truncated write reads as a miss, never as an
        # answer about a different observable.
        if entry.get("fingerprint") != dict(fingerprint):
            return None
        cached_at = entry.get("cached_at")
        status = entry.get("status")
        details = entry.get("details")
        if not isinstance(cached_at, (int, float)) or status not in _CACHEABLE_STATUSES:
            return None
        if not isinstance(details, Mapping):
            return None
        age = self._clock() - cached_at
        # A negative age means the entry was written by a clock ahead of this one; treat
        # it as a miss rather than honoring an entry that would outlive its TTL.
        if age < 0 or age >= self._ttl(str(fingerprint.get("provider", ""))):
            return None
        return CachedResponse(status, str(entry.get("provider", "")), dict(details), float(cached_at))

    def put(self, fingerprint: Mapping[str, str], status: str, provider: str, details: Mapping[str, Any]) -> None:
        """Store a settled answer. Errors and skips are not cacheable and are ignored."""
        if status not in _CACHEABLE_STATUSES:
            return
        entry = {
            "fingerprint": dict(fingerprint),
            "cached_at": self._clock(),
            "status": status,
            "provider": provider,
            "details": dict(details),
        }
        target = self._path(fingerprint)
        try:
            self._directory.mkdir(parents=True, exist_ok=True)
            handle, temporary = tempfile.mkstemp(dir=self._directory, suffix=".tmp")
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as stream:
                    json.dump(entry, stream)
                os.replace(temporary, target)
            except OSError:
                os.unlink(temporary)
                raise
        except OSError:
            # An unwritable cache costs requests, not correctness.
            return


class ProviderPacer:
    """Keep a minimum interval between requests to one rate-limited provider.

    In process the reservation is exact. `reserve` claims the next start time under a
    lock *before* the caller sleeps, so concurrent workers take distinct slots instead of
    each sleeping the same interval and then firing together — which a per-worker sleep
    would allow, and which is the failure this class exists to prevent.

    Across processes it is best-effort and nothing more. The claimed start time is
    written to a file in the state directory and read back on the next reservation, with
    no lock and no lease, so two processes reserving at the same instant can both
    proceed. That bound is documented rather than closed: a real cross-process lease is
    more machinery than a courtesy rate limit warrants, and the provider's own 429 is the
    backstop either way.
    """

    def __init__(
        self,
        *,
        intervals: Mapping[str, float] | None = None,
        state_dir: Path | None = None,
        clock=time.time,
    ):
        self._intervals = dict(_MIN_INTERVAL_SECONDS if intervals is None else intervals)
        self._state_dir = Path(state_dir) if state_dir is not None else None
        self._clock = clock
        self._claimed: dict[str, float] = {}
        # A plain lock rather than one per provider: a reservation is a dictionary read,
        # a file read, and a write, so contention is not worth the extra state.
        self._lock = Lock()

    def interval(self, provider: str) -> float:
        return self._intervals.get(provider, 0.0)

    def _shared_path(self, provider: str) -> Path | None:
        if self._state_dir is None:
            return None
        safe = "".join(character if character.isalnum() or character in "-_" else "_" for character in provider)
        return self._state_dir / f"pace-{safe}.json"

    def _read_shared(self, provider: str) -> float:
        path = self._shared_path(provider)
        if path is None:
            return 0.0
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return 0.0
        claimed = entry.get("claimed_at") if isinstance(entry, Mapping) else None
        return float(claimed) if isinstance(claimed, (int, float)) else 0.0

    def _write_shared(self, provider: str, claimed_at: float) -> None:
        path = self._shared_path(provider)
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handle, temporary = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as stream:
                    json.dump({"provider": provider, "claimed_at": claimed_at}, stream)
                os.replace(temporary, path)
            except OSError:
                os.unlink(temporary)
                raise
        except OSError:
            return

    def reserve(self, provider: str, *, remaining: float | None = None) -> float | None:
        """Claim the next slot for `provider`.

        Returns the seconds the caller must wait before making the request, or `None` if
        that wait would not fit in `remaining` — in which case no slot is claimed, so the
        time stays available to whichever lookup can still use it.

        `remaining` is a duration rather than a deadline on purpose: the caller measures
        its budget on a monotonic clock and this class stamps a wall clock into a shared
        file, and a duration is the one currency both can agree on.
        """
        interval = self.interval(provider)
        if interval <= 0:
            return 0.0
        with self._lock:
            now = self._clock()
            last = max(self._claimed.get(provider, 0.0), self._read_shared(provider))
            wait = max(0.0, last + interval - now)
            if remaining is not None and wait > remaining:
                return None
            claimed_at = now + wait
            self._claimed[provider] = claimed_at
            self._write_shared(provider, claimed_at)
        return wait
