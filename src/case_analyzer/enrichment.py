import ipaddress
import json
import re
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Lock
from typing import Any, NamedTuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

import idna

from .enrichment_cache import EnrichmentCache, ProviderPacer, request_fingerprint
from .schemas import (
    CanonicalCase,
    CaseAnalyzerEnrichment,
    EnrichmentComparison,
    EnrichmentObservation,
)

_DOMAIN_RE = re.compile(
    r"(?=^.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$",
    re.IGNORECASE,
)
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_ENRICHMENT_WORDS = ("enrichment", "reputation", "threat intelligence", "threat intel")
_USER_AGENT = "soc-analyst-case-analyzer/0.1"
_MAX_CONTEXT_SNIPPETS = 3
_HASH_ALGORITHMS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

# The cache identity of each provider's request: endpoint, the parameters that vary the
# answer, and a trailing version marker for the reduced detail set stored below. Bump the
# marker whenever any of those change, so entries written by the older shape stop
# matching rather than being read back as if they were current.
_REQUEST_IDS = {
    "cloudflare-dns": "https://cloudflare-dns.com/dns-query?type=A|v1",
    "rdap": "iana-rdap-bootstrap|v1",
    "virustotal": "https://www.virustotal.com/api/v3|v1",
    "abuseipdb": "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=30|v1",
}
_KIND_LABELS = {"ip": "IP address", "domain": "domain", "file_hash": "file hash"}

# Type hints and field names that resolve to an observable. The boolean records
# whether a syntax failure contradicts the case: `ip`, `domain`, and hash types
# are unambiguous declarations, while a host name may legitimately be a short
# NetBIOS name rather than a domain, so a failed domain parse says nothing about
# the case itself.
#
# `url` and `email` are extraction-only kinds: the value itself has no provider
# here, so the walker contributes its host or domain part instead (see `_emit`).
_HINT_KINDS: dict[str, tuple[str, bool]] = {
    "ip": ("ip", True),
    "ip address": ("ip", True),
    "ip addr": ("ip", True),
    "ipv4": ("ip", True),
    "ipv4 address": ("ip", True),
    "ipv6": ("ip", True),
    "ipv6 address": ("ip", True),
    "source address": ("ip", True),
    "destination address": ("ip", True),
    "device address": ("ip", True),
    "domain": ("domain", True),
    "domain name": ("domain", True),
    "dns domain": ("domain", True),
    "fqdn": ("domain", True),
    "host name": ("domain", False),
    "hostname": ("domain", False),
    "hash": ("file_hash", True),
    "file hash": ("file_hash", True),
    "md5": ("file_hash", True),
    "sha1": ("file_hash", True),
    "sha256": ("file_hash", True),
    "sha512": ("file_hash", True),
    "url": ("url", True),
    "uri": ("url", True),
    "request url": ("url", True),
    "email": ("email", True),
    "email address": ("email", True),
    "sender email": ("email", True),
    "recipient email": ("email", True),
}

# Recognized field types with no observable to extract at all.
_UNSUPPORTED_HINTS = frozenset(
    {
        "file path",
        "file name",
        "user name",
        "process name",
        "port",
        "mac address",
        "vault id",
    }
)
_IP_QUALIFIERS = frozenset(
    {
        "ip",
        "ipv4",
        "ipv6",
        "source",
        "src",
        "destination",
        "dest",
        "dst",
        "device",
        "remote",
        "local",
        "peer",
        "client",
        "server",
        "host",
    }
)
_PROVIDER_ERRORS = (
    OSError,
    TimeoutError,
    URLError,
    ValueError,
    AttributeError,
    TypeError,
    json.JSONDecodeError,
)

_RDAP_FALLBACK = "https://rdap.arin.net/registry/"
_RDAP_BOOTSTRAP_URLS = {
    4: "https://data.iana.org/rdap/ipv4.json",
    6: "https://data.iana.org/rdap/ipv6.json",
}
# The bootstrap registry rarely changes, so it is cached process-wide; the TTL keeps a
# long-lived caller from pinning a stale copy, or a failed fetch, for the life of the process.
_BOOTSTRAP_TTL_SECONDS = 3600.0
_bootstrap_cache: dict[int, tuple[float, list[tuple[Any, str]]]] = {}
_bootstrap_lock = Lock()
# Held across a fetch, so one cold lookup per address family does the work for the rest.
_bootstrap_fetch_locks = {4: Lock(), 6: Lock()}


class _Observable(NamedTuple):
    kind: str
    value: str
    path: str
    context: tuple[str, ...]
    # True only when `cef_types` declared an unambiguous type for the field.
    declared: bool


class _CircuitBreaker:
    """Stop calling a provider that keeps failing, instead of retrying it per observable."""

    def __init__(self, threshold: int):
        self._threshold = threshold
        self._failures: dict[str, int] = {}
        self._lock = Lock()

    def is_open(self, provider: str) -> bool:
        with self._lock:
            return self._failures.get(provider, 0) >= self._threshold

    def record(self, provider: str, failed: bool) -> None:
        with self._lock:
            self._failures[provider] = self._failures.get(provider, 0) + 1 if failed else 0


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _normalize_hint(hint: str) -> str:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", hint)
    return re.sub(r"[^a-z0-9]+", " ", spaced.casefold()).strip()


def _kind_from_hint(hint: str) -> tuple[str, bool] | None:
    """Resolve a `cef_types` value or field name to (kind, declaration_is_strict)."""
    normalized = _normalize_hint(hint)
    if not normalized or normalized in _UNSUPPORTED_HINTS:
        return None
    known = _HINT_KINDS.get(normalized)
    if known:
        return known
    tokens = normalized.split()
    last = tokens[-1]
    if last in {"ip", "ipv4", "ipv6"}:
        return "ip", True
    if last in {"address", "addr"} and len(tokens) > 1 and tokens[-2] in _IP_QUALIFIERS:
        return "ip", True
    if last in {"domain", "fqdn"}:
        return "domain", True
    if last == "hostname" or tokens[-2:] == ["host", "name"]:
        return "domain", False
    if last in {"hash", "md5", "sha1", "sha256", "sha512"}:
        return "file_hash", True
    if last in {"url", "uri"}:
        return "url", True
    if last == "email" or tokens[-2:] == ["email", "address"]:
        return "email", True
    return None


def _kind_from_hints(hints: Any) -> tuple[str, bool] | None:
    values = hints if isinstance(hints, list) else [hints]
    for item in values:
        resolved = _kind_from_hint(str(item))
        if resolved:
            return resolved
    return None


def _url_host(value: str) -> str | None:
    candidate = value.strip()
    try:
        host = urlsplit(candidate).hostname or urlsplit(f"//{candidate}").hostname
    except ValueError:
        return None
    return host or None


def _emit(
    resolved: tuple[str, bool],
    raw: str,
    path: str,
    context: tuple[str, ...],
    declared: bool,
) -> list[_Observable]:
    """Turn one matched field into the observables it contributes."""
    kind, strict = resolved
    if kind == "url":
        host = _url_host(raw)
        if not host:
            return []
        host_kind = "ip" if _is_ip(host) else "domain"
        # The case declared a URL, not a host, so the derived value is inferred.
        return [_Observable(host_kind, host, f"{path}#host", context, False)]
    if kind == "email":
        domain = raw.rpartition("@")[2].strip()
        if not domain:
            return []
        return [_Observable("domain", domain, f"{path}#domain", context, False)]
    return [_Observable(kind, raw, path, context, declared and strict)]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _walk_observables(
    value: Any,
    path: str = "source_data",
    context: tuple[str, ...] = (),
) -> list[_Observable]:
    found: list[_Observable] = []
    if isinstance(value, Mapping):
        local_context = context
        if "notes" in value or "comments" in value:
            local_context = tuple(
                dict.fromkeys(
                    list(context)
                    + _context_snippets([value.get("notes"), value.get("comments")])
                )
            )
        cef = value.get("cef")
        cef_types = value.get("cef_types")
        declared: dict[str, tuple[str, bool]] = {}
        if isinstance(cef, Mapping) and isinstance(cef_types, Mapping):
            for field, hints in cef_types.items():
                resolved = _kind_from_hints(hints)
                if resolved:
                    declared[str(field)] = resolved
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key == "cef_types":
                continue
            if key == "cef" and isinstance(cef, Mapping):
                # Walk `cef` itself so its contents are still extracted when the
                # ingesting app did not populate `cef_types`.
                found.extend(_walk_cef(cef, child_path, local_context, declared))
                continue
            resolved = _kind_from_hint(str(key))
            if resolved and isinstance(child, str):
                found.extend(_emit(resolved, child, child_path, local_context, False))
            found.extend(_walk_observables(child, child_path, local_context))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_walk_observables(child, f"{path}[{index}]", context))
    return found


def _walk_cef(
    cef: Mapping[str, Any],
    path: str,
    context: tuple[str, ...],
    declared: Mapping[str, tuple[str, bool]],
) -> list[_Observable]:
    found: list[_Observable] = []
    for field, raw in cef.items():
        field_path = f"{path}.{field}"
        resolved = declared.get(str(field))
        is_declared = resolved is not None
        if resolved is None:
            resolved = _kind_from_hint(str(field))
        if resolved and isinstance(raw, str):
            found.extend(_emit(resolved, raw, field_path, context, is_declared))
        elif not isinstance(raw, str):
            found.extend(_walk_observables(raw, field_path, context))
    return found


def _context_snippets(value: Any) -> list[str]:
    """Collect notes and comments that already carry enrichment or reputation claims."""
    snippets: list[str] = []
    if isinstance(value, Mapping):
        parts = [str(value.get(key, "")).strip() for key in ("title", "name", "content", "comment")]
        text = " ".join(part for part in parts if part)
        if text and any(word in text.casefold() for word in _ENRICHMENT_WORDS):
            snippets.append(text[:500])
        for child in value.values():
            snippets.extend(_context_snippets(child))
    elif isinstance(value, list):
        for child in value:
            snippets.extend(_context_snippets(child))
    return [item for item in dict.fromkeys(snippets) if item]


def _as_mapping(body: Any) -> dict[str, Any] | None:
    """Providers are expected to answer with a JSON object; `None` marks anything else."""
    return dict(body) if isinstance(body, Mapping) else None


def _malformed_body(status: int) -> dict[str, Any]:
    return {"http_status": status, "error": "The provider returned a JSON body that is not an object."}


def _http_json(url: str, headers: dict[str, str], timeout: float) -> tuple[int, dict[str, Any] | None, str]:
    """Return the status, the decoded JSON object (`None` if the body is not one), and the answering URL."""
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, _as_mapping(json.load(response)), response.url or url
    except HTTPError as exc:
        try:
            body = _as_mapping(json.load(exc))
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = None
        # A malformed error body still carries its status, which is what the caller reports.
        return exc.code, body if body is not None else {"error": str(exc)}, exc.url or url


def _domain_lookup(value: str, timeout: float) -> tuple[str, str, dict[str, Any]]:
    query = urlencode({"name": value, "type": "A"})
    status, body, _ = _http_json(
        f"https://cloudflare-dns.com/dns-query?{query}",
        {"Accept": "application/dns-json", "User-Agent": _USER_AGENT},
        timeout,
    )
    if body is None:
        return "error", "cloudflare-dns", _malformed_body(status)
    if status != 200:
        return "error", "cloudflare-dns", {"http_status": status, "error": body.get("error", "request failed")}
    answers = [
        {"type": item.get("type"), "ttl": item.get("TTL"), "data": item.get("data")}
        for item in body.get("Answer", [])[:20]
        if isinstance(item, Mapping)
    ]
    return ("found" if answers else "not_found"), "cloudflare-dns", {
        "dns_status": body.get("Status"),
        "authenticated_data": bool(body.get("AD")),
        "answers": answers,
    }


def _cached_bootstrap(version: int) -> list[tuple[Any, str]] | None:
    with _bootstrap_lock:
        entry = _bootstrap_cache.get(version)
    if entry is None or time.monotonic() - entry[0] >= _BOOTSTRAP_TTL_SECONDS:
        return None
    return entry[1]


def _fetch_bootstrap(version: int, timeout: float) -> list[tuple[Any, str]]:
    """Read the bootstrap registry into (network, base URL) pairs; an empty list means fall back."""
    entries: list[tuple[Any, str]] = []
    status, body, _ = _http_json(
        _RDAP_BOOTSTRAP_URLS[version],
        {"Accept": "application/json", "User-Agent": _USER_AGENT},
        timeout,
    )
    services = body.get("services") if status == 200 and body is not None else None
    for service in services if isinstance(services, list) else []:
        if not (isinstance(service, list) and len(service) >= 2):
            continue
        prefixes, urls = service[0], service[1]
        base = next(
            (item for item in urls if isinstance(item, str) and item.startswith("https://")),
            None,
        )
        if not base:
            continue
        for prefix in prefixes if isinstance(prefixes, list) else []:
            try:
                entries.append((ipaddress.ip_network(str(prefix)), base))
            except ValueError:
                continue
    return entries


def _rdap_service_base(address: Any, timeout: float) -> str | None:
    """Resolve the RDAP base URL for an address through the IANA bootstrap registry."""
    version = address.version
    cached = _cached_bootstrap(version)
    if cached is None:
        # One fetch per version at a time: concurrent cold lookups wait rather than duplicate it.
        with _bootstrap_fetch_locks[version]:
            cached = _cached_bootstrap(version)
            if cached is None:
                cached = _fetch_bootstrap(version, timeout)
                with _bootstrap_lock:
                    _bootstrap_cache[version] = (time.monotonic(), cached)
    matches = [entry for entry in cached if address in entry[0]]
    if not matches:
        return None
    return max(matches, key=lambda entry: entry[0].prefixlen)[1]


def _ip_lookup(value: str, timeout: float) -> tuple[str, str, dict[str, Any]]:
    address = ipaddress.ip_address(value)
    if not address.is_global:
        return "skipped", "rdap", {"reason": "RDAP lookup skipped for a non-global IP address"}
    started = time.monotonic()
    base = _rdap_service_base(address, timeout)
    source = "iana-bootstrap" if base else "arin-fallback"
    # A bootstrap fetch and the query itself share one timeout, so the pair stays inside it.
    remaining = timeout - (time.monotonic() - started)
    if remaining <= 0:
        # Starting the query now would run past the caller's bound; the caller decides how to
        # record that, and under a budget it becomes a skipped lookup rather than a failure.
        raise TimeoutError("The RDAP bootstrap fetch used the whole timeout for this lookup.")
    status, body, answered_by = _http_json(
        f"{(base or _RDAP_FALLBACK).rstrip('/')}/ip/{quote(value, safe='')}",
        {"Accept": "application/rdap+json", "User-Agent": _USER_AGENT},
        remaining,
    )
    registry = {"rdap_authority": urlsplit(answered_by).netloc, "rdap_source": source}
    if body is None:
        return "error", "rdap", {**_malformed_body(status), **registry}
    if status == 404:
        return "not_found", "rdap", {"http_status": status, **registry}
    if status != 200:
        return "error", "rdap", {
            "http_status": status,
            **registry,
            "error": body.get("errorCode", "request failed"),
        }
    return "found", "rdap", {
        **registry,
        "handle": body.get("handle"),
        "name": body.get("name"),
        "type": body.get("type"),
        "start_address": body.get("startAddress"),
        "end_address": body.get("endAddress"),
        "country": body.get("country"),
    }


def _virustotal_lookup(
    kind: str,
    value: str,
    timeout: float,
    api_key: str,
) -> tuple[str, str, dict[str, Any]]:
    resource = {"domain": "domains", "ip": "ip_addresses", "file_hash": "files"}[kind]
    status, body, _ = _http_json(
        f"https://www.virustotal.com/api/v3/{resource}/{quote(value, safe='')}",
        {
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
            "x-apikey": api_key,
        },
        timeout,
    )
    if body is None:
        return "error", "virustotal", _malformed_body(status)
    if status == 404:
        return "not_found", "virustotal", {"http_status": status}
    if status != 200:
        error = body.get("error", {})
        message = error.get("message", "request failed") if isinstance(error, Mapping) else str(error)
        return "error", "virustotal", {"http_status": status, "error": message}

    data = body.get("data")
    attributes = data.get("attributes", {}) if isinstance(data, Mapping) else {}
    if not isinstance(attributes, Mapping):
        attributes = {}
    details = {
        "last_analysis_stats": attributes.get("last_analysis_stats", {}),
        "reputation": attributes.get("reputation"),
        "categories": attributes.get("categories", {}),
        "last_analysis_date": attributes.get("last_analysis_date"),
    }
    if kind == "file_hash":
        details["meaningful_name"] = attributes.get("meaningful_name")
        details["type_description"] = attributes.get("type_description")
    return "found", "virustotal", details


def _abuseipdb_lookup(
    value: str,
    timeout: float,
    api_key: str,
) -> tuple[str, str, dict[str, Any]]:
    query = urlencode({"ipAddress": value, "maxAgeInDays": 30})
    status, body, _ = _http_json(
        f"https://api.abuseipdb.com/api/v2/check?{query}",
        {
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
            "Key": api_key,
        },
        timeout,
    )
    if body is None:
        return "error", "abuseipdb", _malformed_body(status)
    if status != 200:
        errors = body.get("errors")
        first = errors[0] if isinstance(errors, list) and errors else None
        message = first.get("detail") if isinstance(first, Mapping) else body.get("error")
        return "error", "abuseipdb", {
            "http_status": status,
            "error": message or "request failed",
        }
    data = body.get("data")
    if not isinstance(data, Mapping):
        return "error", "abuseipdb", {
            "http_status": status,
            "error": "The provider response did not contain a data object.",
        }
    return "found", "abuseipdb", {
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
        "is_whitelisted": data.get("isWhitelisted"),
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "report_window_days": 30,
    }


class _Validated(NamedTuple):
    """The outcome of syntax validation for one observable.

    `unicode_form` is the spelling the case used, carried only when it was not plain
    ASCII; it is what `value` is the punycode encoding of.
    """

    valid: bool
    value: str
    unicode_form: str = ""


def _validate(kind: str, value: str) -> _Validated:
    """Check syntax and normalize, without contacting anything.

    Domains are encoded to punycode first, so an internationalized name written in
    Unicode is validated and looked up instead of being discarded by the ASCII-only
    `_DOMAIN_RE` — the exact shape a homograph attack takes.

    The encoding follows **UTS #46, nontransitional**, via the `idna` package, rather
    than Python's built-in `"idna"` codec. The built-in codec implements IDNA 2003,
    whose transitional mapping rewrites some characters into different ASCII: `faß.de`
    encodes to `fass.de`, a domain someone else may own. Looking up a different name
    than the one the case recorded, and presenting the answer as being about this
    observable, is the failure this choice avoids. Nontransitional is also what current
    browsers resolve with, so what is validated here matches what the user's browser
    would have reached. The two standards agree on every other realistic host value in
    the test suite; where they differ, UTS #46 is the stricter of the two.
    """
    candidate = value.strip().rstrip(".")
    if kind == "ip":
        try:
            return _Validated(True, str(ipaddress.ip_address(candidate)))
        except ValueError:
            return _Validated(False, candidate)
    if kind == "file_hash":
        normalized = candidate.casefold()
        valid = len(normalized) in _HASH_ALGORITHMS and bool(_HEX_RE.fullmatch(normalized))
        return _Validated(valid, normalized)
    unicode_form = candidate if not candidate.isascii() else ""
    try:
        ascii_domain = idna.encode(candidate, uts46=True, transitional=False).decode("ascii").casefold()
    except (idna.IDNAError, UnicodeError):
        return _Validated(False, candidate, unicode_form)
    return _Validated(bool(_DOMAIN_RE.fullmatch(ascii_domain)), ascii_domain, unicode_form)


def _comparison(kind: str, valid: bool, declared: bool, lookup_status: str) -> EnrichmentComparison:
    label = _KIND_LABELS[kind]
    if not valid and declared:
        return EnrichmentComparison(
            status="conflicting",
            explanation=f"The case declares this value as a {label}, but it does not have valid {label} syntax.",
        )
    if not valid:
        return EnrichmentComparison(
            status="not_comparable",
            explanation=(
                f"This value was treated as a {label} because of its field name, not because the case "
                f"declares a type for it, and it does not have valid {label} syntax. That is a limit of "
                "the extractor rather than a contradiction inside the case."
            ),
        )
    if lookup_status == "skipped":
        return EnrichmentComparison(
            status="inconclusive",
            explanation=(
                "No provider lookup was performed for this value, so nothing was retrieved to "
                "compare with existing case conclusions."
            ),
        )
    if lookup_status in {"not_found", "error"}:
        return EnrichmentComparison(
            status="inconclusive",
            explanation="An absent or failed provider result does not confirm or contradict existing case conclusions.",
        )
    return EnrichmentComparison(
        status="not_comparable",
        explanation=(
            "DNS and registration facts do not express reputation and cannot confirm or "
            "contradict existing case conclusions."
        ),
    )


def _priority(item: tuple[tuple[str, str], dict[str, Any]], *, virustotal: bool) -> tuple:
    """Order observables so that a truncated run keeps the most informative lookups."""
    (kind, value), entry = item
    if not entry["valid"]:
        tier = 2
    elif kind == "ip" and not ipaddress.ip_address(value).is_global:
        tier = 1
    elif kind == "file_hash" and not virustotal:
        tier = 1
    else:
        tier = 0
    return tier, 0 if entry["declared"] else 1, -len(entry["paths"]), kind, value


def enrich_case(
    case: CanonicalCase,
    *,
    limit: int = 25,
    timeout: float = 5.0,
    budget: float | None = None,
    concurrency: int = 4,
    failure_threshold: int = 3,
    domain_lookup: Callable[[str, float], tuple[str, str, dict[str, Any]]] = _domain_lookup,
    ip_lookup: Callable[[str, float], tuple[str, str, dict[str, Any]]] = _ip_lookup,
    virustotal_lookup: Callable[[str, str, float, str], tuple[str, str, dict[str, Any]]] = _virustotal_lookup,
    virustotal_api_key: str | None = None,
    abuseipdb_lookup: Callable[[str, float, str], tuple[str, str, dict[str, Any]]] = _abuseipdb_lookup,
    abuseipdb_api_key: str | None = None,
    cache: EnrichmentCache | None = None,
    pacer: ProviderPacer | None = None,
) -> CaseAnalyzerEnrichment:
    if limit < 1:
        raise ValueError("The enrichment limit must be at least 1.")
    if timeout <= 0:
        raise ValueError("The enrichment timeout must be greater than zero.")
    if budget is not None and budget <= 0:
        raise ValueError("The enrichment budget must be greater than zero.")
    if concurrency < 1:
        raise ValueError("The enrichment concurrency must be at least 1.")
    if failure_threshold < 1:
        raise ValueError("The provider failure threshold must be at least 1.")

    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for observable in _walk_observables(case.source_data):
        checked = _validate(observable.kind, observable.value)
        entry = grouped.setdefault(
            (observable.kind, checked.value),
            {"valid": checked.valid, "declared": False, "paths": [], "context": [], "unicode": []},
        )
        entry["paths"].append(observable.path)
        entry["context"].extend(observable.context)
        entry["declared"] = entry["declared"] or observable.declared
        # More than one Unicode spelling can encode to the same name (case, width,
        # ignorable characters), so every distinct one seen is kept rather than the first.
        if checked.unicode_form:
            entry["unicode"].append(checked.unicode_form)
    items = sorted(grouped.items(), key=lambda item: _priority(item, virustotal=bool(virustotal_api_key)))
    selected = items[:limit]

    retrieved_at = _utc_now()
    deadline = time.monotonic() + budget if budget else None
    breaker = _CircuitBreaker(failure_threshold)
    stopped_early = False
    stop_lock = Lock()

    def _budget_exhausted(provider: str):
        nonlocal stopped_early
        with stop_lock:
            stopped_early = True
        return "skipped", provider, {
            "reason": "The overall enrichment time budget was exhausted before this lookup could finish."
        }

    def _paced_out(provider: str, wait: float):
        """The provider's own rate limit does not fit in what is left of the budget."""
        nonlocal stopped_early
        with stop_lock:
            stopped_early = True
        return "skipped", provider, {
            "reason": (
                f"The minimum {wait:.0f}s interval between {provider} requests did not fit in the "
                "remaining enrichment time budget."
            )
        }

    def _call(
        provider: str,
        lookup: Callable[[float], tuple[str, str, dict[str, Any]]],
        *,
        kind: str = "",
        value: str = "",
    ):
        """Run one provider lookup, honoring the cache, the time budget, pacing, and the breaker.

        The order of the gates is deliberate. The cache comes first, because a hit costs
        no request, no budget, and no pacing slot — that is what makes a second run over
        the same case cheap. The budget and the circuit breaker come next, so a slot is
        never reserved for a lookup that is not going to happen. Pacing is last, and its
        wait is spent from the same budget as the request itself: the budget is a
        wall-clock bound on enrichment, and a wait that did not count against it would let
        a run quietly outlast the limit the operator asked for.
        """
        nonlocal stopped_early
        fingerprint = None
        if cache is not None and kind and value:
            fingerprint = request_fingerprint(provider, _REQUEST_IDS[provider], kind, value)
            hit = cache.get(fingerprint)
            if hit is not None:
                return hit.status, hit.provider, {**hit.details, "cache": True}, hit.cached_at
        request_timeout = timeout
        remaining = None
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return (*_budget_exhausted(provider), None)
            # Cap the request itself, so an in-flight lookup cannot outlive the budget.
            request_timeout = min(timeout, remaining)
        if breaker.is_open(provider):
            with stop_lock:
                stopped_early = True
            return "skipped", provider, {
                "reason": f"Lookups against {provider} stopped after {failure_threshold} consecutive failures."
            }, None
        if pacer is not None:
            wait = pacer.reserve(provider, remaining=remaining)
            if wait is None:
                return (*_paced_out(provider, pacer.interval(provider)), None)
            if wait > 0:
                time.sleep(wait)
                if deadline is not None:
                    # The wait consumed budget, so the request's own timeout shrinks with it.
                    request_timeout = min(timeout, max(0.0, deadline - time.monotonic()))
                    if request_timeout <= 0:
                        return (*_budget_exhausted(provider), None)
        try:
            status, answered_by, details = lookup(request_timeout)
        except _PROVIDER_ERRORS as exc:
            if deadline is not None and time.monotonic() >= deadline:
                # The budget cut the request short; that is not evidence against the provider.
                return (*_budget_exhausted(provider), None)
            breaker.record(provider, True)
            return "error", provider, {"error": f"{type(exc).__name__}: {exc}"}, None
        breaker.record(provider, status == "error")
        if cache is not None and fingerprint is not None:
            cache.put(fingerprint, status, answered_by, details)
        return status, answered_by, details, None

    def _retrieved_at(cached_at: float | None) -> datetime:
        """When the recorded answer was actually obtained.

        A cache hit is stamped with the original request's time rather than this run's, so
        a saved enrichment block never claims to have just retrieved hour-old data. The
        run's own time is `CaseAnalyzerEnrichment.generated_at`.
        """
        return retrieved_at if cached_at is None else datetime.fromtimestamp(cached_at, UTC)

    def _shared(item: tuple[tuple[str, str], dict[str, Any]]) -> dict[str, Any]:
        (_, _), source = item
        return {
            "source_paths": list(dict.fromkeys(source["paths"])),
            "unicode_values": list(dict.fromkeys(source["unicode"])),
            "artifact_context": list(dict.fromkeys(source["context"]))[:_MAX_CONTEXT_SNIPPETS],
        }

    def _observe_primary(item: tuple[tuple[str, str], dict[str, Any]]) -> list[EnrichmentObservation]:
        """The unpaced observation every observable gets: validation, DNS, or RDAP."""
        (kind, value), source = item
        valid = source["valid"]
        declared = source["declared"]
        provider = "local-validation"
        details: dict[str, Any] = {}
        lookup_status = "skipped"
        cached_at = None
        if not valid:
            details = {"reason": f"Invalid {_KIND_LABELS[kind]} syntax"}
        elif kind == "file_hash":
            details = {
                "algorithm": _HASH_ALGORITHMS[len(value)],
                "reason": "No keyless provider looks up file hashes; VirusTotal is used when a key is configured.",
            }
        elif kind == "domain":
            lookup_status, provider, details, cached_at = _call(
                "cloudflare-dns",
                lambda request_timeout: domain_lookup(value, request_timeout),
                kind=kind,
                value=value,
            )
        else:
            lookup_status, provider, details, cached_at = _call(
                "rdap",
                lambda request_timeout: ip_lookup(value, request_timeout),
                kind=kind,
                value=value,
            )
        return [
            EnrichmentObservation(
                observable_type=kind,
                value=value,
                valid=valid,
                provider=provider,
                retrieved_at=_retrieved_at(cached_at),
                lookup_status=lookup_status,
                details=details,
                comparison_with_case=_comparison(kind, valid, declared, lookup_status),
                **_shared(item),
            )
        ]

    def _observe_reputation(item: tuple[tuple[str, str], dict[str, Any]]) -> list[EnrichmentObservation]:
        """The reputation observations, which are the paced ones."""
        (kind, value), source = item
        valid = source["valid"]
        results: list[EnrichmentObservation] = []
        virustotal_eligible = valid and (
            kind in {"domain", "file_hash"} or ipaddress.ip_address(value).is_global
        )
        if virustotal_eligible and virustotal_api_key:
            vt_status, vt_provider, vt_details, vt_cached_at = _call(
                "virustotal",
                lambda request_timeout: virustotal_lookup(kind, value, request_timeout, virustotal_api_key),
                kind=kind,
                value=value,
            )
            results.append(
                EnrichmentObservation(
                    observable_type=kind,
                    value=value,
                    valid=True,
                    provider=vt_provider,
                    retrieved_at=_retrieved_at(vt_cached_at),
                    lookup_status=vt_status,
                    details=vt_details,
                    comparison_with_case=EnrichmentComparison(
                        status="inconclusive",
                        explanation=(
                            "VirusTotal reputation is recorded separately and is not used to overwrite "
                            "or automatically resolve existing case conclusions."
                        ),
                    ),
                    **_shared(item),
                )
            )
        abuseipdb_eligible = valid and kind == "ip" and ipaddress.ip_address(value).is_global
        if abuseipdb_eligible and abuseipdb_api_key:
            abuse_status, abuse_provider, abuse_details, abuse_cached_at = _call(
                "abuseipdb",
                lambda request_timeout: abuseipdb_lookup(value, request_timeout, abuseipdb_api_key),
                kind=kind,
                value=value,
            )
            results.append(
                EnrichmentObservation(
                    observable_type=kind,
                    value=value,
                    valid=True,
                    provider=abuse_provider,
                    retrieved_at=_retrieved_at(abuse_cached_at),
                    lookup_status=abuse_status,
                    details=abuse_details,
                    comparison_with_case=EnrichmentComparison(
                        status="inconclusive",
                        explanation=(
                            "AbuseIPDB reputation is recorded separately and is not used to overwrite "
                            "or automatically resolve existing case conclusions."
                        ),
                    ),
                    **_shared(item),
                )
            )
        return results

    if selected:
        with ThreadPoolExecutor(max_workers=min(concurrency, len(selected))) as executor:
            # Two passes, not one, and this is what keeps pacing from starving the
            # providers that have no rate limit. A worker sleeping out VirusTotal's
            # interval occupies its thread; in a single pass those sleeps would sit in
            # front of the DNS and RDAP lookups still queued behind them, and the budget
            # would expire on waiting rather than on answers. Running every unpaced
            # lookup to completion first removes the contention instead of mitigating it.
            #
            # The cost is the overlap given up between the passes. It is a smaller loss
            # than it looks: cached reputation answers never reach the pacer at all, and
            # an uncached one was going to serialize regardless.
            #
            # `map` preserves the priority order within each pass, so the observation
            # order per observable is unchanged: primary, then VirusTotal, then AbuseIPDB.
            primary = list(executor.map(_observe_primary, selected))
            reputation = (
                list(executor.map(_observe_reputation, selected))
                if (virustotal_api_key or abuseipdb_api_key)
                else [[] for _ in selected]
            )
        grouped_observations = [first + second for first, second in zip(primary, reputation, strict=True)]
    else:
        grouped_observations = []

    enrichment = CaseAnalyzerEnrichment(
        generated_at=retrieved_at,
        observations=[item for group in grouped_observations for item in group],
        truncated=len(items) > limit,
        stopped_early=stopped_early,
    )
    case.case_analyzer_enrichment = enrichment
    return enrichment
