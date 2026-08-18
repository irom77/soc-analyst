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
_bootstrap_cache: dict[int, list[tuple[Any, str]]] = {}
_bootstrap_lock = Lock()


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


def _as_mapping(body: Any) -> dict[str, Any]:
    """Providers are expected to answer with a JSON object; anything else is an error."""
    if isinstance(body, Mapping):
        return dict(body)
    return {"error": f"The provider returned a non-object JSON body: {str(body)[:200]}"}


def _http_json(url: str, headers: dict[str, str], timeout: float) -> tuple[int, dict[str, Any], str]:
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, _as_mapping(json.load(response)), response.url or url
    except HTTPError as exc:
        try:
            body = _as_mapping(json.load(exc))
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = {"error": str(exc)}
        return exc.code, body, exc.url or url


def _domain_lookup(value: str, timeout: float) -> tuple[str, str, dict[str, Any]]:
    query = urlencode({"name": value, "type": "A"})
    status, body, _ = _http_json(
        f"https://cloudflare-dns.com/dns-query?{query}",
        {"Accept": "application/dns-json", "User-Agent": _USER_AGENT},
        timeout,
    )
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


def _rdap_service_base(address: Any, timeout: float) -> str | None:
    """Resolve the RDAP base URL for an address through the IANA bootstrap registry."""
    version = address.version
    with _bootstrap_lock:
        cached = _bootstrap_cache.get(version)
    if cached is None:
        cached = []
        status, body, _ = _http_json(
            _RDAP_BOOTSTRAP_URLS[version],
            {"Accept": "application/json", "User-Agent": _USER_AGENT},
            timeout,
        )
        services = body.get("services") if status == 200 else None
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
                    cached.append((ipaddress.ip_network(str(prefix)), base))
                except ValueError:
                    continue
        with _bootstrap_lock:
            _bootstrap_cache[version] = cached
    matches = [entry for entry in cached if address in entry[0]]
    if not matches:
        return None
    return max(matches, key=lambda entry: entry[0].prefixlen)[1]


def _ip_lookup(value: str, timeout: float) -> tuple[str, str, dict[str, Any]]:
    address = ipaddress.ip_address(value)
    if not address.is_global:
        return "skipped", "rdap", {"reason": "RDAP lookup skipped for a non-global IP address"}
    base = _rdap_service_base(address, timeout)
    source = "iana-bootstrap" if base else "arin-fallback"
    status, body, answered_by = _http_json(
        f"{(base or _RDAP_FALLBACK).rstrip('/')}/ip/{quote(value, safe='')}",
        {"Accept": "application/rdap+json", "User-Agent": _USER_AGENT},
        timeout,
    )
    registry = {"rdap_authority": urlsplit(answered_by).netloc, "rdap_source": source}
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


def _validate(kind: str, value: str) -> tuple[bool, str]:
    candidate = value.strip().rstrip(".")
    if kind == "ip":
        try:
            return True, str(ipaddress.ip_address(candidate))
        except ValueError:
            return False, candidate
    if kind == "file_hash":
        normalized = candidate.casefold()
        valid = len(normalized) in _HASH_ALGORITHMS and bool(_HEX_RE.fullmatch(normalized))
        return valid, normalized
    try:
        ascii_domain = candidate.encode("idna").decode("ascii").casefold()
    except UnicodeError:
        return False, candidate
    return bool(_DOMAIN_RE.fullmatch(ascii_domain)), ascii_domain


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
        valid, normalized = _validate(observable.kind, observable.value)
        entry = grouped.setdefault(
            (observable.kind, normalized),
            {"valid": valid, "declared": False, "paths": [], "context": []},
        )
        entry["paths"].append(observable.path)
        entry["context"].extend(observable.context)
        entry["declared"] = entry["declared"] or observable.declared
    items = sorted(grouped.items(), key=lambda item: _priority(item, virustotal=bool(virustotal_api_key)))
    selected = items[:limit]

    retrieved_at = _utc_now()
    deadline = time.monotonic() + budget if budget else None
    breaker = _CircuitBreaker(failure_threshold)
    stopped_early = False
    stop_lock = Lock()

    def _call(provider: str, lookup: Callable[[], tuple[str, str, dict[str, Any]]]):
        """Run one provider lookup, honoring the time budget and the circuit breaker."""
        nonlocal stopped_early
        if deadline is not None and time.monotonic() >= deadline:
            with stop_lock:
                stopped_early = True
            return "skipped", provider, {
                "reason": "The overall enrichment time budget was exhausted before this lookup."
            }
        if breaker.is_open(provider):
            with stop_lock:
                stopped_early = True
            return "skipped", provider, {
                "reason": f"Lookups against {provider} stopped after {failure_threshold} consecutive failures."
            }
        try:
            status, answered_by, details = lookup()
        except _PROVIDER_ERRORS as exc:
            breaker.record(provider, True)
            return "error", provider, {"error": f"{type(exc).__name__}: {exc}"}
        breaker.record(provider, status == "error")
        return status, answered_by, details

    def _observe(item: tuple[tuple[str, str], dict[str, Any]]) -> list[EnrichmentObservation]:
        (kind, value), source = item
        valid = source["valid"]
        declared = source["declared"]
        source_paths = list(dict.fromkeys(source["paths"]))
        context = list(dict.fromkeys(source["context"]))[:_MAX_CONTEXT_SNIPPETS]
        provider = "local-validation"
        details: dict[str, Any] = {}
        lookup_status = "skipped"
        if not valid:
            details = {"reason": f"Invalid {_KIND_LABELS[kind]} syntax"}
        elif kind == "file_hash":
            details = {
                "algorithm": _HASH_ALGORITHMS[len(value)],
                "reason": "No keyless provider looks up file hashes; VirusTotal is used when a key is configured.",
            }
        elif kind == "domain":
            lookup_status, provider, details = _call(
                "cloudflare-dns", lambda: domain_lookup(value, timeout)
            )
        else:
            lookup_status, provider, details = _call("rdap", lambda: ip_lookup(value, timeout))
        results = [
            EnrichmentObservation(
                observable_type=kind,
                value=value,
                valid=valid,
                source_paths=source_paths,
                provider=provider,
                retrieved_at=retrieved_at,
                lookup_status=lookup_status,
                details=details,
                artifact_context=context,
                comparison_with_case=_comparison(kind, valid, declared, lookup_status),
            )
        ]
        virustotal_eligible = valid and (
            kind in {"domain", "file_hash"} or ipaddress.ip_address(value).is_global
        )
        if virustotal_eligible and virustotal_api_key:
            vt_status, vt_provider, vt_details = _call(
                "virustotal", lambda: virustotal_lookup(kind, value, timeout, virustotal_api_key)
            )
            results.append(
                EnrichmentObservation(
                    observable_type=kind,
                    value=value,
                    valid=True,
                    source_paths=source_paths,
                    provider=vt_provider,
                    retrieved_at=retrieved_at,
                    lookup_status=vt_status,
                    details=vt_details,
                    artifact_context=context,
                    comparison_with_case=EnrichmentComparison(
                        status="inconclusive",
                        explanation=(
                            "VirusTotal reputation is recorded separately and is not used to overwrite "
                            "or automatically resolve existing case conclusions."
                        ),
                    ),
                )
            )
        return results

    if selected:
        with ThreadPoolExecutor(max_workers=min(concurrency, len(selected))) as executor:
            # `map` preserves the priority order regardless of completion order.
            grouped_observations = list(executor.map(_observe, selected))
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
