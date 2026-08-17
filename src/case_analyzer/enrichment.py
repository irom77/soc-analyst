import ipaddress
import json
import re
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
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
_IP_KEYS = {"ip", "src_ip", "dst_ip", "sourceaddress", "destinationaddress"}
_DOMAIN_KEYS = {"domain", "hostname", "fqdn", "destinationdnsdomain", "sourcednsdomain"}
_ENRICHMENT_WORDS = ("enrichment", "reputation", "threat intelligence", "threat intel")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _kind_from_hint(hint: str) -> str | None:
    normalized = hint.casefold().replace("-", "_")
    if normalized in _IP_KEYS or normalized.endswith("_ip"):
        return "ip"
    if normalized in _DOMAIN_KEYS or "domain" in normalized or normalized.endswith("hostname"):
        return "domain"
    return None


def _walk_observables(
    value: Any,
    path: str = "source_data",
    context: tuple[str, ...] = (),
) -> list[tuple[str, str, str, tuple[str, ...]]]:
    found: list[tuple[str, str, str, tuple[str, ...]]] = []
    if isinstance(value, Mapping):
        cef = value.get("cef")
        cef_types = value.get("cef_types")
        local_context = context
        if isinstance(cef, Mapping):
            local_context = tuple(
                _existing_enrichment_context([value.get("notes", []), value.get("comments", [])])
            )
        if isinstance(cef, Mapping) and isinstance(cef_types, Mapping):
            for field, type_hints in cef_types.items():
                hints = type_hints if isinstance(type_hints, list) else [type_hints]
                kind = next((_kind_from_hint(str(item)) for item in hints if _kind_from_hint(str(item))), None)
                raw = cef.get(field)
                if kind and isinstance(raw, str):
                    found.append((kind, raw, f"{path}.cef.{field}", local_context))
        for key, child in value.items():
            child_path = f"{path}.{key}"
            kind = _kind_from_hint(str(key))
            if kind and isinstance(child, str):
                found.append((kind, child, child_path, local_context))
            if key not in {"cef", "cef_types"}:
                found.extend(_walk_observables(child, child_path, local_context))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_walk_observables(child, f"{path}[{index}]", context))
    return found


def _existing_enrichment_context(value: Any) -> list[str]:
    snippets: list[str] = []
    if isinstance(value, Mapping):
        text = " ".join(str(value.get(key, "")) for key in ("title", "name", "content", "comment"))
        if any(word in text.casefold() for word in _ENRICHMENT_WORDS):
            snippets.append(text.strip()[:500])
        for child in value.values():
            snippets.extend(_existing_enrichment_context(child))
    elif isinstance(value, list):
        for child in value:
            snippets.extend(_existing_enrichment_context(child))
    return list(dict.fromkeys(item for item in snippets if item))[:3]


def _http_json(url: str, headers: dict[str, str], timeout: float) -> tuple[int, dict[str, Any]]:
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, json.load(response)
    except HTTPError as exc:
        try:
            body = json.load(exc)
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = {"error": str(exc)}
        return exc.code, body


def _domain_lookup(value: str, timeout: float) -> tuple[str, str, dict[str, Any]]:
    query = urlencode({"name": value, "type": "A"})
    status, body = _http_json(
        f"https://cloudflare-dns.com/dns-query?{query}",
        {"Accept": "application/dns-json", "User-Agent": "soc-analyst-case-analyzer/0.1"},
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


def _ip_lookup(value: str, timeout: float) -> tuple[str, str, dict[str, Any]]:
    address = ipaddress.ip_address(value)
    if not address.is_global:
        return "skipped", "arin-rdap", {"reason": "RDAP lookup skipped for a non-global IP address"}
    status, body = _http_json(
        f"https://rdap.arin.net/registry/ip/{quote(value, safe='')}",
        {"Accept": "application/rdap+json", "User-Agent": "soc-analyst-case-analyzer/0.1"},
        timeout,
    )
    if status == 404:
        return "not_found", "arin-rdap", {"http_status": status}
    if status != 200:
        return "error", "arin-rdap", {"http_status": status, "error": body.get("errorCode", "request failed")}
    return "found", "arin-rdap", {
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
    resource = "domains" if kind == "domain" else "ip_addresses"
    status, body = _http_json(
        f"https://www.virustotal.com/api/v3/{resource}/{quote(value, safe='')}",
        {
            "Accept": "application/json",
            "User-Agent": "soc-analyst-case-analyzer/0.1",
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

    attributes = body.get("data", {}).get("attributes", {})
    return "found", "virustotal", {
        "last_analysis_stats": attributes.get("last_analysis_stats", {}),
        "reputation": attributes.get("reputation"),
        "categories": attributes.get("categories", {}),
        "last_analysis_date": attributes.get("last_analysis_date"),
    }


def _validate(kind: str, value: str) -> tuple[bool, str]:
    candidate = value.strip().rstrip(".")
    if kind == "ip":
        try:
            return True, str(ipaddress.ip_address(candidate))
        except ValueError:
            return False, candidate
    try:
        ascii_domain = candidate.encode("idna").decode("ascii").casefold()
    except UnicodeError:
        return False, candidate
    return bool(_DOMAIN_RE.fullmatch(ascii_domain)), ascii_domain


def _comparison(kind: str, valid: bool, lookup_status: str) -> EnrichmentComparison:
    if not valid:
        return EnrichmentComparison(
            status="conflicting",
            explanation=f"The value is labeled as a {kind} in the case but does not have valid {kind} syntax.",
        )
    if lookup_status in {"not_found", "error"}:
        return EnrichmentComparison(
            status="inconclusive",
            explanation="An absent or failed provider result does not confirm or contradict existing case conclusions.",
        )
    return EnrichmentComparison(
        status="not_comparable",
        explanation="DNS and registration facts do not express reputation and cannot confirm or contradict existing case conclusions.",
    )


def enrich_case(
    case: CanonicalCase,
    *,
    limit: int = 25,
    timeout: float = 5.0,
    domain_lookup: Callable[[str, float], tuple[str, str, dict[str, Any]]] = _domain_lookup,
    ip_lookup: Callable[[str, float], tuple[str, str, dict[str, Any]]] = _ip_lookup,
    virustotal_lookup: Callable[[str, str, float, str], tuple[str, str, dict[str, Any]]] = _virustotal_lookup,
    virustotal_api_key: str | None = None,
) -> CaseAnalyzerEnrichment:
    if limit < 1:
        raise ValueError("The enrichment limit must be at least 1.")
    if timeout <= 0:
        raise ValueError("The enrichment timeout must be greater than zero.")

    grouped: dict[tuple[str, str], dict[str, list[str]]] = {}
    for kind, raw_value, path, existing_context in _walk_observables(case.source_data):
        valid, normalized = _validate(kind, raw_value)
        key = (kind, normalized)
        entry = grouped.setdefault(key, {"paths": [], "context": []})
        entry["paths"].append(path)
        entry["context"].extend(existing_context)
    items = list(grouped.items())
    observations: list[EnrichmentObservation] = []
    retrieved_at = _utc_now()
    for (kind, value), source in items[:limit]:
        valid, _ = _validate(kind, value)
        provider = "local-validation"
        details: dict[str, Any] = {}
        lookup_status = "skipped"
        if not valid:
            details = {"reason": f"Invalid {kind} syntax"}
        else:
            try:
                lookup_status, provider, details = (
                    domain_lookup(value, timeout) if kind == "domain" else ip_lookup(value, timeout)
                )
            except (OSError, TimeoutError, URLError, ValueError, json.JSONDecodeError) as exc:
                lookup_status = "error"
                provider = "cloudflare-dns" if kind == "domain" else "arin-rdap"
                details = {"error": f"{type(exc).__name__}: {exc}"}
        observations.append(
            EnrichmentObservation(
                observable_type=kind,
                value=value,
                valid=valid,
                source_paths=list(dict.fromkeys(source["paths"])),
                provider=provider,
                retrieved_at=retrieved_at,
                lookup_status=lookup_status,
                details=details,
                existing_case_context=list(dict.fromkeys(source["context"]))[:3],
                comparison_with_case=_comparison(kind, valid, lookup_status),
            )
        )
        virustotal_eligible = valid and (
            kind == "domain" or ipaddress.ip_address(value).is_global
        )
        if virustotal_eligible and virustotal_api_key:
            try:
                vt_status, vt_provider, vt_details = virustotal_lookup(
                    kind, value, timeout, virustotal_api_key
                )
            except (OSError, TimeoutError, URLError, ValueError, json.JSONDecodeError) as exc:
                vt_status = "error"
                vt_provider = "virustotal"
                vt_details = {"error": f"{type(exc).__name__}: {exc}"}
            observations.append(
                EnrichmentObservation(
                    observable_type=kind,
                    value=value,
                    valid=True,
                    source_paths=list(dict.fromkeys(source["paths"])),
                    provider=vt_provider,
                    retrieved_at=retrieved_at,
                    lookup_status=vt_status,
                    details=vt_details,
                    existing_case_context=list(dict.fromkeys(source["context"]))[:3],
                    comparison_with_case=EnrichmentComparison(
                        status="inconclusive",
                        explanation=(
                            "VirusTotal reputation is recorded separately and is not used to overwrite "
                            "or automatically resolve existing case conclusions."
                        ),
                    ),
                )
            )
    enrichment = CaseAnalyzerEnrichment(
        generated_at=retrieved_at,
        observations=observations,
        truncated=len(items) > limit,
    )
    case.case_analyzer_enrichment = enrichment
    return enrichment
