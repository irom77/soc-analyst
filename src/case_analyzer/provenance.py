"""Locally generated run provenance.

Everything here is computed in this process from what the run actually did. None of it
is asked of the model, and none of it is trusted from the response. Attaching it is the
last step of `analyze_case`/`summarize_case`, so the guarantee is on the public call
rather than on an optional helper a caller can forget.
"""

import hashlib
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .schemas import CaseAnalyzerRun, RunChecks

_DISTRIBUTION = "asp-case-analyzer"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    """Hash the file as it sits on disk, before parsing or normalization."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _package_version() -> str:
    try:
        return version(_DISTRIBUTION)
    except PackageNotFoundError:
        # Running from a source tree that was never installed. Recording the gap is
        # better than recording a guess, since the point of the field is identifying
        # which code produced a report.
        return "unknown"


def endpoint_host(base_url: str | None) -> str:
    """Host and port of a base URL, with anything secret dropped.

    `urlsplit().hostname` is used rather than `netloc` deliberately: a base URL may
    carry credentials as userinfo (`https://user:key@host/v1`), and `netloc` would
    record them. Path and query are dropped for the same reason — deployment tokens
    live there on some gateways.
    """
    if not base_url:
        return ""
    # A bare `host:port` has no scheme, so urlsplit would read the host as the scheme.
    split = urlsplit(base_url if "//" in base_url else f"//{base_url}")
    if not split.hostname:
        return ""
    return f"{split.hostname}:{split.port}" if split.port else split.hostname


def build_run_metadata(
    *,
    payload: dict[str, Any],
    messages: list[dict[str, str]],
    model: str,
    base_url: str | None,
    input_file_sha256: str = "",
    checks: RunChecks | None = None,
) -> CaseAnalyzerRun:
    """Describe one completed request. `messages` must be the ones actually sent."""
    case = payload.get("case") or {}
    return CaseAnalyzerRun(
        generated_at=datetime.now(UTC),
        package_version=_package_version(),
        model=model,
        endpoint_host=endpoint_host(base_url),
        system_prompt_sha256=sha256_text(messages[0]["content"]),
        payload_sha256=sha256_text(messages[1]["content"]),
        input_file_sha256=input_file_sha256,
        has_enrichment=bool(case.get("case_analyzer_enrichment")),
        has_knowledge=bool((payload.get("knowledge") or {}).get("records")),
        has_user_input=bool(payload.get("user_input")),
        checks=checks or RunChecks(),
    )
