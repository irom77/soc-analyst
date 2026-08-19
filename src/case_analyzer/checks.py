"""Deterministic post-checks over a returned `InvestigationReport`.

Everything here is local and offline: no second LLM call, no network. The checks turn
two model self-reports into spot-checkable claims.

They verify *form*, never *support*. A citation that resolves proves the model named a
field that exists in the payload it was given; it does not prove the field says what the
finding claims. Treat a clean result as the absence of one specific failure, not as
evidence that a report is grounded.
"""

import re
from typing import Any

from .schemas import LIST_CAPS, InvestigationReport

# One path segment: a key, optionally followed by any number of `[n]` indices.
_SEGMENT = re.compile(r"^([^\[\]]+)((?:\[\d+\])*)$")
_INDEX = re.compile(r"\[(\d+)\]")


def resolve_case_path(case: dict[str, Any], path: str) -> bool:
    """Does `path` name something that exists in the rendered `case` object?

    The grammar is the one enrichment already emits: dotted object keys with `[n]` list
    indices, rooted at `case`. A trailing `#…` fragment is a marker rather than a
    traversable segment — `…destinationDnsDomain#host` records that a domain was derived
    from a URL in that field — so it is stripped before resolving.

    Resolving to `None` still counts as resolved: the path exists and the export left it
    empty, which is different from the path being wrong.
    """
    path = path.split("#", 1)[0].strip()
    if not path:
        return False
    if _resolve(case, path):
        return True
    # "Rooted at the payload's `case` object" invites writing that root out, and a live
    # run showed the model doing it for every citation. The canonical form is the
    # unprefixed one enrichment emits, so it is tried first and a real top-level key
    # named `case` still wins; this only rescues the redundant spelling.
    if path.startswith("case."):
        return _resolve(case, path[len("case.") :])
    return False


def _resolve(case: dict[str, Any], path: str) -> bool:
    current: Any = case
    for segment in path.split("."):
        matched = _SEGMENT.match(segment)
        if not matched:
            return False
        key, indices = matched.group(1), matched.group(2)
        if not isinstance(current, dict) or key not in current:
            return False
        current = current[key]
        for index in _INDEX.findall(indices):
            if not isinstance(current, list):
                return False
            position = int(index)
            if position >= len(current):
                return False
            current = current[position]
    return True


def unresolved_citations(report: InvestigationReport, case: dict[str, Any]) -> list[str]:
    """Cited paths that do not exist in the case the model was given.

    An uncited finding is not reported: absence means "uncited", which the schema
    permits, and conflating it with a bad citation would punish honesty.
    """
    problems = []
    for finding in report.evidence_findings:
        for path in finding.source_paths:
            if not resolve_case_path(case, path):
                problems.append(f"{finding.title!r} cites {path!r}, which does not resolve in the case")
    return problems


def inconsistent_truncation(report: InvestigationReport) -> list[str]:
    """Truncation claims contradicted by the report itself.

    A list below its cap had room for more, so claiming it was shortened is either a
    miscount or a list padded to look complete. Either way the claim is not usable as
    "go read the source for the rest", which is the whole point of the field.
    """
    problems = []
    for note in report.truncated_fields:
        cap = LIST_CAPS[note.field]
        actual = len(getattr(report, note.field))
        if actual < cap:
            problems.append(
                f"{note.field} is reported truncated but holds {actual} of a possible {cap}"
            )
    return problems


def check_report(report: InvestigationReport, case: dict[str, Any]) -> list[str]:
    """Every post-check finding, as lines suitable for stderr. Empty means nothing found."""
    return unresolved_citations(report, case) + inconsistent_truncation(report)
