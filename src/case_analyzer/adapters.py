from collections.abc import Mapping
from typing import Any

from .schemas import CanonicalCase


def _first(data: Mapping[str, Any], *names: str, default: Any = "") -> Any:
    for name in names:
        value = data.get(name)
        if value not in (None, ""):
            return value
    return default


def _list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def detect_format(data: Mapping[str, Any]) -> str:
    keys = {str(key).casefold() for key in data}
    source = str(_first(data, "source", "platform", "product", default="")).casefold()
    if "soar" in source or {"container_type", "container_status", "observables", "detections"} & keys:
        return "soar"
    return "generic"


def normalize_case(data: Mapping[str, Any], source_format: str = "auto") -> CanonicalCase:
    if not isinstance(data, Mapping):
        raise ValueError("The input JSON must contain an object at its top level.")
    selected = detect_format(data) if source_format == "auto" else source_format
    adapters = {"generic": _generic, "soar": _soar}
    try:
        return adapters[selected](data)
    except KeyError:
        raise ValueError(f"Unsupported input format: {selected}") from None


# Top-level source keys each adapter may consume, as the `_first(...)` alias groups below
# list them. Kept next to the adapters so the two cannot drift: a key added to an alias
# group must be added here, or the residue would resend a field that was already lifted.
CONSUMED_SOURCE_KEYS: dict[str, frozenset[str]] = {
    "generic": frozenset({
        "case_id", "id", "caseId", "title", "name", "case_name", "description", "summary",
        "severity", "priority", "status", "state", "created_at", "createdAt", "create_time",
        "updated_at", "updatedAt", "update_time", "tags", "alerts", "events", "artifacts",
        "observables", "indicators", "comments", "notes", "timeline", "source", "platform",
    }),
    "soar": frozenset({
        "case_id", "caseId", "container_id", "id", "title", "name", "case_name", "description",
        "data", "summary", "severity", "priority", "container_status", "status", "create_time",
        "start_time", "created_at", "update_time", "end_time", "updated_at", "tags", "label",
        "alerts", "events", "detections", "artifacts", "observables", "indicators", "entities",
        "comments", "notes", "timeline", "actions", "activities", "source", "platform", "product",
    }),
}


def source_data_residue(case: "CanonicalCase") -> dict[str, Any]:
    """`case.source_data` minus the top-level keys normalization already lifted.

    Only the *sent* payload is reduced; `case.source_data` itself stays whole, because
    enrichment walks it to find observables and roots every `source_paths` value at
    `source_data.`. Nested content is untouched: the SOAR adapter never descends into
    `child_containers`, so for many real exports that key is the only carrier of the
    artifacts and must survive.
    """
    consumed = CONSUMED_SOURCE_KEYS.get(_format_of(case), frozenset())
    return {key: value for key, value in case.source_data.items() if key not in consumed}


def _format_of(case: "CanonicalCase") -> str:
    return "generic" if case.source == "generic" else "soar"


def _generic(data: Mapping[str, Any]) -> CanonicalCase:
    case_id = str(_first(data, "case_id", "id", "caseId"))
    title = str(_first(data, "title", "name", "case_name"))
    if not case_id or not title:
        raise ValueError("Generic JSON requires a case_id (or id) and title (or name).")
    return CanonicalCase(
        case_id=case_id,
        title=title,
        description=str(_first(data, "description", "summary")),
        severity=str(_first(data, "severity", "priority")),
        status=str(_first(data, "status", "state")),
        created_at=str(_first(data, "created_at", "createdAt", "create_time")),
        updated_at=str(_first(data, "updated_at", "updatedAt", "update_time")),
        tags=[str(item) for item in _list(data.get("tags"))],
        alerts=_list(_first(data, "alerts", "events", default=[])),
        artifacts=_list(_first(data, "artifacts", "observables", "indicators", default=[])),
        comments=_list(_first(data, "comments", "notes", default=[])),
        timeline=_list(data.get("timeline")),
        source=str(_first(data, "source", "platform", default="generic")),
        source_data=dict(data),
    )


def _soar(data: Mapping[str, Any]) -> CanonicalCase:
    artifacts = _list(data.get("artifacts"))
    alerts = _list(_first(data, "alerts", "events", default=[]))
    if not alerts and artifacts:
        alerts = [{"title": "SOAR case artifacts", "artifacts": artifacts}]
    return CanonicalCase(
        case_id=str(_first(data, "case_id", "caseId", "container_id", "id")),
        title=str(_first(data, "title", "name", "case_name", default="Untitled SOAR case")),
        description=str(_first(data, "description", "data", "summary")),
        severity=str(_first(data, "severity", "priority")),
        status=str(_first(data, "container_status", "status")),
        created_at=str(_first(data, "create_time", "start_time", "created_at")),
        updated_at=str(_first(data, "update_time", "end_time", "updated_at")),
        tags=[str(item) for item in _list(_first(data, "tags", "label", default=[]))],
        alerts=alerts or _list(_first(data, "detections", default=[])),
        artifacts=artifacts or _list(_first(data, "observables", "indicators", "entities", default=[])),
        comments=_list(_first(data, "comments", "notes", default=[])),
        timeline=_list(_first(data, "timeline", "actions", "activities", default=[])),
        source=str(_first(data, "source", "platform", "product", default="soar")),
        source_data=dict(data),
    )
