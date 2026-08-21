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


def _tag_text(value: Any) -> str:
    """One tag as text.

    Exports write tags as plain strings, but also as `{"key": ..., "value": ...}` pairs.
    `str()` on the mapping would put a Python repr into the payload, so the pair is joined
    instead. Inert for every recorded case here, all of which tag with strings.
    """
    if isinstance(value, Mapping):
        key = _first(value, "key", "name", "label", "tag")
        text = _first(value, "value", "text")
        if key and text:
            return f"{key}: {text}"
        return str(key or text or value)
    return str(value)


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
        adapter = adapters[selected]
    except KeyError:
        raise ValueError(f"Unsupported input format: {selected}") from None
    case = adapter(data)
    # Recorded here because this is the only place that knows which adapter ran. Deriving
    # it later from `case.source` would be wrong: a generic export that names its product
    # (`"source": "splunk"`) would be read back as SOAR, and the residue would then drop
    # keys the generic adapter never lifted.
    case._source_format = selected
    return case


# Top-level source keys each adapter may consume, as the `_first(...)` alias groups below
# list them. Kept next to the adapters so the two cannot drift: a key added to an alias
# group must be added here, or the residue would resend a field that was already lifted.
CONSUMED_SOURCE_KEYS: dict[str, frozenset[str]] = {
    "generic": frozenset({
        "case_id", "id", "caseId", "title", "name", "case_name", "description", "summary",
        "severity", "priority", "status", "state", "created_at", "createdAt", "create_time",
        "updated_at", "updatedAt", "update_time", "tags", "alerts", "events", "artifacts",
        "observables", "indicators", "entities", "comments", "notes", "timeline", "source",
        "platform",
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
    `source_data.`. Nested content is untouched with one exception: when the adapter read
    the case out of an envelope, the same rule is applied again at the record it read from.
    That record's lifted keys are otherwise invisible to a top-level filter, which is why
    the residue recovered 1% of `examples/unknown.json` and 25.7% of everything else.

    The exception is deliberately narrow. It trims the one record the adapter is known to
    have consumed, key by key, rather than dropping the whole subtree -- an envelope holds
    fields no adapter lifts, and a second view of the same record is not the same thing as
    a duplicate of what was sent. The SOAR adapter still never descends into
    `child_containers`, which for many real exports is the only carrier of the artifacts.
    """
    consumed = CONSUMED_SOURCE_KEYS.get(_format_of(case), frozenset())
    residue = {key: value for key, value in case.source_data.items() if key not in consumed}
    return _trim_unwrapped(residue, case._unwrapped_path, consumed)


def _trim_unwrapped(
    residue: dict[str, Any], path: tuple[str, ...], consumed: frozenset[str]
) -> dict[str, Any]:
    """Drop the consumed keys from the record at `path`, copying the containers on the way.

    Copying matters: `residue` still holds the caller's own nested objects, and rewriting
    one in place would edit `case.source_data`, which the whole reduction depends on
    leaving alone.
    """
    if not path:
        return residue
    head, *rest = path
    inner = residue.get(head)
    if not isinstance(inner, Mapping):
        return residue
    trimmed = (
        _trim_unwrapped(dict(inner), tuple(rest), consumed)
        if rest
        else {key: value for key, value in inner.items() if key not in consumed}
    )
    return {**residue, head: trimmed}


def _format_of(case: "CanonicalCase") -> str:
    """The adapter that built `case`, falling back to detection for a hand-built case.

    Never `case.source`: that field carries whatever the export called itself, so a case
    the generic adapter normalized can hold `"splunk"` there. Reducing such a case against
    the SOAR key set would delete `product` and `data`, which generic never lifted.
    """
    if case._source_format in CONSUMED_SOURCE_KEYS:
        return case._source_format
    return detect_format(case.source_data)


# The content alias groups `_generic` reads, one per canonical field it can fill. Used to
# score a candidate record when the top level turns out to be an envelope. Kept next to the
# adapter for the same reason as CONSUMED_SOURCE_KEYS: an alias added below must be added
# here, or an envelope carrying only that field would score zero and never be found. A test
# asserts every name here is also in CONSUMED_SOURCE_KEYS["generic"].
_GENERIC_CONTENT_ALIASES: tuple[tuple[str, ...], ...] = (
    ("description", "summary"),
    ("severity", "priority"),
    ("status", "state"),
    ("created_at", "createdAt", "create_time"),
    ("updated_at", "updatedAt", "update_time"),
    ("tags",),
    ("alerts", "events"),
    ("artifacts", "observables", "indicators", "entities"),
    ("comments", "notes"),
    ("timeline",),
)

# How deep to look for the wrapped record, and how many content fields it must supply.
# Depth 2 reaches `raw.content`, the deepest envelope seen so far; bounding it keeps the
# search out of artifact bodies, where a nested mapping can easily carry a `description`
# and a `status` of its own without being the case. Three fields is the same guard from the
# other side -- one or two hits is what an artifact body would score.
_UNWRAP_MAX_DEPTH = 2
_UNWRAP_MIN_FIELDS = 3


def _content_score(record: Mapping[str, Any]) -> int:
    return sum(1 for group in _GENERIC_CONTENT_ALIASES if _first(record, *group))


def _unwrap_generic(data: Mapping[str, Any]) -> tuple[Mapping[str, Any] | None, tuple[str, ...]]:
    """The nested record to normalize from when the top level carries only identity.

    Some exports wrap the case rather than being it. `examples/unknown.json` is
    `{id, name, type, parsed, raw}`, where `parsed` is the platform's own normalized view
    and `raw.content` the original record; nothing but `id` and `name` sits at the top
    level. Without this, the generic adapter filled two of thirteen fields and everything
    the case actually says -- description, severity, status, timestamps, tags, entities --
    stayed buried in `source_data` for the model to find unaided.

    Consulted **only** when the top-level record produced a case with no content at all, so
    no export that normalizes today can change shape. Returns the record and the path it
    was found at, or `(None, ())` when nothing scores well enough to be worth preferring
    over the top level.
    """
    best: tuple[Mapping[str, Any] | None, tuple[str, ...], int] = (None, (), _UNWRAP_MIN_FIELDS - 1)
    frontier: list[tuple[Mapping[str, Any], tuple[str, ...]]] = [(data, ())]
    for _ in range(_UNWRAP_MAX_DEPTH):
        nxt: list[tuple[Mapping[str, Any], tuple[str, ...]]] = []
        for record, path in frontier:
            for key, value in record.items():
                if not isinstance(value, Mapping):
                    continue
                here = (*path, str(key))
                nxt.append((value, here))
                score = _content_score(value)
                # Strictly greater, so the shallowest of equally good candidates wins.
                if score > best[2]:
                    best = (value, here, score)
        frontier = nxt
    return best[0], best[1]


def _generic(data: Mapping[str, Any]) -> CanonicalCase:
    if _content_score(data):
        return _generic_record(data, data)
    inner, path = _unwrap_generic(data)
    if inner is None:
        return _generic_record(data, data)
    case = _generic_record(inner, data)
    case._unwrapped_path = path
    return case


def _generic_record(record: Mapping[str, Any], data: Mapping[str, Any]) -> CanonicalCase:
    """Build a generic case from `record`, keeping `data` as the identity and the source.

    `record` is `data` itself unless an envelope was unwrapped. Identity falls back to the
    outer record because a wrapper usually keeps it -- `unknown.json`'s inner view has a
    title but no id -- and `source_data` is always the whole outer object, so enrichment
    still walks what the file actually contained and `source_paths` still resolve.
    """
    case_id = str(_first(record, "case_id", "id", "caseId") or _first(data, "case_id", "id", "caseId"))
    title = str(_first(record, "title", "name", "case_name") or _first(data, "title", "name", "case_name"))
    if not case_id or not title:
        raise ValueError("Generic JSON requires a case_id (or id) and title (or name).")
    return CanonicalCase(
        case_id=case_id,
        title=title,
        description=str(_first(record, "description", "summary")),
        severity=str(_first(record, "severity", "priority")),
        status=str(_first(record, "status", "state")),
        created_at=str(_first(record, "created_at", "createdAt", "create_time")),
        updated_at=str(_first(record, "updated_at", "updatedAt", "update_time")),
        tags=[_tag_text(item) for item in _list(record.get("tags"))],
        alerts=_list(_first(record, "alerts", "events", default=[])),
        artifacts=_list(_first(record, "artifacts", "observables", "indicators", "entities", default=[])),
        comments=_list(_first(record, "comments", "notes", default=[])),
        timeline=_list(record.get("timeline")),
        source=str(_first(record, "source", "platform") or _first(data, "source", "platform", default="generic")),
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
