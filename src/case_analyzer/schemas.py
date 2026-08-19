from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer


def _isoformat_z(value: datetime) -> str:
    """Serialize as UTC with a `Z` suffix, the form SOAR exports normally use."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class EnrichmentComparison(BaseModel):
    status: Literal["consistent", "conflicting", "inconclusive", "not_comparable"]
    explanation: str


class EnrichmentObservation(BaseModel):
    observable_type: Literal["domain", "ip", "file_hash"]
    value: str
    valid: bool
    source_paths: list[str] = Field(default_factory=list)
    provider: str
    retrieved_at: datetime
    lookup_status: Literal["found", "not_found", "skipped", "error"]
    details: dict[str, Any] = Field(default_factory=dict)
    # Notes and comments recorded on the artifact or container that held the
    # value. They describe the surrounding case object, not necessarily this
    # observable.
    artifact_context: list[str] = Field(default_factory=list)
    comparison_with_case: EnrichmentComparison

    @field_serializer("retrieved_at")
    def _serialize_retrieved_at(self, value: datetime) -> str:
        return _isoformat_z(value)


class CaseAnalyzerEnrichment(BaseModel):
    generated_at: datetime
    observations: list[EnrichmentObservation] = Field(default_factory=list)
    # The run reached `--enrichment-limit` and did not look up every observable.
    truncated: bool = False
    # A time budget or repeated provider failures stopped lookups early. The
    # affected observables are still listed, with `lookup_status: "skipped"`.
    stopped_early: bool = False

    @field_serializer("generated_at")
    def _serialize_generated_at(self, value: datetime) -> str:
        return _isoformat_z(value)


class CanonicalCase(BaseModel):
    """Platform-neutral input understood by the analysis engine."""

    model_config = ConfigDict(extra="allow")
    case_id: str
    title: str
    description: str = ""
    severity: str = ""
    status: str = ""
    created_at: str = ""
    updated_at: str = ""
    tags: list[str] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    comments: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    source: str = "generic"
    source_data: dict[str, Any] = Field(default_factory=dict)
    case_analyzer_enrichment: CaseAnalyzerEnrichment | None = None


class CaseSummary(BaseModel):
    """Narrative digest of the input case, returned instead of an InvestigationReport."""

    summary: str


class AffectedAsset(BaseModel):
    asset_type: str
    asset_value: str


class EvidenceFinding(BaseModel):
    title: str
    finding_type: str
    subject: str
    evidence: str
    conclusion: str
    source_paths: list[str] = Field(
        default_factory=list,
        description=(
            "Case JSON paths this finding relied on, rooted at the payload's `case` object: "
            "dotted keys with `[n]` list indices, e.g. "
            "`source_data.artifacts[0].cef.destinationDnsDomain`. Cite the field the evidence "
            "was read from, not a paraphrase. Omit rather than guess; an empty list means "
            "uncited, which is permitted."
        ),
    )


class AttackChainStep(BaseModel):
    attack_stage: str
    description: str


class TimelineEvent(BaseModel):
    timestamp: str
    attack_behavior: str
    evidence_field: str


class IndicatorOfCompromise(BaseModel):
    indicator_type: str
    value: str
    context: str


class Remediation(BaseModel):
    action_type: str
    description: str
    priority: str


# The list caps stated in `prompts/investigation.md`. Kept here so the truncation
# post-check can tell a genuine cap from a model that shortened a list for its own
# reasons. `tests/test_checks.py` asserts the prompt and this table agree.
LIST_CAPS: dict[str, int] = {
    "affected_assets": 5,
    "evidence_findings": 5,
    "attack_chain": 6,
    "attack_timeline": 8,
    "ioc_indicators": 10,
    "remediations": 6,
    "unknowns": 5,
}

TruncatedListName = Literal[
    "affected_assets",
    "evidence_findings",
    "attack_chain",
    "attack_timeline",
    "ioc_indicators",
    "remediations",
    "unknowns",
]


class TruncationNote(BaseModel):
    """One list the model shortened to fit its cap.

    Reported per list rather than as a single boolean so a reader knows *which* list to
    go back to the source for. This is the model's own account of what it left out: it
    cannot be verified from the response alone, only checked for self-consistency.
    """

    field: TruncatedListName
    # Deliberately `int` rather than `int | None`: an optional int renders as
    # `anyOf: [integer, null]`, which strict structured-output modes handle unevenly.
    # A note only exists when a list was truncated, so 0 reads unambiguously as
    # "truncated, count not estimated".
    omitted_count: int = Field(
        default=0,
        ge=0,
        description=(
            "Approximate number of items left out. Use 0 if you cannot estimate it rather "
            "than guessing a number."
        ),
    )


class InvestigationReport(BaseModel):
    verdict: str
    severity: str
    impact: str
    priority: str
    confidence: str
    digest: str
    affected_assets: list[AffectedAsset] = Field(default_factory=list)
    evidence_findings: list[EvidenceFinding] = Field(default_factory=list)
    attack_chain: list[AttackChainStep] = Field(default_factory=list)
    attack_timeline: list[TimelineEvent] = Field(default_factory=list)
    ioc_indicators: list[IndicatorOfCompromise] = Field(default_factory=list)
    remediations: list[Remediation] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    truncated_fields: list[TruncationNote] = Field(
        default_factory=list,
        description=(
            "Lists that hit their maximum size, one entry each. Report a list here only when "
            "material content was left out, never to note that a list is merely short."
        ),
    )
