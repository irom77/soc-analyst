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
