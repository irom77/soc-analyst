from typing import Any

from pydantic import BaseModel, ConfigDict, Field


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
