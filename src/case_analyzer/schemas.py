from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_serializer


def _isoformat_z(value: datetime) -> str:
    """Serialize as UTC with a `Z` suffix, the form SOAR exports normally use."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class EnrichmentComparison(BaseModel):
    status: Literal["consistent", "conflicting", "inconclusive", "not_comparable"]
    explanation: str


class EnrichmentObservation(BaseModel):
    # `url` and `email` are the values as the case wrote them, minimally normalized. They
    # coexist with the `domain`/`ip` observable derived from the same field, whose source
    # path carries a `#host` or `#domain` suffix — different providers answer for a whole
    # URL than for its host, so both are recorded rather than one standing in for the other.
    observable_type: Literal["domain", "ip", "file_hash", "url", "email"]
    value: str
    valid: bool
    # The non-ASCII spellings the case used for this observable, which `value` is the
    # punycode form of. Empty when the case wrote it in ASCII. Recorded because the
    # punycode form alone does not say which characters produced it, and a domain can
    # reach the same encoding from more than one spelling.
    #
    # This is provenance, not a verdict: two visually identical spellings still look
    # identical here, so a reader comparing `unicode_values` against a legitimate domain
    # by eye can be fooled exactly as the original victim was. The `xn--` prefix in
    # `value` is the reliable signal that a name was not plain ASCII.
    unicode_values: list[str] = Field(default_factory=list)
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
    # Which adapter built this case, recorded by `normalize_case`. Private so that it stays
    # out of `model_dump` and therefore out of the payload sent to the model -- it is an
    # internal fact about parsing, not evidence. `source` cannot answer this: it holds
    # whatever the export called its own product, so a generic case can say "splunk".
    _source_format: str = PrivateAttr(default="")


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


# The decision vocabulary, closed. These two fields are what makes runs comparable and
# downstream automation safe, so they are a contract rather than a prompt suggestion: an
# off-list value fails schema validation like any other malformed response. The values
# are the ones every recorded run and every eval case already used; the enum writes down
# existing behavior instead of imposing new behavior.
Verdict = Literal["True Positive", "Suspicious", "False Positive", "Benign", "Insufficient Data"]
Confidence = Literal["Low", "Medium", "High"]


class InvestigationReport(BaseModel):
    verdict: Verdict
    # `severity`, `impact`, and `priority` stay free strings deliberately. They restate
    # the source platform's own vocabulary, which varies — the recorded exports carry
    # `critical`, `informational`, and lowercase spellings — so a closed set here would
    # constrain someone else's data model rather than this tool's decisions.
    severity: str
    impact: str
    priority: str
    confidence: Confidence
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


# Bumped when the saved-result shape changes in a way a consumer must notice. Recorded
# in every run block so an archived report identifies its own layout.
REPORT_SCHEMA_VERSION = "1"


class RunChecks(BaseModel):
    """Outcome of the local post-checks in `checks.py`.

    `ran` and `problems` are separate because an empty problem list is ambiguous on its
    own: a summary run has no report to check, and a clean report also produces nothing.
    Only the pair distinguishes "checked and clean" from "not checked".
    """

    ran: bool = False
    problems: list[str] = Field(default_factory=list)


class CaseAnalyzerRun(BaseModel):
    """What produced a saved result: which model, which exact input, which code.

    Generated locally and never by the model. It is deliberately absent from
    `InvestigationReport` and `CaseSummary`, which are the schemas handed to the
    provider as `response_format`; putting it there would invite the model to fill in
    its own provenance. `AnalyzedReport` and `AnalyzedSummary` below add it afterwards.
    """

    generated_at: datetime
    package_version: str
    report_schema_version: str = REPORT_SCHEMA_VERSION
    model: str
    # Host (with port when non-default) of the configured endpoint. Never the full URL:
    # a base URL can carry credentials in its userinfo, and a path or query can carry a
    # deployment token.
    endpoint_host: str = ""
    # The exact bytes the provider was asked to reason over. The rendered payload covers
    # the normalized case plus any enrichment, knowledge, and analyst guidance, which is
    # why the input file's own hash cannot stand in for it.
    system_prompt_sha256: str
    payload_sha256: str
    # Empty when the caller supplied an already-parsed case rather than a file.
    input_file_sha256: str = ""
    # Convenience flags for reading a result at a glance. The payload hash, not these,
    # is what identifies the input.
    has_enrichment: bool = False
    has_knowledge: bool = False
    has_user_input: bool = False
    checks: RunChecks = Field(default_factory=RunChecks)

    @field_serializer("generated_at")
    def _serialize_generated_at(self, value: datetime) -> str:
        return _isoformat_z(value)


class AnalyzedReport(InvestigationReport):
    """The saved result: everything the model returned, plus how it was produced.

    A subclass rather than a wrapper envelope, so the saved shape stays additive —
    a consumer reading `verdict` keeps working, and reports recorded before this
    field existed remain valid input to the same readers.
    """

    case_analyzer_run: CaseAnalyzerRun


class AnalyzedSummary(CaseSummary):
    """The saved result of a `--summary` run, provenanced the same way."""

    case_analyzer_run: CaseAnalyzerRun
