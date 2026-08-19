"""Standalone security case analysis."""

from .analyzer import analyze_case, build_analysis_messages
from .schemas import AnalyzedReport, InvestigationReport

__all__ = [
    # What `analyze_case` returns: the model's report plus a locally generated
    # `case_analyzer_run` block. `InvestigationReport` is its model-facing base, exported
    # for callers that type against the model's own output.
    "AnalyzedReport",
    "InvestigationReport",
    "analyze_case",
    "build_analysis_messages",
]
