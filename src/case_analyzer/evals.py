"""Answer-quality eval harness.

Runs the benchmark cases listed in an eval manifest through the analyzer and checks each
result against the expectations its manifest entry declares. A live run sends one LLM
request per case per sample and may incur provider charges; the harness never contacts
enrichment providers.

Two kinds of entry, chosen by `mode`:

* `analysis` (the default) runs `analyze_case` and checks the verdict against an allowed
  set, optionally the confidence, and optional field-scoped forbidden content.
* `audit` runs `audit_case` against a control set and checks each named control's status
  against an allowed set. This is the only way to measure the claims `--audit` rests on
  that no offline test can reach: whether the model holds the `fail` /
  `insufficient_evidence` line against a case whose own text asserts compliance, and
  whether it can be talked into recording an exception nobody approved.

The check logic (`load_manifest`, `check_report`, `run_benchmark`) accepts an injected
analyze callable so the offline test suite can exercise it without credentials.
"""

import argparse
import json
import sys
import tempfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .adapters import normalize_case
from .analyzer import LLMProviderError, analyze_case, audit_case
from .checks import control_coverage
from .controls import Control, parse_controls
from .schemas import CanonicalCase, CaseAuditReport

ANALYSIS_MODE = "analysis"
AUDIT_MODE = "audit"
_MODES = (ANALYSIS_MODE, AUDIT_MODE)

# The closed set `ControlStatus` allows. Checked at manifest load so a typo in an expected
# status fails before a live run rather than silently never matching.
_CONTROL_STATUSES = ("pass", "fail", "not_applicable", "insufficient_evidence")


@dataclass
class ForbiddenContent:
    """A string the report must not contain, scoped to top-level report fields.

    An empty `fields` list scopes the check to the whole report. A scoped check is
    usually right: a model that *describes* an injected instruction in its findings is
    behaving well, while one that reproduces the payload in the targeted field is not.
    """

    value: str
    fields: list[str] = field(default_factory=list)


@dataclass
class EvalCase:
    case_id: str
    scenario: str
    path: Path
    source_format: str = "soar"
    mode: str = ANALYSIS_MODE
    allowed_verdicts: list[str] = field(default_factory=list)
    allowed_confidence: list[str] = field(default_factory=list)
    forbidden_content: list[ForbiddenContent] = field(default_factory=list)
    user_input: str = ""
    tags: list[str] = field(default_factory=list)
    # Audit entries only. Both the raw records and the parsed controls are kept: the
    # records are what `audit_case` sends, the controls are what it scores against, and
    # it refuses the pair unless they name the same set.
    control_records: list[dict] = field(default_factory=list)
    controls: list[Control] = field(default_factory=list)
    expected_statuses: dict[str, list[str]] = field(default_factory=dict)

    @property
    def expectation(self) -> str:
        """What this entry requires, for the table and the `--list` output."""
        if self.mode == AUDIT_MODE:
            return "; ".join(
                f"{control_id}={'/'.join(statuses)}"
                for control_id, statuses in self.expected_statuses.items()
            )
        return ", ".join(self.allowed_verdicts)


@dataclass
class CaseResult:
    entry: EvalCase
    # One entry per sample: the verdict for an analysis case, the per-control status
    # vector for an audit case. Kept in one field because agreement across samples means
    # the same thing for both -- did the model give the same answer twice.
    outcomes: list[str] = field(default_factory=list)
    confidences: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def status(self) -> str:
        if self.error:
            return "ERROR"
        return "REVIEW" if self.failures else "PASS"

    @property
    def agreement(self) -> float:
        """Fraction of samples that produced the modal outcome."""
        if not self.outcomes:
            return 0.0
        top = Counter(value.casefold() for value in self.outcomes).most_common(1)[0][1]
        return top / len(self.outcomes)


def load_manifest(path: Path) -> list[EvalCase]:
    try:
        items = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read the eval manifest {path}: {exc}") from exc
    if not isinstance(items, list):
        raise ValueError(f"{path} must contain a JSON array of eval cases.")
    base = path.resolve().parent
    entries: list[EvalCase] = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError(f"Every manifest entry must be an object: {item!r}")
        case_id = str(item.get("id", "")) or f"<entry without an id: {item!r}>"
        mode = str(item.get("mode", ANALYSIS_MODE))
        if mode not in _MODES:
            raise ValueError(f"Eval case {case_id}: mode must be one of {', '.join(_MODES)}, not {mode!r}")
        try:
            case_path = (base / item["file"]).resolve()
        except (TypeError, KeyError) as exc:
            raise ValueError(f"Every manifest entry needs id and file: {item!r}") from exc
        if not case_path.is_file():
            raise ValueError(f"Eval case {case_id}: file not found: {case_path}")
        allowed_verdicts: list[str] = []
        control_records: list[dict] = []
        controls: list[Control] = []
        expected_statuses: dict[str, list[str]] = {}
        if mode == AUDIT_MODE:
            control_records, controls = _load_controls(base, item, case_id)
            expected_statuses = _load_expected_statuses(item, controls, case_id)
        else:
            try:
                allowed_verdicts = [str(value) for value in item["allowed_verdicts"]]
            except (TypeError, KeyError) as exc:
                raise ValueError(f"Eval case {case_id}: an analysis entry needs allowed_verdicts") from exc
        user_input = ""
        if item.get("user_input_file"):
            user_input_path = (base / item["user_input_file"]).resolve()
            if not user_input_path.is_file():
                raise ValueError(f"Eval case {case_id}: user-input file not found: {user_input_path}")
            user_input = user_input_path.read_text(encoding="utf-8")
        forbidden = [
            ForbiddenContent(value=str(entry["value"]), fields=[str(name) for name in entry.get("fields", [])])
            for entry in item.get("forbidden_content", [])
        ]
        entries.append(
            EvalCase(
                case_id=case_id,
                scenario=str(item.get("scenario", case_id)),
                path=case_path,
                source_format=str(item.get("format", "soar")),
                mode=mode,
                allowed_verdicts=allowed_verdicts,
                allowed_confidence=[str(value) for value in item.get("allowed_confidence", [])],
                forbidden_content=forbidden,
                user_input=user_input,
                tags=[str(tag) for tag in item.get("tags", [])],
                control_records=control_records,
                controls=controls,
                expected_statuses=expected_statuses,
            )
        )
    case_ids = [entry.case_id for entry in entries]
    if len(set(case_ids)) != len(case_ids):
        raise ValueError(f"{path} contains duplicate case ids.")
    return entries


def _load_controls(base: Path, item: dict, case_id: str) -> tuple[list[dict], list[Control]]:
    """The control set an audit entry is run against, validated the way a real one is.

    Deliberately `parse_controls`, not a looser manifest-local reader: a benchmark control
    set that the CLI would refuse is not measuring the thing operators will run.
    """
    if not item.get("controls_file"):
        raise ValueError(f"Eval case {case_id}: an audit entry needs controls_file")
    controls_path = (base / item["controls_file"]).resolve()
    if not controls_path.is_file():
        raise ValueError(f"Eval case {case_id}: controls file not found: {controls_path}")
    try:
        records = json.loads(controls_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Eval case {case_id}: could not read {controls_path}: {exc}") from exc
    if not isinstance(records, list):
        raise ValueError(f"Eval case {case_id}: {controls_path} must contain a JSON array of controls.")
    try:
        controls = parse_controls(records)
    except ValueError as exc:
        raise ValueError(f"Eval case {case_id}: {exc}") from exc
    ids = [control.control_id for control in controls]
    if len(set(ids)) != len(ids):
        # `expected_statuses` is keyed by bare control_id, so the benchmark needs the
        # stronger uniqueness the tool itself does not require: the tool's identity is
        # `(policy_ref, control_id)`, which lets two policies both number a control 4.2.
        raise ValueError(
            f"Eval case {case_id}: {controls_path} reuses a control_id across policies; "
            "benchmark control sets must have globally unique control_id values because "
            "expected_statuses is keyed by control_id alone."
        )
    return records, controls


def _load_expected_statuses(item: dict, controls: list[Control], case_id: str) -> dict[str, list[str]]:
    """The per-control statuses this case is asserting, checked against the control set."""
    raw = item.get("expected_statuses")
    if not isinstance(raw, dict) or not raw:
        raise ValueError(f"Eval case {case_id}: an audit entry needs a non-empty expected_statuses object")
    known = {control.control_id for control in controls}
    expected: dict[str, list[str]] = {}
    for control_id, statuses in raw.items():
        if control_id not in known:
            raise ValueError(
                f"Eval case {case_id}: expected_statuses names {control_id!r}, which is not in the control set"
            )
        if isinstance(statuses, str) or not isinstance(statuses, list) or not statuses:
            raise ValueError(
                f"Eval case {case_id}: expected_statuses[{control_id!r}] must be a non-empty list of statuses"
            )
        unknown = sorted({str(value) for value in statuses} - set(_CONTROL_STATUSES))
        if unknown:
            raise ValueError(
                f"Eval case {case_id}: expected_statuses[{control_id!r}] names unknown status(es) "
                f"{', '.join(unknown)}; allowed: {', '.join(_CONTROL_STATUSES)}"
            )
        expected[str(control_id)] = [str(value) for value in statuses]
    return expected


def check_report(entry: EvalCase, report: dict) -> list[str]:
    """Return the list of failed checks for one report; an empty list means PASS."""
    failures = _check_audit(entry, report) if entry.mode == AUDIT_MODE else _check_analysis(entry, report)
    return failures + _check_forbidden(entry, report)


def _check_analysis(entry: EvalCase, report: dict) -> list[str]:
    failures: list[str] = []
    verdict = str(report.get("verdict", ""))
    if entry.allowed_verdicts and verdict.casefold() not in {value.casefold() for value in entry.allowed_verdicts}:
        failures.append(f"verdict {verdict!r} outside the allowed set {entry.allowed_verdicts}")
    confidence = str(report.get("confidence", ""))
    if entry.allowed_confidence and confidence.casefold() not in {
        value.casefold() for value in entry.allowed_confidence
    }:
        failures.append(f"confidence {confidence!r} outside the allowed set {entry.allowed_confidence}")
    return failures


def _check_audit(entry: EvalCase, report: dict) -> list[str]:
    """Per-control status, plus coverage of the whole supplied set.

    Coverage is scored here rather than merely recorded, unlike the other local checks: a
    response that skipped a control is not a wrong answer about that control, it is the
    absence of an answer, and a benchmark that let it pass would be measuring nothing.
    """
    statuses = _status_map(report)
    failures = [
        (
            f"control {control_id} answered {statuses[control_id]!r}, outside the allowed set {allowed}"
            if control_id in statuses
            else f"control {control_id} received no assessment"
        )
        for control_id, allowed in entry.expected_statuses.items()
        if statuses.get(control_id) not in allowed
    ]
    try:
        coverage = control_coverage(CaseAuditReport.model_validate(report), entry.controls)
    except ValidationError as exc:
        return failures + [f"the response is not a CaseAuditReport: {exc.errors()[0]['msg']}"]
    return failures + [f"coverage: {problem}" for problem in coverage]


def _check_forbidden(entry: EvalCase, report: dict) -> list[str]:
    failures: list[str] = []
    for item in entry.forbidden_content:
        scope: Any = {name: report.get(name) for name in item.fields} if item.fields else report
        if item.value.casefold() in json.dumps(scope, ensure_ascii=False).casefold():
            where = ", ".join(item.fields) if item.fields else "the report"
            failures.append(f"forbidden content {item.value!r} appeared in {where}")
    return failures


def _status_map(report: dict) -> dict[str, str]:
    """Assessed status by bare `control_id`, for the one duplicate-free set a benchmark uses."""
    return {
        str(assessment.get("control_id", "")).strip(): str(assessment.get("status", ""))
        for assessment in report.get("assessments", [])
        if isinstance(assessment, dict)
    }


def _outcome(entry: EvalCase, report: dict) -> str:
    """One sample's answer, as the string agreement across samples is measured over."""
    if entry.mode != AUDIT_MODE:
        return str(report.get("verdict", ""))
    statuses = _status_map(report)
    return " ".join(f"{control_id}={statuses.get(control_id, '—')}" for control_id in entry.expected_statuses)


def run_benchmark(
    entries: list[EvalCase],
    analyze_fn: Callable[[EvalCase, CanonicalCase], Any],
    *,
    samples: int = 1,
    on_report: Callable[[EvalCase, int, dict], None] | None = None,
) -> list[CaseResult]:
    """Run every entry `samples` times through `analyze_fn` and collect check results.

    `analyze_fn` receives the manifest entry and the normalized case and must return the
    report that entry's `mode` calls for — in practice the provenanced `AnalyzedReport` or
    `AnalyzedAudit` subclass, so each saved result records the model and payload hash it
    came from, and the local post-check result under `case_analyzer_run.checks`. Those
    checks are recorded, not scored: benchmark pass/fail stays the manifest's rules. The
    one exception is audit coverage, which `_check_audit` scores, because a control that
    was never assessed is a hole in the answer rather than a defect in describing it. A
    provider or configuration error stops that entry's remaining samples but not the rest
    of the benchmark.
    """
    results: list[CaseResult] = []
    for entry in entries:
        result = CaseResult(entry=entry)
        results.append(result)
        try:
            data = json.loads(entry.path.read_text(encoding="utf-8"))
            case = normalize_case(data, entry.source_format)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            result.error = f"could not load the case: {exc}"
            continue
        for index in range(samples):
            try:
                report = analyze_fn(entry, case)
            except (LLMProviderError, ValueError) as exc:
                result.error = str(exc)
                break
            report_dict = report.model_dump(mode="json")
            result.outcomes.append(_outcome(entry, report_dict))
            if entry.mode != AUDIT_MODE:
                result.confidences.append(str(report_dict.get("confidence", "")))
            prefix = f"sample {index + 1}: " if samples > 1 else ""
            result.failures.extend(prefix + failure for failure in check_report(entry, report_dict))
            if on_report is not None:
                on_report(entry, index, report_dict)
    return results


def _tally(values: list[str]) -> str:
    counts = Counter(values)
    return ", ".join(value if count == 1 else f"{value} ×{count}" for value, count in counts.items()) or "—"


def render_table(results: list[CaseResult], samples: int) -> str:
    """One table for both modes: `Expected`/`Answer` hold verdicts or status vectors."""
    lines = [
        "| Case | Mode | Expected | Answer(s) | Confidence | Agreement | Checks | Result |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for result in results:
        agreement = f"{round(100 * result.agreement)}%" if samples > 1 and result.outcomes else "—"
        if result.error:
            checks = "—"
        else:
            checks = "ok" if not result.failures else f"{len(result.failures)} failed"
        lines.append(
            f"| {result.entry.case_id} | {result.entry.mode} | {result.entry.expectation or '—'} | "
            f"{_tally(result.outcomes)} | {_tally(result.confidences)} | {agreement} | "
            f"{checks} | {result.status} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the answer-quality eval benchmark against the configured LLM. Analysis cases are "
            "checked on their verdict, audit cases on each control's status and on coverage of the "
            "control set. Each case costs one live LLM request per sample; enrichment providers are "
            "never contacted."
        )
    )
    parser.add_argument(
        "results_dir",
        nargs="?",
        type=Path,
        help="Directory to keep the structured report files (default: a new temporary directory)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("evals/manifest.json"),
        help="Eval manifest to run (default: evals/manifest.json, so run from the repository root)",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=1,
        help="LLM runs per case; above 1, verdict agreement across samples is reported (default 1)",
    )
    parser.add_argument("--only", action="append", default=[], metavar="ID", help="Run only the named case ids")
    parser.add_argument("--tag", action="append", default=[], metavar="TAG", help="Run only cases with a given tag")
    parser.add_argument("--list", action="store_true", help="List the manifest cases and exit without calling an LLM")
    parser.add_argument("--model", help="Model name (or set CASE_ANALYZER_MODEL)")
    parser.add_argument("--llm-timeout", type=float, default=120.0, help="Timeout per LLM request (default 120)")
    args = parser.parse_args(argv)

    if args.samples < 1:
        print("case-analyzer-evals: --samples must be at least 1.", file=sys.stderr)
        return 2
    try:
        entries = load_manifest(args.manifest)
    except ValueError as exc:
        print(f"case-analyzer-evals: {exc}", file=sys.stderr)
        return 2
    if args.only:
        known = {entry.case_id for entry in entries}
        missing = sorted(set(args.only) - known)
        if missing:
            print(f"case-analyzer-evals: unknown case id(s): {', '.join(missing)}", file=sys.stderr)
            return 2
        entries = [entry for entry in entries if entry.case_id in set(args.only)]
    if args.tag:
        entries = [entry for entry in entries if set(args.tag) & set(entry.tags)]
        if not entries:
            print(f"case-analyzer-evals: no case carries the tag(s): {', '.join(args.tag)}", file=sys.stderr)
            return 2

    if args.list:
        print("| Case | Mode | Scenario | Format | Expected | Tags |")
        print("|---|---|---|---|---|---|")
        for entry in entries:
            print(
                f"| {entry.case_id} | {entry.mode} | {entry.scenario} | {entry.source_format} | "
                f"{entry.expectation or '—'} | {', '.join(entry.tags) or '—'} |"
            )
        return 0

    results_dir = args.results_dir or Path(tempfile.mkdtemp(prefix="case-analyzer-evals-"))
    results_dir.mkdir(parents=True, exist_ok=True)
    total = len(entries) * args.samples
    print(
        f"case-analyzer-evals: sending {total} live LLM request(s); report files go to {results_dir}",
        file=sys.stderr,
    )

    def analyze(entry: EvalCase, case: CanonicalCase):
        if entry.mode == AUDIT_MODE:
            return audit_case(
                case,
                entry.controls,
                knowledge_records=entry.control_records,
                user_input=entry.user_input,
                model=args.model,
                timeout=args.llm_timeout,
            )
        return analyze_case(case, user_input=entry.user_input, model=args.model, timeout=args.llm_timeout)

    def save(entry: EvalCase, index: int, report_dict: dict) -> None:
        suffix = f"-{index + 1}" if args.samples > 1 else ""
        target = results_dir / f"{entry.case_id}{suffix}-result.json"
        target.write_text(json.dumps(report_dict, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    results = run_benchmark(entries, analyze, samples=args.samples, on_report=save)
    print(render_table(results, args.samples))
    details = [
        f"- {result.entry.case_id}: {line}"
        for result in results
        for line in ([f"ERROR: {result.error}"] if result.error else result.failures)
    ]
    if details:
        print()
        print("\n".join(details))
    print(f"\nStructured result files: `{results_dir}`")
    reviewable = sum(result.status != "PASS" for result in results)
    if reviewable:
        print(
            f"\n{reviewable} case(s) need review; REVIEW calls for human inspection and is not automatically a "
            "model failure."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
