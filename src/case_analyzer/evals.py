"""Verdict-quality eval harness.

Runs the benchmark cases listed in an eval manifest through the analyzer and checks
each result against its allowed verdict set, an optional allowed confidence set, and
optional field-scoped forbidden content. A live run sends one LLM request per case per
sample and may incur provider charges; the harness never contacts enrichment providers.

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

from .adapters import normalize_case
from .analyzer import LLMProviderError, analyze_case
from .schemas import CanonicalCase


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
    allowed_verdicts: list[str] = field(default_factory=list)
    allowed_confidence: list[str] = field(default_factory=list)
    forbidden_content: list[ForbiddenContent] = field(default_factory=list)
    user_input: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class CaseResult:
    entry: EvalCase
    verdicts: list[str] = field(default_factory=list)
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
        """Fraction of samples that produced the modal verdict."""
        if not self.verdicts:
            return 0.0
        top = Counter(value.casefold() for value in self.verdicts).most_common(1)[0][1]
        return top / len(self.verdicts)


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
        try:
            case_id = str(item["id"])
            case_path = (base / item["file"]).resolve()
            allowed_verdicts = [str(value) for value in item["allowed_verdicts"]]
        except (TypeError, KeyError) as exc:
            raise ValueError(f"Every manifest entry needs id, file, and allowed_verdicts: {item!r}") from exc
        if not case_path.is_file():
            raise ValueError(f"Eval case {case_id}: file not found: {case_path}")
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
                allowed_verdicts=allowed_verdicts,
                allowed_confidence=[str(value) for value in item.get("allowed_confidence", [])],
                forbidden_content=forbidden,
                user_input=user_input,
                tags=[str(tag) for tag in item.get("tags", [])],
            )
        )
    case_ids = [entry.case_id for entry in entries]
    if len(set(case_ids)) != len(case_ids):
        raise ValueError(f"{path} contains duplicate case ids.")
    return entries


def check_report(entry: EvalCase, report: dict) -> list[str]:
    """Return the list of failed checks for one report; an empty list means PASS."""
    failures: list[str] = []
    verdict = str(report.get("verdict", ""))
    if entry.allowed_verdicts and verdict.casefold() not in {value.casefold() for value in entry.allowed_verdicts}:
        failures.append(f"verdict {verdict!r} outside the allowed set {entry.allowed_verdicts}")
    confidence = str(report.get("confidence", ""))
    if entry.allowed_confidence and confidence.casefold() not in {
        value.casefold() for value in entry.allowed_confidence
    }:
        failures.append(f"confidence {confidence!r} outside the allowed set {entry.allowed_confidence}")
    for item in entry.forbidden_content:
        scope: Any = {name: report.get(name) for name in item.fields} if item.fields else report
        if item.value.casefold() in json.dumps(scope, ensure_ascii=False).casefold():
            where = ", ".join(item.fields) if item.fields else "the report"
            failures.append(f"forbidden content {item.value!r} appeared in {where}")
    return failures


def run_benchmark(
    entries: list[EvalCase],
    analyze_fn: Callable[[EvalCase, CanonicalCase], Any],
    *,
    samples: int = 1,
    on_report: Callable[[EvalCase, int, dict], None] | None = None,
) -> list[CaseResult]:
    """Run every entry `samples` times through `analyze_fn` and collect check results.

    `analyze_fn` receives the manifest entry and the normalized case and must return an
    `InvestigationReport` — in practice the provenanced `AnalyzedReport` subclass, so
    each saved result records the model and payload hash it came from, and the local
    post-check result under `case_analyzer_run.checks`. Those checks are recorded, not
    scored: benchmark pass/fail stays the manifest's verdict, confidence, and
    forbidden-content rules. A provider or configuration error stops that entry's
    remaining samples but not the rest of the benchmark.
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
            result.verdicts.append(str(report_dict.get("verdict", "")))
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
    lines = [
        "| Case | Expected verdict(s) | Verdict(s) | Confidence | Agreement | Checks | Result |",
        "|---|---|---|---|---|---|---|",
    ]
    for result in results:
        expected = ", ".join(result.entry.allowed_verdicts) or "—"
        agreement = f"{round(100 * result.agreement)}%" if samples > 1 and result.verdicts else "—"
        if result.error:
            checks = "—"
        else:
            checks = "ok" if not result.failures else f"{len(result.failures)} failed"
        lines.append(
            f"| {result.entry.case_id} | {expected} | {_tally(result.verdicts)} | "
            f"{_tally(result.confidences)} | {agreement} | {checks} | {result.status} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the verdict-quality eval benchmark against the configured LLM. "
            "Each case costs one live LLM request per sample; enrichment providers are never contacted."
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
        print("| Case | Scenario | Format | Expected verdict(s) | Tags |")
        print("|---|---|---|---|---|")
        for entry in entries:
            print(
                f"| {entry.case_id} | {entry.scenario} | {entry.source_format} | "
                f"{', '.join(entry.allowed_verdicts)} | {', '.join(entry.tags) or '—'} |"
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
