import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv

from .adapters import normalize_case
from .analyzer import (
    LLMProviderError,
    analyze_case,
    build_analysis_messages,
    build_analysis_payload,
    build_summary_messages,
    summarize_case,
)
from .enrichment import enrich_case
from .enrichment_cache import EnrichmentCache, ProviderPacer, default_cache_dir
from .provenance import sha256_file
from .schemas import RunChecks


def _json_file(path: Path, max_bytes: int = 0):
    if max_bytes:
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise ValueError(f"Could not read JSON from {path}: {exc}") from exc
        if size > max_bytes:
            raise ValueError(
                f"{path} is {size / 1_000_000:.1f} MB, above the {max_bytes / 1_000_000:.1f} MB "
                "input limit. Reduce the export or raise --max-input-bytes; note that the "
                "configured gateway may enforce a smaller limit of its own."
            )
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read JSON from {path}: {exc}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze an exported security case with an LLM.")
    parser.add_argument("input", type=Path, help="Case export JSON file")
    parser.add_argument("--format", choices=("auto", "generic", "soar"), default="auto")
    parser.add_argument(
        "--output", type=Path, help="Write the result JSON, including its run provenance, to this file"
    )
    parser.add_argument("--knowledge", type=Path, help="Optional JSON array of knowledge records")
    parser.add_argument("--user-input", default="", help="Additional analyst guidance")
    parser.add_argument("--model", help="Model name (or set CASE_ANALYZER_MODEL)")
    parser.add_argument(
        "--base-url",
        help="Provider endpoint, OpenAI-compatible unless the model carries a native "
        "prefix (or set CASE_ANALYZER_BASE_URL)",
    )
    parser.add_argument("--api-key", help="Provider key (prefer CASE_ANALYZER_API_KEY)")
    parser.add_argument("--dry-run", action="store_true", help="Normalize and print input without calling an LLM")
    parser.add_argument(
        "--summary",
        action="store_true",
        help=(
            "Ask the LLM to describe the input case in prose and stop. Prints a summary plus its "
            "run provenance instead of an InvestigationReport; no verdict, severity, or "
            "remediation is produced."
        ),
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Print normalization and the exact LLM messages before the result",
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Validate observables and query free keyless DNS/RDAP providers",
    )
    parser.add_argument(
        "--allow-enrichment-in-dry-run",
        action="store_true",
        help=(
            "Permit --enrich to contact providers while --dry-run is set. Without this flag the "
            "combination is refused, because a dry run otherwise sends no data anywhere."
        ),
    )
    parser.add_argument(
        "--enrichment-limit",
        type=int,
        default=25,
        help=(
            "Maximum unique observables to enrich. Configured reputation providers add separate "
            "observations, so a public IP can produce RDAP, VirusTotal, and AbuseIPDB results."
        ),
    )
    parser.add_argument("--enrichment-timeout", type=float, default=5.0, help="Timeout per provider request in seconds")
    parser.add_argument(
        "--enrichment-budget",
        type=float,
        default=60.0,
        help=(
            "Overall wall-clock budget in seconds for all enrichment lookups; it also caps each "
            "request's timeout, and observables left over are recorded as skipped. Use 0 for no "
            "budget (default 60)"
        ),
    )
    parser.add_argument(
        "--enrichment-concurrency",
        type=int,
        default=4,
        help="Number of enrichment lookups to run at once (default 4)",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help=(
            "Directory for cached enrichment responses and cross-process pacing state "
            f"(default {default_cache_dir()}). Cached observable values and provider answers are "
            "stored there in the clear; use --no-cache where that is not acceptable."
        ),
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help=(
            "Contact enrichment providers for every observable and store nothing. Rate-limit "
            "pacing still applies, because that is the provider's rule rather than a local "
            "optimization; only its cross-process half needs the cache directory."
        ),
    )
    parser.add_argument(
        "--enrichment-failure-threshold",
        type=int,
        default=3,
        help=(
            "Stop calling a provider after this many consecutive failed lookups; lookups already "
            "in flight still finish, so a run can exceed it by up to one full set of workers "
            "(default 3)"
        ),
    )
    parser.add_argument(
        "--llm-timeout",
        type=float,
        default=120.0,
        help="Timeout in seconds for the LLM request (default 120)",
    )
    parser.add_argument(
        "--max-input-bytes",
        type=int,
        default=5_000_000,
        help="Reject case and knowledge files larger than this. Use 0 for no limit (default 5000000)",
    )
    return parser


def _heading(text: str) -> None:
    print(f"\n=== {text} ===")


def _print_json(value) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def _explain(case, knowledge, knowledge_path, user_input, *, summary: bool = False) -> None:
    _heading("1. Normalize the exported Case")
    _print_json(case.model_dump(mode="json", exclude_none=True))

    _heading("2. Add supplied Knowledge context")
    if knowledge_path:
        print(f"Loaded {len(knowledge)} record(s) from {knowledge_path}.")
    else:
        print("No Knowledge file supplied; the standalone analyzer does not query a database.")
    _print_json(knowledge)

    _heading(f"3. Build the structured {'case-summary' if summary else 'investigation'} request")
    build_messages = build_summary_messages if summary else build_analysis_messages
    messages = build_messages(case, knowledge_records=knowledge, user_input=user_input)
    print("SystemMessage:")
    print(messages[0]["content"])
    print("\nHumanMessage (JSON payload, sent between untrusted-data markers):")
    _print_json(build_analysis_payload(case, knowledge_records=knowledge, user_input=user_input))


def _report_checks(checks: RunChecks) -> None:
    """Echo the post-check results on stderr; they are already in the saved result.

    `analyze_case` runs the checks and records them under `case_analyzer_run.checks`, so
    this only makes them visible to someone watching the terminal. Nothing is recomputed
    here, which keeps the warning and the saved record from being able to disagree.
    """
    problems = checks.problems
    if not checks.ran or not problems:
        return
    print(
        f"case-analyzer: report check: {len(problems)} problem(s) found. The report is still "
        "written; these are defects in how it describes itself, not provider errors.",
        file=sys.stderr,
    )
    for problem in problems:
        print(f"case-analyzer: report check: {problem}", file=sys.stderr)


def _report_enrichment(enrichment) -> None:
    counts = Counter(item.lookup_status for item in enrichment.observations)
    # Reported so a run that made no requests is distinguishable from one that did. Each
    # cached observation also carries `"cache": true` and its original retrieval time.
    cached = sum(1 for item in enrichment.observations if item.details.get("cache"))
    print(
        "case-analyzer: enrichment: "
        f"found={counts['found']} not_found={counts['not_found']} "
        f"skipped={counts['skipped']} error={counts['error']} "
        f"cached={cached} "
        f"truncated={'yes' if enrichment.truncated else 'no'} "
        f"stopped_early={'yes' if enrichment.stopped_early else 'no'}",
        file=sys.stderr,
    )
    if enrichment.stopped_early:
        print(
            "case-analyzer: enrichment warning: lookups stopped early; the time budget was "
            "exhausted or a provider failed repeatedly. Affected observables are recorded as "
            "skipped with a reason.",
            file=sys.stderr,
        )
    for item in enrichment.observations:
        if item.lookup_status != "error":
            continue
        status = item.details.get("http_status")
        reason = f"HTTP {status}" if status else item.details.get("error", "provider request failed")
        print(
            f"case-analyzer: enrichment warning: {item.provider} failed for "
            f"{item.observable_type} {item.value}: {reason}",
            file=sys.stderr,
        )


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        load_dotenv()
        case = normalize_case(_json_file(args.input, args.max_input_bytes), args.format)
        # Read and validate every input file before enrichment, so a malformed
        # knowledge file cannot waste provider calls and quota.
        knowledge = _json_file(args.knowledge, args.max_input_bytes) if args.knowledge else []
        if not isinstance(knowledge, list):
            raise ValueError("The knowledge file must contain a JSON array.")
        if args.enrich:
            if args.dry_run and not args.allow_enrichment_in_dry_run:
                raise ValueError(
                    "--enrich contacts external providers and discloses observable values to them, "
                    "which --dry-run otherwise avoids. Pass --allow-enrichment-in-dry-run to accept "
                    "that, or drop --enrich."
                )
            if args.dry_run:
                print(
                    "case-analyzer: --enrich sends observable values to Cloudflare DNS, the RDAP "
                    "registries, and, when keys are configured, VirusTotal, AbuseIPDB, and "
                    "URLhaus even with --dry-run; "
                    "only the LLM call is skipped.",
                    file=sys.stderr,
                )
            cache_dir = Path(args.cache_dir) if args.cache_dir else default_cache_dir()
            enrichment = enrich_case(
                case,
                cache=None if args.no_cache else EnrichmentCache(cache_dir),
                # The pacer runs either way. Without a cache directory it keeps its state
                # in this process only, which still prevents concurrent workers from
                # firing at a rate-limited provider together.
                pacer=ProviderPacer(state_dir=None if args.no_cache else cache_dir),
                limit=args.enrichment_limit,
                timeout=args.enrichment_timeout,
                budget=args.enrichment_budget or None,
                concurrency=args.enrichment_concurrency,
                failure_threshold=args.enrichment_failure_threshold,
                virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
                abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY"),
                abuse_ch_api_key=os.getenv("ABUSE_CH_AUTH_KEY"),
            )
            _report_enrichment(enrichment)
        wanted = "a case summary" if args.summary else "an InvestigationReport"
        if args.explain:
            _explain(case, knowledge, args.knowledge, args.user_input, summary=args.summary)
        if args.dry_run:
            result = build_analysis_payload(case, knowledge_records=knowledge, user_input=args.user_input)
            if args.explain:
                _heading("4. Stop without invoking the LLM")
                print(f"Preview complete. Remove --dry-run to request {wanted}.")
        else:
            if args.explain:
                _heading(f"4. Invoke the LLM for {wanted}")
            request = summarize_case if args.summary else analyze_case
            response = request(
                case,
                knowledge_records=knowledge,
                user_input=args.user_input,
                model=args.model,
                base_url=args.base_url,
                api_key=args.api_key,
                timeout=args.llm_timeout,
                # Hashed from the file as it sits on disk, before normalization, so a
                # saved report can be tied back to the export it came from.
                input_file_sha256=sha256_file(args.input),
            )
            _report_checks(response.case_analyzer_run.checks)
            # `mode="json"` renders the run timestamp; every other field is already
            # JSON-native.
            result = response.model_dump(mode="json")
        rendered = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output:
            args.output.write_text(rendered + "\n", encoding="utf-8")
            if args.explain:
                print(f"Wrote result JSON to {args.output}.")
        else:
            print(rendered)
        if args.explain and not args.dry_run:
            _heading("5. Stop without writing to a source platform")
            print("The standalone command does not update a Case, database, or worker job.")
        return 0
    except LLMProviderError as exc:
        print(f"case-analyzer: LLM error: {exc}", file=sys.stderr)
        return exc.exit_code
    except (OSError, ValueError) as exc:
        print(f"case-analyzer: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
