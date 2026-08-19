import argparse
import sys
from pathlib import Path

from .cli import main as case_analyzer_main


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Deprecated alias for `case-analyzer --explain`. It forwards neither --output nor "
            "--enrich; use case-analyzer directly when either is needed."
        )
    )
    parser.add_argument("input", type=Path, help="Case export JSON file")
    parser.add_argument("--format", choices=("auto", "generic", "soar"), default="auto")
    parser.add_argument("--knowledge", type=Path, help="Optional JSON array of knowledge records")
    parser.add_argument("--user-input", default="", help="Additional analyst guidance")
    parser.add_argument("--model", help="Model name (or set CASE_ANALYZER_MODEL)")
    parser.add_argument(
        "--base-url",
        help="Provider endpoint, OpenAI-compatible unless the model carries a native prefix",
    )
    parser.add_argument("--api-key", help="Provider key (prefer CASE_ANALYZER_API_KEY)")
    parser.add_argument(
        "--invoke",
        action="store_true",
        help="Call the configured LLM. Without this flag, no LLM request is made.",
    )
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    print(
        "explain_case_analysis is deprecated; use case-analyzer --explain instead.",
        file=sys.stderr,
    )
    forwarded = [str(args.input), "--format", args.format, "--explain"]
    if not args.invoke:
        forwarded.append("--dry-run")
    for flag, value in (
        ("--knowledge", args.knowledge),
        ("--user-input", args.user_input),
        ("--model", args.model),
        ("--base-url", args.base_url),
        ("--api-key", args.api_key),
    ):
        if value:
            forwarded.extend((flag, str(value)))
    return case_analyzer_main(forwarded)


if __name__ == "__main__":
    raise SystemExit(main())
