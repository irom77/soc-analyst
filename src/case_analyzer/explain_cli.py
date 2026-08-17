import argparse
import json
import sys
from pathlib import Path

from .adapters import normalize_case
from .analyzer import analyze_case, build_analysis_messages, build_analysis_payload
from .cli import _json_file


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preview, and optionally run, the standalone case-analysis workflow."
    )
    parser.add_argument("input", type=Path, help="Case export JSON file")
    parser.add_argument("--format", choices=("auto", "generic", "soar"), default="auto")
    parser.add_argument("--knowledge", type=Path, help="Optional JSON array of knowledge records")
    parser.add_argument("--user-input", default="", help="Additional analyst guidance")
    parser.add_argument("--model", help="Model name (or set CASE_ANALYZER_MODEL)")
    parser.add_argument("--base-url", help="OpenAI-compatible endpoint")
    parser.add_argument("--api-key", help="Provider key (prefer CASE_ANALYZER_API_KEY)")
    parser.add_argument(
        "--invoke",
        action="store_true",
        help="Call the configured LLM. Without this flag, no LLM request is made.",
    )
    return parser


def _heading(text: str) -> None:
    print(f"\n=== {text} ===")


def _json(value) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        case = normalize_case(_json_file(args.input), args.format)
        knowledge = _json_file(args.knowledge) if args.knowledge else []
        if not isinstance(knowledge, list):
            raise ValueError("The knowledge file must contain a JSON array.")

        _heading("1. Normalize the exported Case")
        _json(case.model_dump(exclude_none=True))

        _heading("2. Add supplied Knowledge context")
        if args.knowledge:
            print(f"Loaded {len(knowledge)} record(s) from {args.knowledge}.")
        else:
            print("No Knowledge file supplied; the standalone analyzer does not query a database.")
        _json(knowledge)

        _heading("3. Build the structured investigation request")
        messages = build_analysis_messages(
            case, knowledge_records=knowledge, user_input=args.user_input
        )
        print("SystemMessage:")
        print(messages[0].content)
        print("\nHumanMessage (JSON):")
        _json(build_analysis_payload(case, knowledge_records=knowledge, user_input=args.user_input))

        if not args.invoke:
            _heading("4. Stop without invoking the LLM")
            print("Preview complete. Re-run with --invoke to request an InvestigationReport.")
            return 0

        _heading("4. Invoke the LLM for an InvestigationReport")
        report = analyze_case(
            case,
            knowledge_records=knowledge,
            user_input=args.user_input,
            model=args.model,
            base_url=args.base_url,
            api_key=args.api_key,
        )
        _json(report.model_dump())

        _heading("5. Stop without writing to a source platform")
        print("The standalone command does not update a Case, database, or worker job.")
        return 0
    except (OSError, ValueError) as exc:
        print(f"explain_case_analysis: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
