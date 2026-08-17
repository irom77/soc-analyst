import argparse
import json
import sys
from pathlib import Path

from .adapters import normalize_case
from .analyzer import analyze_case, build_analysis_payload


def _json_file(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read JSON from {path}: {exc}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze an exported security case with an LLM.")
    parser.add_argument("input", type=Path, help="Case export JSON file")
    parser.add_argument("--format", choices=("auto", "generic", "soar"), default="auto")
    parser.add_argument("--output", type=Path, help="Write the InvestigationReport JSON to this file")
    parser.add_argument("--knowledge", type=Path, help="Optional JSON array of knowledge records")
    parser.add_argument("--user-input", default="", help="Additional analyst guidance")
    parser.add_argument("--model", help="Model name (or set CASE_ANALYZER_MODEL)")
    parser.add_argument("--base-url", help="OpenAI-compatible endpoint (or set CASE_ANALYZER_BASE_URL)")
    parser.add_argument("--api-key", help="Provider key (prefer CASE_ANALYZER_API_KEY)")
    parser.add_argument("--dry-run", action="store_true", help="Normalize and print input without calling an LLM")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        case = normalize_case(_json_file(args.input), args.format)
        knowledge = _json_file(args.knowledge) if args.knowledge else []
        if not isinstance(knowledge, list):
            raise ValueError("The knowledge file must contain a JSON array.")
        if args.dry_run:
            result = build_analysis_payload(case, knowledge_records=knowledge, user_input=args.user_input)
        else:
            result = analyze_case(
                case,
                knowledge_records=knowledge,
                user_input=args.user_input,
                model=args.model,
                base_url=args.base_url,
                api_key=args.api_key,
            ).model_dump()
        rendered = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        else:
            print(rendered)
        return 0
    except (OSError, ValueError) as exc:
        print(f"case-analyzer: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
