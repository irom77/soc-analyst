#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
manifest="$script_dir/examples/reasoning/expectations.json"
results_dir="${1:-$(mktemp -d)}"
mkdir -p "$results_dir"

mapfile -t cases < <(uv run --project "$script_dir" python - "$manifest" <<'PY'
import json
import sys

for item in json.load(open(sys.argv[1], encoding="utf-8")):
    print(item["file"])
PY
)

for case_file in "${cases[@]}"; do
    uv run --project "$script_dir" case-analyzer \
        "$script_dir/examples/reasoning/$case_file" \
        --format soar \
        --output "$results_dir/${case_file%.json}-result.json"
done

uv run --project "$script_dir" python - "$manifest" "$results_dir" <<'PY'
import json
import pathlib
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
results_dir = pathlib.Path(sys.argv[2])
print("| Scenario | Expected verdict(s) | Actual verdict | Confidence | Comparison |")
print("|---|---|---|---|---|")
failures = 0
for item in manifest:
    result_path = results_dir / item["file"].replace(".json", "-result.json")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    expected = item["expected_verdicts"]
    passed = result["verdict"].casefold() in {value.casefold() for value in expected}
    failures += not passed
    print(
        f'| {item["scenario"]} | {", ".join(expected)} | '
        f'{result["verdict"]} | {result["confidence"]} | {"PASS" if passed else "REVIEW"} |'
    )
print(f"\nStructured result files: `{results_dir}`")
if failures:
    print(f"\n{failures} result(s) fell outside the expected sets; review the evidence and model reasoning.")
    raise SystemExit(1)
PY
