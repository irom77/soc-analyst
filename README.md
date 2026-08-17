# Standalone Case Analyzer

Soc Analyst is a standalone agentic security-case analyzer. It runs the Case Analysis LLM workflow without Django, PostgreSQL, or the Agentic SOC worker, normalizes exported security-case JSON to a platform-neutral representation, and returns a structured `InvestigationReport` JSON document.

For a detailed explanation of the package architecture and execution flow, see the [Case Analyzer code walkthrough](case-analyzer-code.md).

For common questions about evidence handling and generated conclusions, see the [Case Analyzer FAQ](FAQ.md).

For a complete nested-container example and recorded live LLM output, see the [Splunk SOAR case analysis result](examples/splunk-soar-analysis.md).

For contrasting cases that exercise evidence-oriented reasoning rather than keyword matching, see the [reasoning examples and recorded comparison](examples/reasoning/README.md).

## Run it

From this directory, create the isolated environment:

```bash
uv sync
```

Inspect normalization without sending data to an LLM:

```bash
uv run case-analyzer examples/generic-case.json --dry-run
```

For a case exported from another SOAR platform:

```bash
uv run case-analyzer examples/other-soar-case.json --format soar --dry-run
```

Invoke an OpenAI-compatible model:

```bash
export CASE_ANALYZER_MODEL="your-model"
export CASE_ANALYZER_API_KEY="your-key"
export CASE_ANALYZER_BASE_URL="https://provider.example/v1"

uv run case-analyzer examples/generic-case.json \
  --format generic \
  --output investigation-report.json
```

`CASE_ANALYZER_BASE_URL` is optional when using OpenAI. The equivalent `OPENAI_MODEL`, `OPENAI_API_KEY`, and `OPENAI_BASE_URL` variables are also accepted.

## Run the reasoning examples

After configuring the provider variables above, run the automated comparison from the repository root:

```bash
./test.sh
```

The script sends three synthetic nested SOAR cases to the configured LLM: alarming wording with benign evidence, reassuring wording with malicious evidence, and alarming wording with insufficient evidence. It prints a Markdown table comparing each actual verdict with an allowed expected set. A result outside its expected set is marked `REVIEW` and makes the script exit nonzero so that a person can inspect the model's reasoning.

By default, full structured reports are written to a temporary directory whose path is printed after the table. Pass a directory to retain them at a chosen location:

```bash
./test.sh ./reasoning-results
```

Each run makes three live LLM calls and may incur provider charges. See the [reasoning examples and recorded comparison](examples/reasoning/README.md) for the scenarios, expectations, limitations, and results from a recorded run.

## Input formats

- `generic`: requires `case_id` or `id`, plus `title` or `name`; common alert, artifact, comment, and timeline fields are retained.
- `soar`: maps common case, container, alert, detection, artifact, observable, action, and activity fields used by other SOAR platforms.
- `auto`: uses recognizable source fields and otherwise selects `generic`.

Every adapter retains the complete export under `case.source_data`, so the model can use evidence not covered by the initial mapping. SOAR export shapes vary between platforms; validate the dry-run output and refine the adapter against a sanitized export before operational use.

An optional knowledge file must be a JSON array:

```bash
uv run case-analyzer case.json --knowledge knowledge.json --dry-run
```

## Origin and license

Soc Analyst was extracted from the standalone case-analysis work developed in [FunnyWolf/agentic-soc-platform](https://github.com/FunnyWolf/agentic-soc-platform), the open-source Agentic SOC Platform. Project documentation is available at [asp.viperrtp.com](https://asp.viperrtp.com/).

This repository is distributed under the MIT License. See [LICENSE](LICENSE) for the copyright and permission notice retained from the Agentic SOC Platform project.

## Privacy and safety

The non-dry-run command sends the normalized case, original `source_data`, optional knowledge, and analyst input to the configured model provider. Remove secrets and unnecessary personal data, and use a provider approved for your security telemetry. The analyzer only writes the path passed to `--output`; it does not update the source platform.
