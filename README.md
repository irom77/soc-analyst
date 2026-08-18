# Standalone Case Analyzer

Soc Analyst is a standalone agentic security-case analyzer. It runs the Case Analysis LLM workflow without Django, PostgreSQL, or the Agentic SOC worker, normalizes exported security-case JSON to a platform-neutral representation, and returns a structured `InvestigationReport` JSON document.

For a detailed explanation of the package architecture and execution flow, see the [Case Analyzer code walkthrough](case-analyzer-code.md).

For common questions about evidence handling and generated conclusions, see the [Case Analyzer FAQ](FAQ.md).

For a complete nested-container example and recorded live LLM output, see the [Splunk SOAR case analysis result](examples/splunk-soar-analysis.md). The [Splunk SOAR case summary result](examples/splunk-soar-summary.md) records what `--summary` returns for the same export, with each claim traced back to the evidence it came from. The [full explanation transcript](examples/splunk-soar-explain-case-analysis.txt) records the earlier compatibility command's walkthrough for the same export.

For contrasting cases that exercise evidence-oriented reasoning rather than keyword matching, see the [reasoning examples and recorded comparison](examples/reasoning/README.md).

For examples that use case-specific `--user-input` to perform evidence-quality,
closure-readiness, and response-process reviews, see the
[case-audit guidance examples](examples/user-input-case-audit/README.md).

## Run it

From this directory, create the isolated environment:

```bash
uv sync
```

Inspect normalization without sending data to an LLM:

```bash
uv run case-analyzer examples/generic-case.json --dry-run
```

Validate and enrich observables before analysis:

```bash
uv run case-analyzer examples/splunk-soar.json \
  --format soar \
  --enrich \
  --dry-run \
  --allow-enrichment-in-dry-run
```

`--enrich` performs local syntax validation, queries Cloudflare's keyless DNS-over-HTTPS
resolver for domains, and queries the RDAP registry that holds a public IP address for
its registration data. When `VIRUSTOTAL_API_KEY` is set, it also queries VirusTotal for
domain, public-IP, and file-hash reputation. When `ABUSEIPDB_API_KEY` is set, it queries
AbuseIPDB for public-IP reputation over the preceding 30 days. Keep keys in the ignored
`.env` file; providers without a configured key are simply skipped. Enrichment still contacts providers when it is
combined with `--dry-run`, which otherwise sends no data anywhere, so that combination
requires `--allow-enrichment-in-dry-run` and prints a notice to standard error before
the first request.

Bound the work with `--enrichment-limit` (default `25` unique observables),
`--enrichment-timeout` (default `5` seconds per request), `--enrichment-budget` (default
`60` seconds of wall time for all lookups; `0` disables it),
`--enrichment-concurrency` (default `4` lookups at once), and
`--enrichment-failure-threshold` (default `3` consecutive failures before a provider is
dropped for the rest of the run). Observables that are not looked up because the budget
ran out or a provider was dropped are still listed, with `lookup_status: "skipped"` and
a reason, and the run reports `stopped_early: true`. The budget also caps the timeout of
each request it starts, so a lookup cannot outlive it; a request the budget cuts short is
recorded as `skipped` rather than counted against the provider. The failure threshold
counts lookups that have already failed, and requests in flight are not cancelled, so a
failing provider can receive up to one further set of concurrent lookups. The limit counts unique
observables; configured reputation providers add separately attributed observations, so
a public IP can produce RDAP, VirusTotal, and AbuseIPDB observations. When the limit truncates a run, observables
that a provider can actually answer for are kept first, then values whose type the case
declared, then values seen in more places; invalid values are dropped first.

Observables are read from `cef` blocks, from `cef_types` declarations when the ingesting
app provided them, and from recognizable field names elsewhere in the export.
`observable_type` is `domain`, `ip`, or `file_hash`. URLs and email addresses are
recognized and contribute their host or domain part, whose source path is marked with a
`#host` or `#domain` suffix; the URL and the address themselves are not looked up,
because no configured provider covers them.

The generated data is kept separately under
`case.case_analyzer_enrichment.observations`; imported artifacts, notes, comments, and
other `source_data` are never overwritten. Each observation records its provider,
retrieval time, source paths, lookup status, `artifact_context`, and
`comparison_with_case`. DNS and RDAP metadata is marked `not_comparable` with existing
reputation claims because resolution or registration data cannot establish whether an
observable is malicious. In particular, `not_found`, a provider error, no DNS answers,
or a lookup that was never performed must not be interpreted as benign; those results
are `inconclusive`. Invalid syntax is `conflicting` only when the case itself declared
the value's type through `cef_types`; when the type was inferred from a field name, a
syntax failure is reported as `not_comparable` because it reflects the extractor rather
than a contradiction in the case.

`artifact_context` quotes notes and comments that already contain enrichment or
reputation claims, taken from the artifact or container that held the value. It
describes that surrounding object rather than the specific observable, and the system
prompt tells the model to read it that way.

IP lookups resolve the responsible registry through the IANA RDAP bootstrap
(`data.iana.org/rdap`), which is fetched once and then cached in the process for an hour,
so a long-lived caller refreshes it instead of pinning one copy. If the bootstrap is
unavailable, the lookup falls back to `rdap.arin.net` and relies on its redirects.
`details.rdap_source` records which of the two was used, and `details.rdap_authority`
records the host that actually answered. Cold lookups for the same address family share
one fetch rather than each making their own. The bootstrap fetch and the registry query
share a single lookup timeout, and the query is not started at all if the fetch has
already used it up.

Cloudflare DNS and RDAP do not require API keys, while VirusTotal and AbuseIPDB do.
AbuseIPDB's Standard tier currently permits 1,000 `check` requests per day; consult its
current API documentation and terms for other tiers and usage restrictions. All are
external services with availability, privacy, and rate-limit considerations. Observable values are disclosed
to the selected service. The provider calls are best-effort: a lookup failure is
recorded on its observation and does not abort the case analysis. Every enriched run
prints lookup counts to standard error, plus a warning for each failed provider
request. JSON output remains on standard output or in the file selected by `--output`.
See [`examples/enrichment/`](examples/enrichment/) for a recorded enriched payload and
the command used to regenerate it.

LLM failures stop the analysis without writing a report. Authentication failures,
rate or quota limits, timeouts, connection failures, provider HTTP errors, and model
responses that do not match the requested schema are reported as concise
`case-analyzer: LLM error:` messages without printing credentials, request payloads, or
raw model output. A missing model or API key is reported before any request is sent.
Automatic LLM retries are disabled to avoid unplanned cost and additional rate-limit
pressure; `--llm-timeout` (default `120` seconds) bounds a single request. Exit codes
are `2` for input/configuration errors, `3` for authentication, `4` for rate/quota
limits, `5` for timeout/connection failures, and `6` for other provider errors.

### Summarize the input case

Add `--summary` to have the model describe what the case contains and stop, instead of
investigating it:

```bash
uv run case-analyzer examples/splunk-soar.json --format soar --summary
```

The run prints `{"summary": "..."}` rather than an `InvestigationReport`, and no verdict,
severity, attack chain, IOC list, or remediation is produced. The system prompt asks for
one to three paragraphs covering what was reported and by which source, when it started
and last changed, the assets and observables involved, and what analysts already recorded
in comments or the timeline; the model is told to describe the evidence rather than draw
conclusions from it.

`--summary` composes with the other flags. It sends the same case payload as an analysis
run, so it costs one LLM request and honours `--knowledge`, `--user-input`, `--model`,
`--llm-timeout`, and `--output`. Running it after `--enrich` includes the enrichment
block, which the prompt requires be attributed to its provider. Combined with `--dry-run`
no request is sent; add `--explain` to that combination to see the summary system prompt:

```bash
uv run case-analyzer examples/splunk-soar.json --format soar --summary --dry-run --explain
```

See [`examples/splunk-soar-summary.md`](examples/splunk-soar-summary.md) for a recorded
live run against the nested Splunk SOAR export, including a table tracing every claim in
the generated summary back to the field, note, or comment it came from.

Add `--explain` to print normalization plus the exact system and human messages before
the result:

```bash
uv run case-analyzer examples/generic-case.json --explain
```

Combine it with `--dry-run` to stop before the LLM call:

```bash
uv run case-analyzer examples/generic-case.json --explain --dry-run
```

For a complete captured live run, see the [`splunk-soar.json` walkthrough transcript](examples/splunk-soar-explain-case-analysis.txt).

Unlike the original Django command, the standalone command cannot look up a Case or
search Knowledge in PostgreSQL. Pass an optional JSON array with `--knowledge` when
that context is available. The `explain_case_analysis` and `explain-case-analysis`
commands remain as deprecated compatibility aliases; their old `--invoke` behavior is
translated to `case-analyzer --explain`.

### System message, human message, and analyst input

Every live analysis sends two messages to the model:

- `SystemMessage` contains the permanent investigation instructions loaded from
  [`src/case_analyzer/prompts/investigation.md`](src/case_analyzer/prompts/investigation.md).
  Edit that file to change the analyzer's general SOC role, evidence rules, verdict
  guidance, or response limits.
- `HumanMessage` is generated by the program for each run. It opens with a short
  preamble stating that the payload is untrusted data rather than instructions, then
  carries the JSON payload — the normalized `case`, optional `knowledge.records`, and
  optional `user_input` — between `=== BEGIN CASE PAYLOAD JSON ===` and
  `=== END CASE PAYLOAD JSON ===` markers. The wrapper hardens the request against
  instructions embedded in exported case text; see the recorded before-and-after
  measurements in [`evals/baseline-2026-08-18.md`](evals/baseline-2026-08-18.md).
  “Human” is the LLM API role name; it does not mean the JSON was typed by a person.
- `--user-input` adds case-specific analyst guidance inside the `HumanMessage`. It
  supplements the system instructions and case evidence; it does not replace them.

For example:

```bash
uv run case-analyzer examples/splunk-soar.json \
  --explain \
  --user-input "Focus on lateral movement and identify missing evidence"
```

Preview the exact messages without contacting the provider by adding `--dry-run`.
See [Message construction and analyst guidance](case-analyzer-code.md#message-construction-and-analyst-guidance)
for the payload structure and relevant source functions.

For a case exported from another SOAR platform:

```bash
uv run case-analyzer examples/other-soar-case.json --format soar --dry-run
```

Invoke an OpenAI-compatible model:

```bash
cp .env.example .env
# Edit .env with your provider settings.

uv run case-analyzer examples/generic-case.json \
  --format generic \
  --output investigation-report.json
```

The CLI automatically loads `.env` from the working directory. `.env` is ignored by Git and must not be committed. Existing environment variables and command-line options take precedence. `CASE_ANALYZER_BASE_URL` is optional when using OpenAI. The equivalent `OPENAI_MODEL`, `OPENAI_API_KEY`, and `OPENAI_BASE_URL` variables are also accepted.

### Model and gateway limits

The analyzer uses `ChatOpenAI` to send requests in the OpenAI API format. The
configured `CASE_ANALYZER_BASE_URL` identifies the service that receives the request;
it might be a model provider's compatibility endpoint, a third-party router, or an
internal gateway. A request can therefore follow this path:

```text
case-analyzer -> OpenAI-compatible gateway -> selected model
```

The selected model's advertised context window is only an upper bound. An
intermediary gateway can enforce a smaller input or output token limit, HTTP request
size limit, rate or token quota, timeout, or structured-output restriction. For
example, a model might accept 1,048,576 input tokens while its configured gateway
accepts only 128,000 tokens or limits request bodies to 5 MB.

The practical limit is whichever applicable limit is reached first: the model limit,
the gateway or proxy limit, the provider account tier, or a limit configured by the
analyzer. The analyzer imposes no token limit and never truncates oversized input
automatically, but `--max-input-bytes` (default `5000000`, `0` disables it) rejects
oversized case and knowledge files locally instead of letting the gateway reject the
request after the data has been sent. That byte limit is not a token limit: consult the
documentation for both the selected model and the service named by
`CASE_ANALYZER_BASE_URL` when sizing case, knowledge, and enrichment payloads.

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

## Run the eval benchmark

A broader verdict-quality benchmark extends the three reasoning cases with the
unsupported ip-verdict audit case and two prompt-injection cases whose checks are
field-scoped (an injected canary phrase must not reach the digest, and an
attacker-supplied domain must not reach the IOC list or remediations). List the cases
without contacting anything with `uv run case-analyzer-evals --list`; a live run costs
one LLM request per case per sample. See [`evals/README.md`](evals/README.md) for the
manifest format, `--samples` verdict-agreement measurement, and interpretation notes.

## Develop and test

The suite is offline: provider callables and the LLM client are stubbed, so no request
is sent and no credentials are needed.

```bash
uv sync
uv run python -m unittest discover -s tests -t .
uv run ruff check src tests
```

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

Soc Analyst was extracted from [irom77/agentic-soc](https://github.com/irom77/agentic-soc), a fork of the open-source [FunnyWolf/agentic-soc-platform](https://github.com/FunnyWolf/agentic-soc-platform) project. Agentic SOC Platform documentation is available at [asp.viperrtp.com](https://asp.viperrtp.com/).

This repository is distributed under the MIT License. See [LICENSE](LICENSE) for the copyright and permission notice retained from the Agentic SOC Platform project.

## Privacy and safety

The non-dry-run command sends the normalized case, original `source_data`, optional enrichment, knowledge, and analyst input to the configured model provider. `--enrich` also sends extracted domains to Cloudflare DNS, public IPs to the RDAP registries, and, when keys are configured, domains, public IPs, and file hashes to VirusTotal and public IPs to AbuseIPDB. It does so even when combined with `--dry-run`, which is why that combination must be confirmed with `--allow-enrichment-in-dry-run` and prints a notice to standard error before the first request. Remove secrets and unnecessary personal data, and use providers approved for your security telemetry. The analyzer only writes the path passed to `--output`; it does not update the source platform.
