# TODO

Findings prefixed `H-`, `M-`, or `L-` refer to [`code-review-2026-08-17.md`](code-review-2026-08-17.md),
which records the symptom, location, offline verification, and recommended direction for each.
Every review finding was implemented on 2026-08-17, in two passes: the correctness,
testing, and cleanup items first, then the behavior, extraction, and cleanup items that
needed a UX decision. See "Completed" below. What remains is here: the three original
items that predate the review, plus follow-ups the fixes opened up.

Two follow-up reviews on 2026-08-18 found six further gaps, all addressed in
"Completed (2026-08-18 follow-up)" below.

Planned improvement work beyond this list is tracked in
[`improvement-plan-2026-08-18.md`](improvement-plan-2026-08-18.md), a tiered roadmap
from the 2026-08-18 limitations review. Its eval-harness prerequisite and
prompt-injection item are done (see "Completed" below); the remaining tiers —
report provenance and enum verdicts, evidence citations, enrichment caching, and the
dedicated audit mode — are open there and not duplicated here.

Check the current state with `uv run python -m unittest discover -s tests -t .` and
`uv run ruff check src tests` (89 offline tests; no credentials or network needed).

## Existing

- [ ] Add a dedicated formal compliance-audit mode instead of relying on `user_input`
  to reshape an `InvestigationReport`. Give it a separate system prompt and structured
  response schema with named control identifiers, `pass`/`fail`/`not_applicable`/
  `insufficient_evidence` status, evidence citations back to case fields, policy and
  framework versions, documented exceptions, remediation owners and due dates, and
  human approval/audit-trail metadata. Accept applicable policies and control
  definitions as versioned `--knowledge` records, distinguish "not documented" from
  "did not occur," validate control coverage deterministically, and require human
  review before the result can close a case or change a compliance record. Add offline
  schema and prompt tests plus representative recorded examples before enabling any
  provider-backed automation.
- [ ] Address payload quality, duplicated `source_data`, provider cost and rate limits, and excessive noisy enrichment. Measured duplication is 1.52x on `examples/splunk-soar.json` (M-7); VirusTotal has no throttle against its ~4 request/minute public tier (L-5). L-5 is not theoretical: two live runs of the single-observable enrichment example minutes apart returned `HTTP 429` on the second, so a 25-observable run on the public tier will mostly record quota errors. Caching plus a request interval would fix both runs.
- [ ] Evaluate additional free enrichment providers in this order: ThreatFox for domain/IP IOC matches, GreyNoise Community for internet-scanner context, and URLhaus after complete URL extraction is supported. Keep provider results separately attributed, cache responses, respect enrichment limits, and treat `not_found` as inconclusive. Document and enforce each provider's API quota, fair-use terms, and commercial-use restrictions before enabling it in operational workflows.
- [x] Add optional AbuseIPDB public-IP reputation through the v2 `check` endpoint. It uses a 30-day report window, runs only when `ABUSEIPDB_API_KEY` is configured, and keeps the result separately attributed. The Standard tier currently permits 1,000 `check` requests per day; higher account tiers have higher limits. Operators remain responsible for confirming that their account and use comply with the provider's current terms.
- [x] Add `--summary`, which asks the model to describe the input case in prose and stops, printing `{"summary": ...}` instead of an `InvestigationReport`. It reuses the analysis payload under a separate `prompts/summary.md` system prompt that forbids a verdict, severity, attack chain, or remediation, and returns the `CaseSummary` schema. `analyze_case` and `summarize_case` now share one provider call and its sanitized error mapping. With `--dry-run` no request is sent; `--explain` shows the summary prompt.
- [ ] Remove the deprecated `explain_case_analysis` and `explain-case-analysis` aliases in the next breaking release; use `case-analyzer --explain` instead. The `--help` text already states that the alias forwards neither `--output` nor `--enrich` (L-9).

## Extraction coverage

- [ ] Look up the URL and the email address themselves once a provider covers them; today only their host or domain part is enriched, and `#host`/`#domain` marks the derived source path. URLhaus is the candidate for URLs (see the provider item above).

## Completed (2026-08-19 LiteLLM proxy)

- [x] Confirm the analyzer can drive a provider with no OpenAI-compatible endpoint
  without changing application code, by routing through a LiteLLM proxy. Verified
  against Google's native `generateContent` API (previously the project reached
  `gemini-2.5-flash` only through the `/v1beta/openai` compatibility shim):
  `with_structured_output(InvestigationReport)` validated, 89 tests and `ruff` clean,
  and the sanitized provider errors kept their exit codes across the extra hop
  (unknown model `6`, unreachable endpoint `5`). Config lives in
  `litellm-config.yaml`; the run is recorded in `examples/litellm-proxy/`, and
  `.env.example` carries the three commented `CASE_ANALYZER_*` values.
  The install needs two load-bearing pins — `--python 3.12` (litellm's `uvloop` fails
  on 3.14) and `fastapi<0.140` (litellm 1.97.0 imports `get_flat_dependant`, removed
  in FastAPI 0.140, and its own `fastapi>=0.136.3,<1.0` bound resolves to a broken
  combination). Both are pinned to upstream bugs and should be revisited on upgrade.

- [x] Decide whether to adopt the LiteLLM **SDK** in place of the proxy. Decided:
  adopt it, dropping LangChain, per [`litellm-sdk-plan-2026-08-19.md`](litellm-sdk-plan-2026-08-19.md).
  The proxy needs a sidecar process (and Postgres for its `/ui` dashboard), which sits
  awkwardly with a standalone CLI. Two measurements settled the approach: calling
  `litellm.completion` directly resolves to 49 dependencies against 65 for
  `langchain-litellm` and 39 today, because `langchain-litellm` pulls `langchain-core`
  *and* `litellm`; and the `openai.*` except-ladder in `analyzer.py` catches LiteLLM's
  exceptions unchanged. Both correct earlier estimates made before measurement. The SDK
  also needs no Python pin — 3.14 passes, since `uvloop` was a `[proxy]` extra.
  Review superseded the second point in part: the ladder does catch, but it is replaced
  with `litellm.exceptions` anyway, because importing `openai` while declaring only
  `litellm` leaves a direct dependency undeclared — and LiteLLM pins
  `openai>=2.20.0,<3.0.0`, downgrading the installed 3.1.0 to 2.54.0.

- [x] Execute that plan. `langchain-openai` is gone; messages are dicts; `response_format`
  plus an explicit `model_validate_json` replaces `with_structured_output`; the
  except-ladder is rebuilt on `litellm.exceptions`. `--explain` message construction is
  byte-identical to the pre-migration capture (377 lines diffed), and `--dry-run` output
  is unchanged. 96 tests pass and `ruff check src tests` is clean.

  Two corrections to the plan, both found during execution:

  - `litellm.exceptions.APIError` is a **sibling** of everything LiteLLM raises, not an
    ancestor — LiteLLM subclasses `openai`'s types directly, so
    `issubclass(litellm.InternalServerError, litellm.APIError)` is `False`. The planned
    catch-all was dead code and an unreachable endpoint escaped as an unhandled
    traceback (exit 1), leaking the raw provider message past the sanitized contract.
    `openai.OpenAIError` is the only working catch-all, so `openai` is now a **declared**
    direct dependency pinned to LiteLLM's own range — which answers the undeclared-import
    concern that motivated dropping it, without pretending the base class exists in
    LiteLLM.
  - LiteLLM reports a refused connection as a synthetic `InternalServerError` (status
    500) and drops the original exception, so it cannot be distinguished from a genuine
    provider outage. `InternalServerError`, `ServiceUnavailableError` and
    `BadGatewayError` map to exit 5 — the documented code for connection failures —
    under a message covering either cause. The unreachable-endpoint *message* therefore
    changed; the exit code did not.

- [x] Keep bare and opaque model names on the OpenAI-compatible route. `_NATIVE_PREFIXES`
  in `analyzer.py` is the allowlist, currently `("gemini/",)`; everything else gets
  `custom_llm_provider="openai"`. Asserted at the application boundary and with
  `get_llm_provider` canaries.

- [x] Stop chaining provider exceptions onto `LLMProviderError` (review finding,
  2026-08-19). `raise ... from exc` kept the original in `__cause__`, where every
  formatted traceback reprints it, so the sanitized message removed raw text that the
  traceback then republished — the exact route `case-analyzer-code.md` already said
  disqualified `enable_json_schema_validation`. Two paths were confirmed leaking before
  the fix: a provider error carried its raw response text, and a schema mismatch carried
  the model's **entire** rejected output as `ValidationError.errors()[0]["input"]`. Each
  handler now builds the error and the raise happens after the `try` statement, leaving
  `__cause__` and `__context__` unset. Exit codes are unchanged (`5` reconfirmed
  end-to-end against a closed port). `LITELLM_LOG=DEBUG` replaces the cause for
  development. Regression tests assert `__cause__`, `__context__`, and the formatted
  traceback; both fail against the pre-fix code.

- [x] Guard the native-prefix documentation against drift (review finding, 2026-08-19).
  The policy is restated in `README.md`, `FAQ.md`, `case-analyzer-code.md` and
  `.env.example`, none of which can reasonably defer to another. A test asserts every
  entry of `_NATIVE_PREFIXES` appears in all four, so adding a provider without
  documenting it fails the suite. `_provider_kwargs` keeps its string-prefix form; a
  route type is warranted when a second native provider lands, not before.

- [x] Add the offline timeout regression test. Enters through `_request_structured`
  against a loopback `ThreadingHTTPServer`, asserts `exit_code == 5`; `daemon_threads`
  keeps teardown under a second.

- [x] Verify live against the native API. `CASE_ANALYZER_MODEL=gemini/gemini-2.5-flash`
  with no base URL produced a valid `InvestigationReport`, recorded in
  [`examples/litellm-sdk/`](examples/litellm-sdk/README.md) alongside a comparison with
  the proxy run: same verdict, severity, confidence, evidence and remediation counts.

## Completed (2026-08-18 injection hardening)

- [x] Record the first live benchmark baseline (`evals/baseline-2026-08-18.md`):
  gemini-2.5-flash passed every wording-resistance and audit case but followed
  embedded instructions in all samples of both prompt-injection cases. Harden in two
  measured layers: an untrusted-data rule in `prompts/investigation.md` and
  `prompts/summary.md`, then BEGIN/END payload delimiters via
  `render_payload_message` in `analyzer.py`. The prompt rule alone fixed the verdict
  override and the attacker-IOC compliance but leaked the digest canary in 1 of 3
  samples; with the delimiters all injection samples pass. Recorded re-runs live in
  `evals/results/`.

## Completed (2026-08-18 eval harness)

- [x] Add the verdict-quality eval harness: `case-analyzer-evals` backed by
  `src/case_analyzer/evals.py` and `evals/manifest.json`. It reuses the three
  reasoning cases and the ip-verdict audit case, adds two prompt-injection cases with
  field-scoped forbidden-content checks (`evals/cases/`), and supports `--samples` for
  verdict-agreement measurement plus `--only`/`--tag` selection. Harness logic is
  covered offline in `tests/test_evals.py` with a stubbed analyze function; a live run
  costs one LLM request per case per sample and never contacts enrichment providers.
  `test.sh` and the recorded examples are unchanged. Future adversarial-review or
  self-consistency modes should run against the same manifest for comparability.

## Completed (2026-08-18 follow-up)

- [x] Make the enrichment budget a real wall-clock bound: it now caps each request's timeout as well as gating the start of a lookup, so a single lookup can no longer run for the full `--enrichment-timeout` past the deadline. A request the budget cuts short is recorded as `skipped` and is not counted against the provider (M-2 follow-up).
- [x] State the circuit breaker's actual guarantee. The check is inherently check-then-act: lookups already dispatched are not cancelled, so a failing provider can receive up to `threshold + concurrency - 1` calls. `--help`, `README.md`, and a new concurrency test record that bound (M-2 follow-up).
- [x] Give the RDAP bootstrap cache a one-hour TTL, and describe it as process-wide rather than per run, so a long-lived caller cannot pin a stale copy or a failed fetch indefinitely (L-4 follow-up).
- [x] Make the bootstrap fetch single-flight per address family, so concurrent cold lookups wait for one fetch instead of each making their own and "fetched once" is true under concurrency (L-4 follow-up).
- [x] Stop the RDAP query from starting when the bootstrap fetch has used the whole lookup timeout. The previous 0.1s floor let an IP lookup run past the budget; it now raises, which a budgeted run records as `skipped` (M-2 follow-up).
- [x] Report a non-object JSON body from a `200` response as a provider `error`. It was previously coerced to an empty mapping, which read as `not_found` for DNS and as `found` for RDAP and VirusTotal (H-5 follow-up).

## Completed (2026-08-17 review, second pass)

- [x] Bound enrichment wall time with `--enrichment-budget` (default 60s), run lookups through `--enrichment-concurrency` workers (default 4), and drop a provider after `--enrichment-failure-threshold` consecutive failures. Unqueried observables are recorded as `skipped` with a reason, and the run reports `stopped_early` (M-2).
- [x] Require `--allow-enrichment-in-dry-run` before `--enrich` may contact providers during a dry run; the stderr notice is still printed (M-5).
- [x] Extract file hashes as a `file_hash` observable enriched through VirusTotal, and contribute the host or domain part of URL and email fields as `domain`/`ip` observables with a `#host`/`#domain` source path (H-2 follow-up).
- [x] Resolve RDAP through the IANA bootstrap, cached process-wide for an hour, falling back to `rdap.arin.net`; `details.rdap_source` and `details.rdap_authority` record what happened (L-4).
- [x] Make `generated_at` and `retrieved_at` real `datetime` fields with a `Z` serializer, removing the manual timestamp rewrite (L-10).
- [x] Reject oversized case and knowledge files with `--max-input-bytes` (default 5 MB, `0` disables) before they are parsed or sent (L-11).

## Completed (2026-08-17 review, first pass)

- [x] Document the enrichment block in `prompts/investigation.md` (M-6).
- [x] Coerce non-mapping JSON response bodies inside `_http_json` (H-5).
- [x] Recurse into `cef` when `cef_types` is missing or not a mapping (H-1).
- [x] Replace substring hint matching with an explicit hint-to-kind table plus word-boundary matching (H-2).
- [x] Track whether a kind was declared by `cef_types` or inferred from a key name, and only report `conflicting` for declared mismatches (H-3).
- [x] Rename `existing_case_context` to `artifact_context`, collect it for any mapping carrying `notes`/`comments`, and state in the prompt that it describes the containing artifact rather than the value (H-4, M-1).
- [x] Give `skipped` lookups their own comparison branch (M-3).
- [x] Read and validate every input file before running enrichment (M-4).
- [x] Warn on stderr before the first request when `--enrich` is combined with `--dry-run` (M-5, partial; see above).
- [x] Pass `--llm-timeout` to `ChatOpenAI`, preflight the API key with an exit-2 message, and wrap structured-output `ValidationError` without printing raw model output. `max_retries=0` is unchanged (M-8).
- [x] Group on the validated tuple instead of validating twice (L-1).
- [x] Truncate enrichment context once at the caller and fix the doubled space in joined snippets (L-2).
- [x] Make truncation deterministic and prioritized (L-3).
- [x] Record the RDAP authority that answered (L-4, partial; see above).
- [x] Note in `--help` that VirusTotal can double the observation count (L-6).
- [x] Add `tests/__init__.py`, document the test command in `README.md` and `AGENTS.md`, and add a `dev` dependency group with ruff (L-7).
- [x] Add regression tests for the review findings plus `adapters.py`, `_http_json` status branches, `_validate`, VirusTotal eligibility, observation counts, and `--output` writing: 43 tests, all offline (L-8).
- [x] Note in `--help` that the deprecated alias forwards neither `--output` nor `--enrich` (L-9).
- [x] Regenerate `examples/enrichment/` against live providers so the recorded payload uses `artifact_context`, and verify the full path — enrichment, prompt, structured output — with one live LLM run.
