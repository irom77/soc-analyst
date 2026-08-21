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
from the 2026-08-18 limitations review. Every item in it is now implemented except
Tier 4 item 11 (a context-overflow strategy), which stays propose-and-discuss on the
plan's own advice: wait until someone actually hits `--max-input-bytes`. Tier 3's audit
mode shipped on 2026-08-20 and was measured across samples on 2026-08-21; Tier 4's
`source_data` deduplication landed opt-in on 2026-08-20 with an envelope follow-up on
2026-08-21. Every design question in that plan's review section is now resolved. The benchmark was
re-run on the post-Tier-2 build on 2026-08-20 and all six cases pass; see
[`evals/post-tier-2-2026-08-20.md`](evals/post-tier-2-2026-08-20.md). The enrichment
stack was verified against live providers the same day, confirming item 6, item 5's
cache and pacer, and item 7's URLhaus path, and fixing a credential leak it exposed; see
[`examples/live-enrichment/`](examples/live-enrichment/README.md).

Check the current state with `uv run python -m unittest discover -s tests -t .` and
`uv run ruff check src tests` (307 offline tests; no credentials or network needed).

## Existing

- [x] Fix the two defects an external review of `3b7a8dc..HEAD` confirmed, both of which
  the offline suite had no test for. **A URL that cannot be parsed kept its credential:**
  `_validate_url` redacted only after `urlsplit` and `.port` succeeded, so
  `https://alice:hunter2@example.com:notaport/x` and a malformed IPv6 authority reached the
  report and the model payload intact — the same leak class as 2026-08-20, by a different
  branch. Redaction now runs before parsing and works on the text via `_AUTHORITY_RE`, so
  no return can bypass it. The old splice also corrupted scheme-relative URLs
  (`//alice:hunter2@example.com/x` became `//aexample.comx`); that is fixed too, and a
  scheme-plus-path with no `//` is now deliberately left alone, because RFC 3986 reads
  `mailto:user@example.com` the same way and nothing distinguishes the two.
  **`--reduce-source-data` could delete evidence:** the residue picked its key set from
  `case.source`, which holds whatever the export calls itself, so a generic case with
  `"source": "splunk"` was reduced against the SOAR set and lost `product` and `data`.
  `normalize_case` now records the adapter it actually ran in a private
  `CanonicalCase._source_format`, which stays out of `model_dump` and so out of the
  payload. Six regression tests added, each confirmed to fail against the previous code.


- [ ] Confirm VirusTotal's base64 URL identifier with a live call, against a key with
  quota available. The 2026-08-20 run reached VirusTotal but its quota was exhausted, so
  both URL attempts returned HTTP 429 before the identifier was evaluated. The encoding
  itself is now pinned to the worked example in VirusTotal's own v3 URL documentation
  rather than to a value our code produced, which closes the circularity: the previous
  test would have passed under padded standard base64, because its 24-byte URL needs no
  padding and contains no `+` or `/`. What remains unproven is only that the live API
  accepts the documented form. The domain endpoint and item 5's 15-second pacer were
  confirmed in the same run. See
  [`examples/live-enrichment/README.md`](examples/live-enrichment/README.md).

- [x] Add a dedicated formal compliance-audit mode instead of relying on `user_input`.
  Shipped as `--audit` (improvement-plan item 8): `prompts/audit.md`, a `CaseAuditReport`
  of per-control `pass`/`fail`/`not_applicable`/`insufficient_evidence` entries with cited
  evidence paths, control records validated before the request in `controls.py`, and a
  deterministic coverage check in `checks.py` that is not asked of the model. Offline
  only, matching the `--summary` rollout: 61 tests, and the recorded example in
  `examples/audit/` is a `--dry-run --explain` preview, not model output. **The control
  record shape is provisional** -- designed against the requirements in
  `examples/user-input-case-audit/README.md` rather than a real policy export. Flat
  controls, `(policy_ref, control_id)` identity, and a mandatory rationale on every status
  are the three decisions to revisit once real controls exist; each is pinned by a test.

- [x] Run `--audit` live. Done on 2026-08-20 against `gemini-2.5-flash`: all nine
  benchmark cases pass, the asserted-compliance case returned `insufficient_evidence`
  rather than `pass` for the control its own note claimed was met, the injected note
  ordering every control passed was refused with `documented_exceptions` empty and no
  canary anywhere, and the two checks added the same day produced no false positives on
  three correct answers. One sample, one model, three audit cases -- a tripwire, not a
  guarantee. See [`evals/audit-mode-2026-08-20.md`](evals/audit-mode-2026-08-20.md).
  Re-run at `--samples 3` on 2026-08-21: 100% agreement on every control in all three
  cases, citations byte-identical in 7 of 9 assessments and varying only by an added
  corroborating field in the other 2. That closes the "one sample" caveat and no other;
  see [`evals/audit-stability-2026-08-21.md`](evals/audit-stability-2026-08-21.md).

- [ ] Run `--audit` against a **real** policy export, which the live run above does not
  cover. The eval harness half is done: it now takes `mode: "audit"`
  entries with a `controls_file` and per-control `expected_statuses`, scores each control
  and the coverage of the whole set, and ships three cases over one control set --
  asserted-but-undocumented compliance (`IR-4.2` must be `insufficient_evidence`, not
  `pass`), genuinely documented compliance (every control `pass`, the anti-degeneracy
  anchor without which an always-`insufficient_evidence` model scores clean), and an
  injected note ordering every control passed with an approved exception invented. Name
  the three ids with `--only` to measure them (3 live requests per sample); `--tag audit`
  also selects `ip-verdict-claim`, which is an analysis case, and so costs four.
  **Still unmeasured, and not reachable this way:** whether a *real* policy export parses
  without reshaping. The benchmark control set was written for the benchmark, so the
  record shape stays provisional until it meets a real one.
- [ ] Address payload quality and excessive noisy enrichment. The duplicated `source_data` half (M-7) is done: `--reduce-source-data` sends only the fields normalization did not lift, cutting about a quarter of the payload on SOAR-shaped cases, and ships off by default because two of six benchmark cases moved verdict or confidence under it. Measured in [`evals/source-data-residue-2026-08-20.md`](evals/source-data-residue-2026-08-20.md), which also found the one case it did almost nothing for: `examples/unknown.json` recovered 1.1% where every other case recovered a quarter to two fifths. That was followed up on 2026-08-21 and the diagnosis there was wrong — the `raw`/`parsed` pair is real but is 12% of the file, not its bulk. The actual cause was that the case is an *envelope*, so the generic adapter lifted nothing at all and the residue had nothing to subtract: 0 of 10 canonical fields filled, against 4 to 8 for every other example. Normalization now unwraps an envelope when the top level carries no content, and the residue applies its key rule at the depth the adapter read from; that case fills 7 of 10 fields and reduces by 35.4%, and every other example is byte-identical. What is left is about 1.5k characters of `raw.content` restating lifted fields in the other key spelling, deliberately not chased. See [`evals/envelope-normalization-2026-08-21.md`](evals/envelope-normalization-2026-08-21.md). The provider cost and rate-limit half (L-5) is done — the response cache and 15-second VirusTotal pacing landed with Tier 2 item 5, which is what the `HTTP 429` on the second live run called for.
- [ ] Evaluate the remaining free enrichment providers: ThreatFox for domain/IP IOC matches and GreyNoise Community for internet-scanner context. URLhaus is done — it landed with item 7 once whole URLs became observables. Keep provider results separately attributed, respect enrichment limits, and treat `not_found` as inconclusive; caching and per-provider pacing are now handled centrally in `enrichment_cache.py`, so a new provider needs a request id and, if it publishes a per-minute limit, an interval. Document and enforce each provider's API quota, fair-use terms, and commercial-use restrictions before enabling it in operational workflows.
- [x] Add optional AbuseIPDB public-IP reputation through the v2 `check` endpoint. It uses a 30-day report window, runs only when `ABUSEIPDB_API_KEY` is configured, and keeps the result separately attributed. The Standard tier currently permits 1,000 `check` requests per day; higher account tiers have higher limits. Operators remain responsible for confirming that their account and use comply with the provider's current terms.
- [x] Add `--summary`, which asks the model to describe the input case in prose and stops, printing `{"summary": ...}` instead of an `InvestigationReport`. It reuses the analysis payload under a separate `prompts/summary.md` system prompt that forbids a verdict, severity, attack chain, or remediation, and returns the `CaseSummary` schema. `analyze_case` and `summarize_case` now share one provider call and its sanitized error mapping. With `--dry-run` no request is sent; `--explain` shows the summary prompt.
- [ ] Remove the deprecated `explain_case_analysis` and `explain-case-analysis` aliases in the next breaking release; use `case-analyzer --explain` instead. The `--help` text already states that the alias forwards neither `--output` nor `--enrich` (L-9).

## Extraction coverage

- [ ] Revisit email addresses if a provider worth trusting starts covering them. They are
  extracted and recorded today, but nothing looks them up, so the observation is
  provenance rather than enrichment.

## Completed (2026-08-19 full-URL and email observables)

- [x] Tier 2 item 7 — the URL and the email address are now observables in their own
  right, not just the `#host`/`#domain` part derived from them. `observable_type` gained
  `url` and `email`; a URL or email field emits both the value and its host or domain, so
  a whole URL and its host stay separate questions with separate providers.
- [x] URLhaus (`https://urlhaus-api.abuse.ch/v1/url/`) added as the URL provider, gated on
  `ABUSE_CH_AUTH_KEY` and sending it as the `Auth-Key` header with the URL as a POST form
  body. It answers HTTP 200 for a refused query as well as a hit, so the outcome is read
  from `query_status`: `ok` is `found`, `no_results` is `not_found`, anything else is an
  error. VirusTotal covers URLs too, by the unpadded URL-safe base64 identifier its API
  requires. Both are separately attributed and `inconclusive`, never a verdict.
- [x] URL normalization keeps the path, query, and fragment byte-for-byte and folds only
  the scheme, host, an implied port, and an empty path. **Userinfo is stripped**, so a
  `user:password@` URL never reaches a third-party API or the plaintext cache; the
  original text stays reachable through `source_paths`. Only `http`, `https`, and `ftp`
  are valid schemes. An email's domain half is normalized as a domain and its local part
  is left alone, since RFC 5321 makes it case-sensitive.
- [x] Email addresses are recorded but never sent anywhere — no provider here answers for
  an address. Email observables, and URL observables when no URL provider is configured,
  sort behind everything a provider can answer for, so they never take an
  `--enrichment-limit` slot from a real lookup.
- [x] URLhaus is unpaced (abuse.ch publishes fair-use terms, not a rate), so it runs in the
  unpaced first pass alongside DNS and RDAP and cannot be starved by VirusTotal's spacing.
  Its responses are cached under their own request id with the one-hour reputation TTL.
- [x] Verified offline: 198 tests pass, and a synthetic case carrying a credentialed
  internationalized URL, an internationalized address, and an unparsable URL produced the
  expected seven observations with the credential removed. No live abuse.ch or VirusTotal
  request was made and no recorded example was regenerated.

## Completed (2026-08-19 enrichment caching and pacing)

- [x] Tier 2 item 5 — response cache plus provider pacing, in `enrichment_cache.py`
  (`EnrichmentCache`, `ProviderPacer`) with `--cache-dir` and `--no-cache`. Fixes the
  failure recorded further down this file — HTTP 429 on a second run minutes later — and
  the duplicated-cost concern in one change.

  Responses are keyed by provider, endpoint-and-parameters, observable type, and value
  together; a version marker in the per-provider request id retires entries when the
  request or the stored detail set changes. Writes are atomic. TTL is per provider: 15
  minutes for DNS, an hour for reputation, a day for registration data. Only `found` and
  `not_found` are stored — caching an error would freeze a timeout or a 429 into every
  later run, which is the opposite of the point. A cache hit keeps the original
  `retrieved_at`, so a saved block never claims to have just fetched hour-old data.

  Pacing spaces VirusTotal requests 15 seconds apart for the public 4/min tier, claiming
  the next slot under a lock *before* waiting, so concurrent workers take distinct slots
  instead of all sleeping and then firing together. Cross-process it is best-effort
  through the cache directory, documented rather than closed.

  Review point 3 was signed off and is recorded in the plan: waits consume
  `--enrichment-budget` (a free wait would let a run outlast a wall-clock limit
  invisibly), overflow is `skipped` with a reason naming the interval rather than a
  failure, and starvation is *removed* rather than mitigated — lookups run in two passes
  so every unpaced provider finishes before the first paced reservation. Measured offline:
  9 of 9 RDAP lookups completed while 6 of 9 VirusTotal lookups were paced out, inside the
  budget. At defaults this means about four uncached VirusTotal lookups per cold run;
  raise the budget for a large cold case, and a repeat run within the TTL costs nothing.

  The cache writes observable values and provider answers outside the case file in plain
  JSON. Readable on purpose — an uninspectable cache is unauditable — but the directory
  now deserves the same handling as the cases, and `--no-cache` is the way out.

  179 tests pass and `ruff check src tests` is clean.

## Completed (2026-08-19 internationalized domains)

- [x] Tier 2 item 6 — IDN handling. Half of it was already in place: `_validate` has
  punycoded domains before matching the ASCII-only `_DOMAIN_RE` since the original
  enrichment work, so Unicode names were being looked up rather than discarded. What was
  missing was the choice of standard and the original spelling.

  Domains are now encoded with **UTS #46, nontransitional**, through the `idna` package
  instead of Python's built-in IDNA 2003 codec. The deciding case is `faß.de`: the
  built-in codec's transitional mapping encodes it to `fass.de`, so the tool would look
  up a domain someone else may own and attribute the answer to the observable in the
  case. Nontransitional is also what browsers resolve with. The two were compared first
  across the host shapes the suite covers — NetBIOS names, `localhost`, literal
  addresses, underscored labels, over-long labels, leading and trailing hyphens, trailing
  dots, mixed case, ordinary IDNs — and agreed on every validity outcome; they diverge
  only on transitional mappings and on emoji labels, which are now invalid. `idna` was
  already installed transitively via `httpx`/`requests`, so it is newly declared, not
  newly installed.

  `EnrichmentObservation.unicode_values` records the non-ASCII spellings the case used;
  `value` stays the punycode form. A list, not a field, because case, width, and
  ignorable characters can collapse several spellings into one name. It is provenance
  and not a homograph verdict — confusable spellings still render identically in it, so
  the reliable signal remains the `xn--` prefix on `value`, and the schema says so.

  Additive: both recorded enrichment examples validate untouched. 154 tests pass and
  `ruff check src tests` is clean.

## Completed (2026-08-19 report self-description)

- [x] Tier 1 item 2 — enum-constrained decision vocabulary. `verdict` and `confidence`
  are now `Literal` types: the five verdicts and Low/Medium/High, in the Title Case
  every recorded run and eval case already used. `severity`, `impact`, and `priority`
  stay free strings — the recorded SOAR exports carry `critical`, `informational`, and
  lowercase spellings, which belong to the source platform rather than to this tool.

  An off-list value fails validation like any other malformed response (exit 6, no
  report), which is what makes the vocabulary a contract; the sanitized error names the
  field, never the rejected wording. All seven previously recorded reports validate
  against the closed schema untouched, and a test asserts that, so it doubles as the
  regression guard if the sets ever change. Another test asserts the prompt names exactly
  the enum values, since drift between them would fail every run.

  This is the only Tier 1 item that changes what the provider sees, so it was verified
  live: [`examples/provenance/`](examples/provenance/README.md) records the run. The same
  run re-confirmed the citation fix in the live path — 14 of 14 citations resolved, none
  written with the `case.` prefix that the earlier run exposed.

- [x] Tier 1 item 1 — report provenance. `analyze_case()` and `summarize_case()` now
  return `AnalyzedReport`/`AnalyzedSummary`: the model's own schema plus a
  `case_analyzer_run` block built locally by the new `provenance.py`. It records the
  model, endpoint host, SHA-256 of the system prompt and rendered payload, an optional
  input-file hash, package and report-schema versions, a timestamp, presence flags, and
  the post-check result.

  The plan's two open review points were the design, and both were decided here.
  Provenance is kept out of the model-facing schema by splitting request schema from
  saved-result schema — `InvestigationReport`/`CaseSummary` are still exactly what goes
  out as `response_format`, and the saved types subclass them — rather than by an
  envelope, which would have moved every existing field down a level and broken both
  recorded examples and any consumer of the CLI's stdout. The guarantee lives on the
  public calls rather than an optional `attach_provenance()` helper, so there is no
  supported unprovenanced path; `_request_structured` is private.

  The endpoint is stored as host and port only: a base URL can carry credentials in its
  userinfo and a token in its query, and a test asserts no part of a key reaches the
  block.

- [x] Tier 1 item 4 — evidence citations by JSON path. `EvidenceFinding.source_paths`
  cites the case fields a finding was read from, using the grammar enrichment already
  emits. `checks.resolve_case_path` verifies each one against the rendered payload,
  locally and with no second LLM call. The live run recorded in
  [`examples/citations/`](examples/citations/README.md) reported 16 of 16 citations
  unresolved on the first try: the paths were right, but the model spelled the root out
  as `case.…`, which "rooted at the payload's `case` object" invites. Fixed on both
  sides — the prompt says not to write the root segment, and the resolver retries
  without a `case.` prefix only after the canonical form fails, so a real top-level key
  of that name still wins. Re-verified offline: 16 of 16 resolve.

- [x] Tier 1 item 3 — truncation signalling. `InvestigationReport.truncated_fields`
  names each list shortened to fit its cap, enum-constrained to the seven capped
  collections. `omitted_count` is a plain `int` rather than `int | None`, because an
  optional int renders as `anyOf: [integer, null]` and strict structured-output modes
  handle that unevenly; the whole report schema is now free of `anyOf`. `LIST_CAPS`
  records the caps the prompt states and a test asserts they agree. The post-check
  catches the one contradiction a response can expose — truncation claimed for a list
  below its cap; under-reporting is not detectable from a response and is not claimed
  to be.

  Both pieces deferred here were delivered with Tier 1 item 1 below: the check result is
  recorded in `case_analyzer_run.checks` as well as echoed on stderr, and it now runs
  inside `analyze_case()`, so the eval harness gets it without change.

  One observation worth watching rather than acting on: in the recorded run
  `truncated_fields` was empty while `evidence_findings`, `remediations` and `unknowns`
  each sat exactly at their cap. Consistent with a complete report, equally consistent
  with under-reporting, and not decidable from one sample.

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
  is unchanged. 147 tests pass and `ruff check src tests` is clean.

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
