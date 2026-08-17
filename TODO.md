# TODO

Findings prefixed `H-`, `M-`, or `L-` refer to [`code-review-2026-08-17.md`](code-review-2026-08-17.md),
which records the symptom, location, offline verification, and recommended direction for each.

## Existing

- [ ] Address payload quality, duplicated `source_data`, provider cost and rate limits, and excessive noisy enrichment. Measured duplication is 1.52x on `examples/splunk-soar.json` (M-7); VirusTotal has no throttle against its ~4 request/minute public tier (L-5).
- [ ] Evaluate additional free enrichment providers in this order: AbuseIPDB for public-IP reputation, ThreatFox for domain/IP IOC matches, GreyNoise Community for internet-scanner context, and URLhaus after complete URL extraction is supported. Keep provider results separately attributed, cache responses, respect enrichment limits, and treat `not_found` as inconclusive. Document and enforce each provider's API quota, fair-use terms, and commercial-use restrictions before enabling it in operational workflows.
- [ ] Remove the deprecated `explain_case_analysis` and `explain-case-analysis` aliases in the next breaking release; use `case-analyzer --explain` instead. Until then, note in `--help` that the alias forwards neither `--output` nor `--enrich` (L-9).

## Correctness (from the 2026-08-17 review, in suggested order)

- [ ] Document the enrichment block in `prompts/investigation.md`: `not_found` and `error` are not evidence of benignness, `comparison_with_case` is not a verdict, and VirusTotal statistics are third-party votes rather than ground truth. The model currently receives `case_analyzer_enrichment` with no instructions for it (M-6). No code change; independent of every item below.
- [ ] Coerce non-mapping JSON response bodies inside `_http_json` so a provider returning a JSON array cannot crash the CLI with an uncaught `AttributeError` (H-5).
- [ ] Rework observable extraction in one pass, since these three share a provenance refactor of `_walk_observables` (H-1, H-2, H-3):
  - [ ] Recurse into `cef` when `cef_types` is missing or not a mapping; today those artifacts yield zero observables silently (H-1).
  - [ ] Replace substring hint matching with an explicit hint-to-kind table plus word-boundary matching, covering `host_name`, `url`, hash types, and space-separated spellings, and rejecting `domainCreationDate`-style false positives (H-2).
  - [ ] Track whether a kind was declared by `cef_types` or inferred from a key name, and only report `conflicting` for declared mismatches; inferred mismatches are extractor noise, not a contradiction inside the case (H-3).
- [ ] Fix `existing_case_context` attribution (H-4, M-1):
  - [ ] Stop copying artifact-level notes onto every observable in that artifact; today a destination IP carries a note about a domain's reputation. Either match the note text against the value or rename the field to `artifact_context` and say so in the prompt (H-4).
  - [ ] Compute context for any mapping carrying `notes`/`comments`, not only ones with a `cef` child, so generic-format exports keep it (M-1).
- [ ] Give `skipped` lookups their own comparison branch; a private IP that was never queried currently gets an explanation about DNS and registration facts that were not retrieved (M-3).
- [ ] Read and validate every input file before running enrichment, so a malformed `--knowledge` file cannot waste provider calls and VirusTotal quota (M-4).

## Testing and tooling

- [ ] Make the suite discoverable: add `tests/__init__.py` (or document that only `-t tests` works), record the test command in `README.md` and `AGENTS.md`, and add a dev dependency group for the chosen runner and linter (L-7).
- [ ] Add the regression tests that would have caught the review findings, plus the untested surface: `adapters.py` in full, `_http_json` status branches, `_validate` idna and trailing-dot handling, VirusTotal eligibility for private IPs, the limit-versus-VirusTotal observation count, and `--output` writing (L-8).

## Behavior and interface changes (confirm intended UX first)

- [ ] Bound enrichment wall time: an overall budget, concurrent lookups, and a circuit breaker after repeated provider failures. Worst case today is roughly 250s with no interim output (M-2).
- [ ] Decide how `--enrich` should behave under `--dry-run`. It currently discloses observables to third parties; at minimum warn on stderr before the first request (M-5).
- [ ] Harden the analyzer: pass a request timeout to `ChatOpenAI`, preflight the API key with an actionable exit-2 message instead of the opaque `OpenAIError` path, and wrap structured-output `ValidationError` so raw model output is not printed. Keep `max_retries=0` (M-8).

## Cleanup

- [ ] Remove the duplicated `_validate` call in `enrich_case` and group on the validated tuple (L-1).
- [ ] Truncate enrichment context once at the caller rather than at every recursion level, and fix the doubled space in joined snippets (L-2).
- [ ] Make truncation deterministic and prioritized instead of taking the first `limit` items in dict insertion order (L-3).
- [ ] Stop hardcoding `rdap.arin.net`: use the IANA RDAP bootstrap or record the authority that actually answered, since `provider` currently reports `arin-rdap` regardless (L-4).
- [ ] Note in `--help` that VirusTotal can double the observation count relative to `--enrichment-limit` (L-6).
- [ ] Consider `datetime` fields with a serializer instead of `str` timestamps, removing the manual `+00:00`-to-`Z` rewrite (L-10).
- [ ] Consider an input size guard in `_json_file` so oversized cases fail locally rather than at the gateway (L-11).
