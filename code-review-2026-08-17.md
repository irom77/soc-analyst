# Code Review — 2026-08-17

Read-only review of `src/case_analyzer/` at commit `5020fd8` ("Track additional enrichment
providers"), working tree clean. No code was changed. Every behavioral claim below was
verified by running the code offline (injected provider callables, no live LLM or provider
requests). This file is a handoff record: each finding states the symptom, the location, the
verification, and a recommended direction, so it can be picked up without re-deriving the
analysis.

## Status

The findings below describe the code as it was at `5020fd8`. They were implemented on
2026-08-17; the body of this file is left unchanged as the record of what was found.

| Resolved | Open |
| --- | --- |
| H-1, H-2, H-3, H-4, H-5, M-1, M-2, M-3, M-4, M-5, M-6, M-8, L-1, L-2, L-3, L-4, L-6, L-7, L-8, L-9, L-10, L-11 | M-7 and L-5, which were already `TODO.md` items before the review |

Notes for anyone reading a finding against current code:

- H-4 was resolved by the "rename" option: the field is `artifact_context`, and the
  system prompt states that it describes the containing artifact rather than the value.
- H-2's hash hints produce a `file_hash` observable enriched through VirusTotal; URL and
  email hints contribute their host or domain part, whose source path carries a `#host`
  or `#domain` suffix. The URL and address themselves are still not looked up.
- M-5 was resolved by the stricter option: `--enrich` with `--dry-run` is refused unless
  `--allow-enrichment-in-dry-run` is passed.
- L-4 now uses the IANA RDAP bootstrap with an ARIN fallback, so `provider` is `rdap`
  rather than `arin-rdap`.

## How to reproduce the verification environment

```bash
uv sync
uv run python -m unittest discover -s tests -t .
```

At the reviewed commit that discovery command failed (see L-7) and the explicit module
form `uv run python -m unittest tests.test_cli tests.test_enrichment` was needed. Enrichment
findings were reproduced by calling `case_analyzer.enrichment` directly with stub
`domain_lookup` / `ip_lookup` callables, which avoids all network access.

## What is in good shape (do not regress these)

- Clear layering: `adapters` → `enrichment` → `analyzer` → `cli`, with no back-references.
- Every provider call is an injectable parameter of `enrich_case`, so enrichment is fully
  testable offline. Preserve this seam.
- Enrichment is written to `case.case_analyzer_enrichment` and never mutates `source_data`;
  `tests/test_enrichment.py:29` asserts it.
- Provider failures are sanitized into `LLMProviderError` with distinct exit codes
  (2/3/4/5/6), and enrichment failures are recorded per-observation rather than aborting.
- stdout carries only JSON; all diagnostics go to stderr (`tests/test_cli.py:69` asserts
  stdout stays parseable).
- No credentials tracked: `git ls-files` lists only `.env.example`.

---

## High severity

### H-1. `cef` contents are dropped entirely when `cef_types` is absent

`src/case_analyzer/enrichment.py:66`

`if key not in {"cef", "cef_types"}` prevents recursion into the `cef` mapping, and the only
other extraction path (`:54`) requires `cef_types` to be a `Mapping`. So an artifact with a
populated `cef` and no `cef_types` produces zero observables, with no warning.

Verified:

```python
case = normalize_case({"id": "a", "title": "t", "artifacts": [
    {"cef": {"destinationAddress": "9.9.9.9", "destinationDnsDomain": "evil.test"}}]})
_walk_observables(case.source_data)   # -> []
```

Splunk SOAR exports do not always carry `cef_types` (it is populated by the ingesting app).
`examples/splunk-soar.json` happens to have it on all three artifacts, which is why no test
catches this.

Direction: when `cef_types` is missing or not a mapping, fall back to recursing into `cef`
with the existing key-name heuristics. Guard against double-emitting fields that
`cef_types` already resolved.

### H-2. The type-hint vocabulary misses the `cef_types` values the repo's own example uses

`src/case_analyzer/enrichment.py:22-23, 31-37`

`_kind_from_hint` returns `None` for `host_name`, so `sourceHostName` is never extracted
from `cef` even when `cef_types` declares it. Verified against `examples/splunk-soar.json`:

```
cef_type: ('destinationAddress', ('ip',))       -> ip
cef_type: ('destinationDnsDomain', ('domain',)) -> domain
cef_type: ('sourceHostName', ('host_name',))    -> None      <-- dropped
cef_type: ('destinationPort', ('port',))        -> None       (correct, not an observable)
cef_type: ('processName', ('process_name',))    -> None       (correct)
```

Also unmapped: `url`, `hash` / `md5` / `sha1` / `sha256`, `email`, and the space-separated
spellings SOAR emits (`"host name"`, `"ip address"`).

The substring test `"domain" in normalized` also produces false positives:

```
_kind_from_hint("domainCreationDate")   -> "domain"
_kind_from_hint("registeredDomainAge")  -> "domain"
```

Direction: replace the substring checks with an explicit hint→kind table plus
word-boundary/suffix matching over a normalized (`-`, `_`, space → single separator) form.
Add a test asserting every distinct `cef_types` value in `examples/` maps to the intended
kind or to `None` deliberately.

### H-3. `_comparison` reports a fabricated case-internal contradiction

`src/case_analyzer/enrichment.py:191-196`

An invalid value yields `status="conflicting"` with the explanation *"The value is labeled as
a {kind} in the case but does not have valid {kind} syntax."* That sentence is only true when
`cef_types` **declared** the type. For values classified by the key-name heuristic the claim
is false, and it is handed to the LLM as evidence of an inconsistency inside the case.

Concrete triggers, both from H-2: a NetBIOS hostname (`sourceHostName: "WORKSTATION-01"`,
which `_validate` rejects as a domain — verified `(False, 'workstation-01')`) and
`domainCreationDate`, which the heuristic mislabels as a domain and validation then rejects.

Direction: carry the provenance of the kind through `_walk_observables`
(`declared` from `cef_types` vs `inferred` from a key name). Only `declared` mismatches
justify `conflicting`; `inferred` mismatches are extractor noise and should be
`not_comparable` with an explanation that says so.

### H-4. `existing_case_context` is attributed to the wrong observable

`src/case_analyzer/enrichment.py:50-53, 227-229`

Context is computed once per artifact and then copied onto every observable found in that
artifact, so a note about one value is presented as context for another. Verified on
`examples/splunk-soar.json` — the destination **IP** observation carries a note about the
**domain**:

```
('ip', '198.51.100.44', ...) existing_case_context:
  ['Threat Intelligence Enrichment  Domain resolved via Fast Flux DNS.
    Reputation score: 89/100 Malicious.']
```

The model reads that as reputation evidence for the IP. This matters more than it looks,
because the whole design intent is that enrichment must not silently import reputation
claims.

Direction: either attach a snippet only when the observable's value (or a normalized form of
it) appears in the note text, or rename the field to `artifact_context` and say in the
prompt that it describes the containing artifact, not the value. The doubled space in the
snippet is a separate cosmetic bug (see L-2).

### H-5. A non-mapping JSON response body crashes the CLI with a traceback

`src/case_analyzer/enrichment.py:88-98`

`_http_json` is annotated `-> tuple[int, dict[str, Any]]` but returns whatever `json.load`
produced. A provider returning a JSON array or scalar makes the callers' `body.get(...)`
(`:109`, `:134`, `:164`) raise `AttributeError`, which appears in none of the caught tuples
— not `enrichment.py:245`, not `:271`, not `cli.py:144`. The process dies with a traceback
mid-analysis instead of recording an error observation.

Verified by stubbing `_http_json` to return `(500, ["boom"])`:

```
CRASH: AttributeError 'list' object has no attribute 'get'
```

Direction: normalize inside `_http_json` — if the decoded body is not a `Mapping`, return
`{"error": <repr, truncated>}`. Add `AttributeError`/`TypeError` to the caught tuples as a
belt-and-braces measure, and add tests for the 404 / 500 / non-JSON / non-mapping branches.

---

## Medium severity

### M-1. Artifact context is lost entirely for non-SOAR export shapes

`src/case_analyzer/enrichment.py:50`

`local_context` is only computed when the mapping has a `cef` child, so a generic-format
artifact never contributes context, contradicting the README's description. Verified:

```python
case = normalize_case({"id": "c", "title": "t", "artifacts": [
    {"destinationAddress": "8.8.8.8",
     "notes": [{"title": "Threat Intelligence Enrichment", "content": "malicious"}]}]})
# -> observations[0].existing_case_context == []
```

Direction: compute context for any mapping that has `notes`/`comments`, independent of `cef`.

### M-2. No overall time budget; lookups are strictly sequential

`src/case_analyzer/enrichment.py:233-294`

Worst case is `--enrichment-limit` (default 25) × 2 providers × `--enrichment-timeout`
(default 5s) ≈ 250s of wall time, with no output until it finishes.

Direction: add an overall deadline (e.g. `--enrichment-budget`), run lookups through a small
`ThreadPoolExecutor`, and stop calling a provider after N consecutive failures (recording the
remainder as `skipped` with a reason).

### M-3. `skipped` observations get a factually wrong comparison

`src/case_analyzer/enrichment.py:191-205`

A private IP is never queried, but `skipped` is not in `{"not_found", "error"}`, so it falls
through to the `not_comparable` branch whose explanation talks about DNS and registration
facts that were never retrieved. Verified: `10.20.4.115` in `examples/splunk-soar.json`.

Direction: add an explicit `skipped` branch — no lookup was performed, therefore
inconclusive/no data.

### M-4. Billable enrichment runs before cheap input validation

`src/case_analyzer/cli.py:100-111`

`enrich_case` (network, and VirusTotal quota) executes before `--knowledge` is read and
type-checked at `:109-111`. A malformed knowledge file wastes every provider call.

Direction: read and validate every input file first, then enrich.

### M-5. `--enrich --dry-run` still performs live third-party lookups

`src/case_analyzer/cli.py:101`

The README documents it, but "dry run" conventionally means no side effects, and the side
effect here is disclosing observable values to Cloudflare, ARIN, and VirusTotal.

Direction: at minimum print a stderr notice before the first request; better, make the
network access an explicit opt-in when `--dry-run` is set.

### M-6. The prompt says nothing about the enrichment block

`src/case_analyzer/prompts/investigation.md`

`case_analyzer_enrichment` reaches the model through `build_analysis_payload`
(`analyzer.py:39-45`), but none of the semantics the README is careful about are conveyed:
that `not_found`/`error` is not evidence of benignness, what `not_comparable` means, that
`comparison_with_case` is not a verdict, and that VirusTotal `last_analysis_stats` are
third-party votes rather than ground truth. The model currently improvises these rules.

Direction: add one paragraph to the system prompt. Highest value per line changed in the
repo, and it can be done independently of every other item here.

### M-7. Payload duplication is measurable and unbounded

`src/case_analyzer/adapters.py:59, 82`

Every adapter stores the full export in `source_data` in addition to the normalized fields.
Measured on `examples/splunk-soar.json`:

```
raw export        4,615 chars
LLM payload       6,995 chars  (1.52x)
normalized-only   2,323 chars  (all of which also appears inside source_data)
```

This is TODO item 1; the concrete options are a `--no-source-data` flag, emitting only the
`source_data` keys that normalization did not already cover, or truncating oversized arrays
with an explicit marker so the model knows content was elided.

### M-8. Analyzer robustness gaps

`src/case_analyzer/analyzer.py:73-99`

1. No `timeout=` passed to `ChatOpenAI`, so a hung gateway blocks for the openai-client
   default (600s). Consider a `--llm-timeout` flag. Note `max_retries=0` is deliberate and
   documented — keep it.
2. A missing API key surfaces as the opaque `LLM request failed (OpenAIError)` / exit 6.
   Mirror the explicit `selected_model` check at `:74-75` with an actionable exit-2 message.
3. `with_structured_output(...).invoke(...)` can raise `pydantic.ValidationError`, a
   `ValueError` subclass, which lands in the generic `cli.py:144` handler and may print raw
   model output. Wrap it as an `LLMProviderError` with its own exit code and truncated detail.

---

## Low severity / hygiene

- **L-1. Dead validation work.** `enrichment.py:225` computes `valid` and discards it;
  `:234` recomputes it from the normalized value. Group on the validated tuple instead.
- **L-2. `_existing_enrichment_context` truncates at every recursion level.**
  `enrichment.py:85` applies `[:3]` inside the recursion, so parent-level snippets can be
  dropped arbitrarily depending on nesting depth. Truncate once at the caller. The same
  function joins absent keys into a doubled space, visible in the recorded example output
  (`"Threat Intelligence Enrichment  Domain resolved..."`).
- **L-3. Truncation is arbitrary.** `enrichment.py:233` takes `items[:limit]` in dict
  insertion order — no prioritization (public over private, frequency of appearance) and no
  deterministic ordering across runs.
- **L-4. RDAP endpoint is hardcoded.** `enrichment.py:127` always queries `rdap.arin.net`;
  non-ARIN address space depends on redirect following, and `provider` still reports
  `arin-rdap` when another RIR actually answered. Consider the IANA RDAP bootstrap, or
  document the redirect dependency and record the responding authority.
- **L-5. No VirusTotal throttling.** The public tier allows roughly 4 requests/minute; 25
  observables will mostly return 429s recorded as `error` observations. Pairs with the
  caching item already in `TODO.md`.
- **L-6. VirusTotal doubles the observation count.** `--enrichment-limit` bounds unique
  observables, so the output can hold up to `2 x limit` observations. Not a bug, but worth
  stating in `--help` next to the flag.
- **L-7. Test discovery is broken and undocumented.** `tests/` has no `__init__.py`, so
  `uv run python -m unittest discover -s tests -t .` fails with
  `ImportError: Start directory is not importable`. Only `-t tests` or the explicit module
  form works. No test command is documented in `README.md` or `AGENTS.md`, and
  `pyproject.toml` has no dev dependency group for pytest/ruff.
- **L-8. Coverage gaps, all cheap because the seams already exist.** Untested:
  `adapters.py` in full (`detect_format`, the missing-`id`/`title` error path, every `_soar`
  fallback chain), `_http_json` status branches, `_validate` idna + trailing-dot handling
  (verified working: `"example.com." -> (True, 'example.com')`), VirusTotal eligibility for
  private IPs, the limit-vs-VirusTotal observation count, and `--output` file writing.
- **L-9. `explain_cli` forwards neither `--output` nor `--enrich`** (`explain_cli.py:36-44`).
  Acceptable for a deprecated alias slated for removal (`TODO.md` item 3), but worth a
  `--help` note until then.
- **L-10. Timestamps are `str`.** `schemas.py:17, 25` — `datetime` with a serializer would
  validate them and remove the manual `+00:00` → `Z` rewrite at `enrichment.py:28`.
- **L-11. `_json_file` has no size guard** (`cli.py:15-19`). Given the "Model and gateway
  limits" section of the README, consider rejecting or warning on inputs above a documented
  size rather than discovering the limit at the gateway.

---

## Suggested work order

1. **M-6** (prompt paragraph) — one paragraph, no code, independent of everything else, and
   it closes the gap between the README's documented semantics and what the model is told.
2. **H-5** (non-mapping body) — smallest change that removes a hard crash.
3. **H-1 + H-2 + H-3** together — they all live in the extraction path and share the
   provenance refactor (`declared` vs `inferred` kind). Doing them separately means touching
   `_walk_observables` three times.
4. **H-4 + M-1** together — both are `existing_case_context` attribution.
5. **M-3, M-4** — small, self-contained correctness fixes.
6. **L-7 + L-8** — make the suite discoverable, then add the regression tests that would
   have caught H-1, H-2, and H-5.
7. **M-2, M-5, M-7, M-8** — behavior and interface changes; worth confirming the intended
   UX before implementing, since M-5 and M-7 add or change flags.
8. Remaining **L** items as cleanup.

Items M-7 and L-5 are already reflected in `TODO.md`; the rest are new.
