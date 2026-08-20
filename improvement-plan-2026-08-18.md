# Improvement Plan — 2026-08-18

Status: **updated 2026-08-18 after the eval-harness branch**. Two things changed
since the draft: the eval prerequisite and the injection item are done and measured.

- **Done — eval harness.** `case-analyzer-evals` with `evals/manifest.json` (the
  three reasoning cases, the ip-verdict audit case, and two new prompt-injection
  cases), `--samples` agreement measurement, field-scoped forbidden-content checks,
  and offline tests. See [`evals/README.md`](evals/README.md).
- **Done — item 9 (prompt-injection hardening), upgraded from "measurement" to
  "measured fix".** The recorded baseline showed the configured model following
  case-embedded instructions in 6 of 6 injection samples. An untrusted-data rule in
  both system prompts plus BEGIN/END payload delimiters closed it: the full
  benchmark now passes 18 of 18 samples with no regressions detected by the
  six-case benchmark (passing it does not establish complete correctness; see
  the caveats in the writeup). Recorded in
  [`evals/baseline-2026-08-18.md`](evals/baseline-2026-08-18.md).
- **Answered — the open agentic question.** On current evidence, adversarial review
  and self-consistency modes are not justified: the one demonstrated failure class
  was fixed by hardening alone, and the failing runs showed 100% sample agreement
  (consistently wrong), which repeat sampling cannot detect. The benchmark is the
  tripwire for revisiting this.

The remaining tiers below are unchanged and still the roadmap. No other code changes
have been made. This plan follows the
limitations review of the same date and is ordered by leverage-to-effort ratio. It is
shaped to fit the repository's conventions: surgical changes, offline tests first,
recorded examples preserved, `uv` for all commands.

Related documents: [`code-review-2026-08-17.md`](code-review-2026-08-17.md) (prior
review, all findings implemented), [`TODO.md`](TODO.md) (items 5, 7, and 8 below
overlap with existing entries).

## Tier 1 — small changes, outsized audit value

### 1. Report provenance block — DONE (2026-08-19)

Implemented as `CaseAnalyzerRun` in `schemas.py`, built by the new `provenance.py`, and
attached by `analyze_case`/`summarize_case` themselves. The two review points below
decided the shape:

- **Review point 1** (keep it out of the model-facing schema) is resolved by separating
  the request schema from the saved-result schema, the second option the point offers.
  `InvestigationReport` and `CaseSummary` remain exactly what goes out as
  `response_format`; `AnalyzedReport` and `AnalyzedSummary` subclass them and add
  `case_analyzer_run`. A test asserts the request schemas never grow the field, and
  another asserts the provider is asked for the base class.
- **Review point 2** (make the guarantee part of the public path) is resolved by
  attaching in the public functions rather than in an optional `attach_provenance()`.
  There is no unprovenanced supported call: `_request_structured` is the raw primitive
  and is private. The eval harness and library callers were provenanced without any
  change to their code.

A subclass was chosen over the `{report_metadata, report}` envelope the point sketched,
because the envelope is not additive: it moves every existing field down a level, so
recorded examples stop being valid input to the same readers and every downstream
consumer of the CLI's stdout breaks. The subclass keeps the plan's "purely additive"
requirement literally true.

Recorded as specified, with two clarifications the implementation forced: the endpoint
is stored as host and port only, because a base URL can carry credentials in its
userinfo and a token in its query; and `package_version` records `"unknown"` rather than
a guess when running from an uninstalled source tree.

This also closed the two pieces deferred from item 4. The post-check now runs inside
`analyze_case`, so its result is recorded in `case_analyzer_run.checks` — the "flagged
in the run output" half — and the eval harness picks it up for free. `checks.ran` is
kept separate from `checks.problems`: a `--summary` run has nothing to check, which must
not read as a clean result. The benchmark records the checks without scoring them;
pass/fail stays the manifest's verdict, confidence, and forbidden-content rules.


Add an optional `report_metadata` (or `case_analyzer_run`) field to
`InvestigationReport` and `CaseSummary`, filled in **locally, never by the model**.
Attach it in a shared run-assembly helper (e.g. an `attach_provenance(report, ...)`
step next to `analyze_case`) used by the CLI, the eval harness, and library callers
alike — `analyze_case`/`summarize_case` are public APIs and the eval harness calls
them directly, so a CLI-only implementation would leave those reports unprovenanced
and break "any saved report becomes self-describing". Record:

- model name and base URL host (never the key),
- SHA-256 of the rendered request payload (the exact delimited human message) and of
  the system prompt — these identify the complete effective input, which the raw
  file does not, since the model sees the normalized case plus optional enrichment,
  knowledge, and user input,
- SHA-256 of the original input file, kept as a separate field,
- package version plus a report schema version identifier,
- run timestamp,
- whether enrichment, knowledge, and user input were present (convenience flags,
  not the identity of the input — the payload hash is).

Any saved report becomes self-describing for audit purposes ("which model, with which
prompt, said this about which exact input"). Purely additive: keep the field optional so
existing recorded examples stay valid. Entirely testable offline.

### 2. Enum-constrain the decision vocabulary — DONE (2026-08-19)

Implemented with the value sets signed off as proposed: `verdict` is
`Literal["True Positive", "Suspicious", "False Positive", "Benign", "Insufficient Data"]`
and `confidence` is `Literal["Low", "Medium", "High"]`, in the Title Case every recorded
run and every eval case already used. `severity`, `impact`, and `priority` stay free
strings for the reason the item anticipated, now with evidence: the recorded SOAR exports
carry `critical`, `informational`, and lowercase spellings, so a closed set there would
constrain the source platform's data model rather than this tool's decisions.

An off-list value fails schema validation like any other malformed response —
`LLMProviderError`, exit 6, no report — which is what makes the vocabulary a contract
rather than a suggestion. The sanitized error names the field and not the rejected
wording, matching the existing error contract.

All seven previously recorded reports validate against the closed schema untouched,
which is the evidence that this writes down existing behavior rather than imposing new
behavior; a test asserts it and doubles as the regression guard for any future change to
the sets. Another test asserts the prompt names exactly the enum values, since drift
between them would make every run fail.

Unlike items 1, 3, and 4, this one is provider-visible: it changes the JSON schema sent
as `response_format`. The live run in [`examples/provenance/`](examples/provenance/README.md)
confirms the configured provider accepts it and returns canonical values.


Make `verdict` a `Literal["True Positive", "Suspicious", "False Positive", "Benign",
"Insufficient Data"]` and constrain `confidence` (e.g. low/medium/high). Because the
schema is enforced through `with_structured_output`, this moves vocabulary stability
from prompt suggestion to contract, making runs comparable and downstream automation
safe. Leave `severity`/`priority` as free strings initially if source platforms vary
too much. **Open decision:** final value sets need user sign-off.

### 3. Signal list truncation in the report — DONE (2026-08-19)

Implemented as `InvestigationReport.truncated_fields: list[TruncationNote]`, one entry
per shortened list. `field` is enum-constrained to the seven capped collections, so the
model cannot name a list that does not exist, and `LIST_CAPS` in `schemas.py` records
the caps the prompt states — a test asserts the two agree. `omitted_count` is a plain
`int` defaulting to 0 rather than `int | None`: an optional int renders as
`anyOf: [integer, null]`, which strict structured-output modes handle unevenly, and a
note only exists when a list *was* truncated, so 0 reads as "count not estimated".
`checks.py` flags the one contradiction a response can expose — a list reported as
truncated while sitting below its cap. Under-reporting stays undetectable, as the
original note anticipated.


The investigation prompt caps list sizes (5 findings, 10 IOCs, 8 timeline events, …).
Add per-list metadata rather than a single boolean — e.g.
`truncated_fields: list[str]` naming each capped collection, optionally with an
omitted count per field — so a large incident cannot silently masquerade as a small
one *and* the reader knows which list to go back to the source for. Do not route
this through `unknowns`: that list is itself capped, and it would mix missing
evidence with presentation loss. Note in the field description that this is
model-reported truncation — it cannot be deterministically verified from the
response alone.

### 4. Evidence citations by JSON path — DONE (2026-08-19)

Implemented as `EvidenceFinding.source_paths`, with the grammar pinned as specified and
`checks.resolve_case_path` as the deterministic post-check. The live run in
`examples/citations/` found the spec had one gap the plan did not anticipate: "rooted at
the payload's `case` object" reads naturally as "starts with `case.`", and the model
wrote all 16 citations that way, so every correct citation was reported as a defect. The
prompt now says explicitly not to write the root segment, and the resolver accepts the
prefixed spelling only after the canonical form fails, so a genuine top-level key named
`case` is never shadowed.

Partially delivered against the original wording: unresolved citations are reported on
stderr but not yet *flagged in the run output*, because there is no run output to flag
them in until item 1's envelope exists — putting the result on `InvestigationReport`
would make it model-facing, which review point 1 rules out. For the same reason the
check is wired into the CLI only; the eval harness calls `analyze_case()` directly and
so does not run it. Both land with items 1–2.


Add optional `source_paths: list[str]` to `EvidenceFinding` (align with the existing
`TimelineEvent.evidence_field`), instructing the model to cite the case JSON paths each
finding relied on. Pin down the path contract before implementing — the enrichment
`source_paths` are path-like strings, not formal JSONPath, so without a spec two
implementations could emit incompatible paths or "validate" by matching an unrelated
field:

- grammar: dotted object keys with `[n]` list indices, rooted at the payload's
  `case` object, matching what enrichment observations already emit;
- the synthetic `#host`/`#domain` suffixes are markers, not traversable segments —
  the checker strips a trailing `#…` fragment before resolving;
- a missing citation is permitted (absence means "uncited", not "invalid");
- unresolved citations are reported on stderr by the post-check and flagged in the
  run output, never silently dropped.

Then the **local, deterministic post-check** in the shared run-assembly layer
verifies each cited path resolves in the rendered payload. Converts "trust the
prose" into "spot-checkable claims" with no second LLM call.

## Tier 2 — enrichment robustness (partly tracked in TODO.md)

### 5. Response cache plus provider pacing — DONE (2026-08-19)

Implemented as `enrichment_cache.py` (`EnrichmentCache`, `ProviderPacer`), wired into
`enrich_case` and exposed as `--cache-dir` / `--no-cache`. Built as specified: the
fingerprint is provider, endpoint-and-parameters (one `request_id` string per provider,
with a version marker to retire entries when the request or the stored detail set
changes), observable type, and value; writes are atomic; TTL is per provider — 15 minutes
for DNS, an hour for reputation, a day for registration data; cache hits record
`"cache": true`.

Three things the implementation settled that the item left open:

- **Only settled answers are cached.** `error` and `skipped` are not. Caching an error
  would freeze a timeout or an HTTP 429 — the very failure this item exists to fix — into
  every later run.
- **A cache hit keeps the original `retrieved_at`.** Stamping it with the run's time
  would have a saved block claim it had just fetched hour-old data. The run's own time is
  already `generated_at` on the block.
- **The stored fingerprint is re-checked on read**, not trusted from the file name, so a
  layout change or a truncated write reads as a miss rather than as an answer about a
  different observable.

**Review point 3, resolved.** Signed off 2026-08-19:

- *Pacing waits consume the budget.* `--enrichment-budget` is documented as a wall-clock
  bound on enrichment and already caps each request's timeout; a free wait would let a run
  quietly outlast the limit the operator set, which is worse than skipping because it is
  invisible. The consequence is real and is documented rather than hidden: at 15s spacing,
  about four uncached VirusTotal lookups fit in the 60s default.
- *Overflow becomes `skipped`*, with a reason naming the interval — distinct from budget
  exhaustion and from a circuit-breaker skip — and sets `stopped_early`. Nothing failed,
  so it is not an error. A refused reservation claims no slot, so the time stays available
  to a lookup that can still use it.
- *Starvation is removed rather than mitigated.* Lookups now run in two passes: every
  unpaced provider (DNS, RDAP) completes before the first paced reservation is made, so a
  worker sleeping out a rate limit can never hold a thread a keyless lookup needed. The
  cost is the overlap given up between passes, which is small because cached reputation
  answers never reach the pacer at all. Measured offline over nine observables with a 5s
  budget and a 2s interval: 9 of 9 RDAP lookups completed, 3 VirusTotal requests fit, 6
  were paced out, and the run finished inside the budget.
- *Cross-process pacing stays best-effort*, as the point anticipated. The claim is written
  to the cache directory with no lock or lease, so two processes reserving at the same
  instant can both proceed; the provider's 429 is the backstop. Documented on the class
  and in the README rather than closed, because a real lease is more machinery than a
  courtesy rate limit warrants.

One consequence worth stating plainly: the cache writes observable values from cases —
addresses, domains, file hashes — and provider answers about them outside the case file,
in the clear. Readability is the point, since a cache that cannot be inspected cannot be
audited, but the directory now deserves the same handling as the cases. `--no-cache` is
the answer where that is not acceptable.


Small on-disk cache keyed by a canonical request fingerprint — provider, endpoint,
observable type and value, and request parameters — with a per-provider TTL.
"Provider + observable" alone can collide across observable types, endpoints, or
future provider API versions. Because enrichment runs concurrent workers, cache
writes must be atomic (write-then-rename), and the minimum request interval for
VirusTotal (~15 s for the public 4/min tier) must be enforced per provider *across*
workers via shared state — a per-worker sleep still allows simultaneous requests.
Cross-process pacing is best-effort through the cache directory; document that
bound. Fixes the documented real-world failure (HTTP 429 on a second run minutes
later; see TODO) and the duplicated-cost concern in one change. `--cache-dir` for
the path, `--no-cache` to opt out, and record `"cache": true` in observation details
so provenance stays honest.

### 6. IDN (internationalized domain) handling — DONE (2026-08-19)

The item's premise was partly stale. `_validate` already punycoded domains before
matching `_DOMAIN_RE`, added with the original enrichment work (`2f31821`), so Unicode
names were being looked up rather than discarded. Two things were genuinely missing: the
standard was never chosen (review point 4), and only the encoded form was recorded.

**Standard: UTS #46, nontransitional, via the `idna` package.** The decisive case is
`faß.de`. Python's built-in `"idna"` codec is IDNA 2003, whose transitional mapping
encodes it to `fass.de` — a different domain, which someone else may own. The tool would
then look up one name, and present the answer as being about another; for an enrichment
step whose whole purpose is attribution, that is a correctness bug rather than a
strictness preference. Nontransitional is also what current browsers resolve with, so
what is validated here matches what the user's browser would have reached.

The switch was measured before it was made: across the realistic host values the test
suite covers — NetBIOS names, `srv-dc01`, `localhost`, literal addresses, underscored
labels, over-long labels, leading and trailing hyphens, trailing dots, mixed case, and
ordinary IDNs — the two standards produce the **same valid/invalid outcome for every
one**. They diverge on transitional mappings (the reason for the change) and on emoji
labels, which IDNA 2003 accepts and UTS #46 rejects; an emoji domain is now marked
invalid and not looked up. `idna` was already installed as a transitive dependency of
`httpx`/`requests`, so declaring it direct adds an import, not an install.

**Both forms** are recorded as `EnrichmentObservation.unicode_values`: `value` stays the
punycode form and the list carries the non-ASCII spellings the case used, empty when the
case wrote the name in ASCII. It is a list rather than a single field because more than
one spelling can encode to the same name — case, width, and ignorable characters all
collapse — and keeping only the first would silently drop the others.

One honest limit is documented on the field itself: this is provenance, not a
homograph verdict. Two confusable spellings render identically in `unicode_values`, so a
reader comparing them against a legitimate domain by eye can be fooled exactly as the
original victim was. The reliable signal that a name was not plain ASCII is the `xn--`
prefix on `value`. Deriving an actual confusability judgment — mixed-script labels within
a single label being the usual signature — is a separate piece of work and is not
attempted here.

### 7. Full-URL and email lookups — DONE (2026-08-19)

Implemented as two new observable types. `EnrichmentObservation.observable_type` gained
`url` and `email`, and a URL or email field now emits **both** the value itself and the
host or domain derived from it, rather than the derived part standing in for the whole.
That is the point of the item: a whole URL and its host are different questions with
different providers, and a single malicious path on an otherwise ordinary host is exactly
where the difference decides the answer.

**With the qualification that `--enrichment-limit` still cuts.** Both observables are
always emitted, but they are then sorted and truncated independently, so a tight limit can
keep one and drop the other: at `--enrichment-limit 1` an inferred URL field leaves only
the derived host, and a declared one leaves only the URL. What `_priority` does guarantee
is narrower — an observable no configured provider can answer is tiered below one that can,
so it never displaces a real lookup. "Neither substitutes for the other" describes what is
extracted, not what survives a limit small enough to cut the pair in half.

**URLhaus is the URL provider**, gated on `ABUSE_CH_AUTH_KEY` and sent as the `Auth-Key`
header with the URL as a POST form body — the only shape the abuse.ch API accepts, and the
reason `_http_json` grew an optional `form` argument. It answers HTTP 200 for a refused
query as well as for a hit, so the outcome is read from `query_status` and never from the
status code: `ok` is `found`, `no_results` is `not_found`, and `invalid_url` or a rejected
key is an `error` — a failure of the lookup rather than a statement about the URL.
VirusTotal covers URLs as well, addressed by the unpadded URL-safe base64 identifier its
API requires instead of a percent-encoded path segment. Both are recorded separately and
marked `inconclusive`, like every other reputation source here.

Three things the implementation settled that the item left open:

- **Userinfo is stripped from a URL before it is looked up or recorded.** An export can
  carry `https://user:password@host/path`, and this value is sent to a third-party API and
  written to the on-disk cache in the clear. This follows the rule already set by
  `CaseAnalyzerRun.endpoint_host`, which records a host and port and never the userinfo.
  Nothing else about the URL is rewritten: the path, query, and fragment are preserved
  byte-for-byte, because a distribution URL's identity lives in its path, and only the
  scheme, host, an implied port, and an empty path are normalized. The original text stays
  reachable through `source_paths`.
- **Email addresses are recorded but never looked up.** No free provider worth trusting
  covers an address, and inventing a lookup for one would be worse than saying so: the
  observation carries `lookup_status: "skipped"` with a reason, and the domain half is
  enriched as its own observable. The value is provenance — the addresses appear in the
  enrichment block with their source paths — rather than enrichment.
- **An uncoverable observable never costs a lookup.** Email observables, and URL
  observables when no URL provider is configured, sort into the same priority tier as a
  non-global IP, so `--enrichment-limit` truncation drops them before anything a provider
  could have answered for.

**ThreatFox was deliberately not added here.** Its value is domain and IP IOC matching,
which is the separate provider-evaluation item in `TODO.md`, and adding two providers in
one change would double the surface for no gain against this item's own goal. URLhaus is
the URL-specific provider the item and the TODO both name.

URLhaus is unpaced: abuse.ch publishes fair-use terms rather than a per-minute rate, so it
runs in the unpaced first pass alongside DNS and RDAP and cannot be starved by
VirusTotal's spacing. Its responses are cached under their own request id with the
one-hour reputation TTL — which is what item 5 was sequenced ahead of this one to provide,
and it needed no change to accept a fourth provider.

Verified offline only. 198 tests pass; a synthetic case carrying a credentialed
internationalized URL, an internationalized address, and an unparsable URL produced the
expected observations with the credential removed and both punycode encodings applied. No
live abuse.ch or VirusTotal request was made, and no recorded example was regenerated.


Via URLhaus/ThreatFox as TODO already plans. Sequence **after** item 5, since new
providers multiply request volume.

## Tier 3 — dedicated audit mode (design before code)

### 8. `--audit` mode — DONE (2026-08-20), shipped offline

As sketched in TODO.md; keep v1 scope tight:

- Separate system prompt (`prompts/audit.md`) and a `CaseAuditReport` schema:
  per-control entries with `control_id`,
  `status: Literal["pass", "fail", "not_applicable", "insufficient_evidence"]`,
  `evidence_paths` (machine-checkable, per item 4), and `rationale`; top-level
  `policy_refs` and `documented_exceptions`.
- Controls supplied as versioned `--knowledge` records with a declared shape,
  validated **before the LLM request**: `control_id` values must be unique and
  non-empty, otherwise "exactly one response per control" is ambiguous. The CLI then
  validates **deterministically** that every supplied control received exactly one
  response entry and rejects response entries naming unknown controls (coverage
  check in Python, not trusted to the model).

  "Rejects" needs to be read precisely: a coverage defect does not suppress the report,
  which would throw away the only evidence of what went wrong. It is reported in
  `checks.problems`, echoed on stderr, and exits `7` so that no caller can mistake an
  incomplete audit for a complete one. The report is written and marked, not withheld.
- Bake in "absent from the export = not documented, not proof it did not occur" as a
  schema-level distinction: `insufficient_evidence` vs `fail`.
- Ship offline first — schema tests, prompt tests, dry-run/explain support, one
  recorded example — before any live run, matching how `--summary` was rolled out.
- Require human review before the result can close a case or change a compliance
  record (documentation and exit-behavior, not auto-write-back).

Built as specified, with every bullet above implemented: `prompts/audit.md`, a
`CaseAuditReport` of `ControlAssessment` entries, `controls.py` validating the set before
the request, and `check_audit` in `checks.py` doing coverage in Python. 61 offline tests.
Shipped without a live run, matching the `--summary` rollout; the recorded example in
[`examples/audit/`](examples/audit/README.md) is a `--dry-run --explain` preview rather
than model output, and is labeled as such.

**The control record shape is provisional and was designed, not observed.** It follows the
requirements written down in `examples/user-input-case-audit/README.md` — named controls,
per-control status, citations, policy versions, exceptions — because no real policy export
was available to design against. Three decisions carry the risk, each pinned by a test so
it cannot drift silently:

- **Controls are flat.** Nesting is precisely what makes "exactly one assessment per
  control" ambiguous, which the item calls out as the reason to validate uniqueness at
  all. Sub-controls are flattened into distinct ids when records are prepared.
- **Identity is `(policy_ref, control_id)`,** so two policies can each number a control
  `4.2` in one run; it degrades to the bare id for a single policy. Narrowing this later
  to `control_id` alone is a breaking change for multi-policy sets.
- **`applies_when` is optional, and a rationale is mandatory for every status.**
  `not_applicable` is the one status producing neither a finding nor a gap, so leaving it
  unexplained would make it the cheapest exit from a control the model could not evidence.

What that leaves unproven is what the offline suite cannot reach: whether a real control
set parses without reshaping, and whether the model actually holds the
`fail`/`insufficient_evidence` line under a case whose text asserts its own compliance.
The prompt addresses the second and the injection hardening from item 9 applies, but
neither has been measured here. A live run against a real control set is the next step,
and the eval harness has no audit cases yet.

## Tier 4 — structural, propose-and-discuss

### 9. Prompt-injection hardening — DONE, see status above

Implemented 2026-08-18 as a two-layer measured fix: an untrusted-data rule in both
system prompts, plus BEGIN/END payload delimiters via `render_payload_message` in
`analyzer.py`. Two recorded eval cases (verdict override, canary digest) in
`evals/manifest.json` re-measure resistance per model. The original proposal here
(measurement only) is superseded; the measured result is recorded in
[`evals/baseline-2026-08-18.md`](evals/baseline-2026-08-18.md).

### 10. Deduplicate `source_data` — DONE (2026-08-20), shipped opt-in

Implemented as `source_data_residue()` in `adapters.py`, applied in
`build_analysis_payload` and exposed as `--reduce-source-data`, **off by default**. The
measurement the plan asked for is in
[`evals/source-data-residue-2026-08-20.md`](evals/source-data-residue-2026-08-20.md) and
changed the shape of the item in three ways:

- The 1.52x figure understates the duplication and overstates the saving. `source_data` is
  75% of the payload across the recorded examples, but residue recovers only 14% of those
  characters — 25.7% on the benchmark corpus, 23% on `splunk-soar.json`, and **1%** on
  `unknown.json`, the largest payload, whose bulk is a `raw`/`parsed` pair duplicated
  *inside* `source_data` where a top-level filter cannot see it. Collapsing those pairs is
  a separate problem, not this one.
- "The model genuinely uses it" is truer than the parenthetical suggests. Four of the six
  benchmark cases lift zero artifacts and zero alerts; their evidence sits in
  `child_containers`, which no adapter descends into. Dropping `source_data` outright would
  delete the evidence base for most of the corpus, so the residue shape is what makes the
  change safe rather than a stylistic preference.
- The reduction cannot happen in the adapter. `enrichment.py` walks `case.source_data` and
  roots `source_paths` there, so the stored case stays whole and only the sent copy shrinks.

Benchmarked at three samples: six of six pass, both injection cases hold, and neither of
the two cases that moved reasoned worse — `scary-words-benign` chose `False Positive` over
`Benign` on the same digest, and `ip-verdict-claim` kept its verdict with more evidence
findings. It ships off by default because two of six moving is not behaviour-neutral, and
three samples cannot promise a seventh case would not.

Original text: measured duplication is 1.52x on `examples/splunk-soar.json` (M-7). Rather
than dropping `source_data` (the model genuinely uses it), send only the source fields the
normalizer did not already lift, or a diff-style residue. Trickiest change to make safely —
measure token savings on the recorded examples before committing to it.

### 11. Context-overflow strategy

For cases over `--max-input-bytes`, an explicit `--truncate-strategy` (e.g. drop
oldest timeline entries first, cap artifact bodies) that **records what was dropped**
in the provenance block — never silent. A two-pass summarize-then-analyze mode is the
alternative; hold off until someone actually hits the limit, since a second LLM call
changes the cost model.

## Deliberately out of scope

- **Automatic LLM retries** — cost discipline is a stated design choice.
- **Auto-write-back to source platforms** — human-in-the-loop is the correct posture
  given non-deterministic verdicts.
- **Keyword-search knowledge layer** — would re-import the Django/database dependency
  the standalone tool exists to avoid.

## Suggested sequencing

Start with Tier 1: items 1, 3, and 4 are pure additions; item 2 needs only the enum
value decision. Item 8 deserves its own design pass against a real control set before
any code. (All of Tier 1 is now done; see the progress note below.)

Progress (2026-08-19): items 3, 4, and 1 are done. Items 3 and 4 were taken first
because they were the only Tier 1 items with no open review question; item 1 followed
once review points 1 and 2 were decided, which is recorded under the item itself.

Tiers 1 and 2 are complete — items 5, 6, and 7 all landed on 2026-08-19 — and every review
point is resolved. Item 7 was sequenced after item 5 for a reason that held up: the cache
and pacing absorbed a fourth provider without a change, so URLhaus multiplied neither the
request volume nor the machinery.

Benchmark re-run (2026-08-20): the tripwire was fired before starting Tier 3, because four
of the six commits since the last recorded run change what the model is asked to produce
(citations, truncation reporting, the verdict/confidence enums, and sanitized errors). All
six cases pass and the provenance, citation, and truncation fields are confirmed populated
on live output for the first time. Read that as the tripwire not firing, not as evidence of
equivalence: six cases at three samples can catch a change that breaks a manifest or a
post-check, and cannot resolve a shift in reasoning quality either way. Recorded in
[`evals/post-tier-2-2026-08-20.md`](evals/post-tier-2-2026-08-20.md). The harness never
contacts enrichment providers, so items 5, 6, and 7 were checked separately the same day
against live DNS, RDAP, and AbuseIPDB
([`examples/live-enrichment/`](examples/live-enrichment/README.md)): item 6's UTS #46
encoding is confirmed by a test that could have failed, item 5's cache is confirmed, and
the run exposed a credential leak in `unicode_values` that is now fixed. URLhaus was then
confirmed against the real API: all four outcomes return HTTP 200 and only `query_status`
separates them, so the implementation needed no change, and one field produced a URLhaus
`malware_download` hit alongside an AbuseIPDB score of 3 for its host — the case for
treating a URL and its host as separate observables, observed rather than argued. Item 5's
pacer was then confirmed by wall clock — 7 VirusTotal attempts predicted 93.7s and the run
took 93.90s — but VirusTotal's quota was exhausted, so item 7's base64 URL identifier is
the one enrichment path still resting on a fixture and needs a key with quota available.

What remains: Tier 3 item 8 (`--audit` mode) still needs its own design pass against a
real control set before any code. Item 10 landed opt-in on 2026-08-20; Tier 4 item 11
remains propose-and-discuss, and the plan's own advice on it is to wait until someone
actually hits the input limit — though item 10's measurement found the raw/parsed
duplication inside `source_data` that would matter most if they did. Outside
this plan, `TODO.md` still carries the remaining provider evaluation (ThreatFox,
GreyNoise Community), which item 7 deliberately left alone.

## Review — to be verified before implementation

The plan is close to implementation-ready, but these design details should be
resolved before work begins:

1. **Resolved (2026-08-19).** **Keep locally generated metadata out of the model-facing schema.** Adding
   `report_metadata` directly to `InvestigationReport` or `CaseSummary` while passing
   that schema to `with_structured_output()` would expose the field to the model and
   invite it to populate data that must be generated locally. (The `with_structured_output()`
   call named here is gone as of the LiteLLM SDK migration; the same schema is now passed
   as `response_format=`, so the concern is unchanged and only the API name is stale.) Prefer a locally
   constructed envelope such as `{report_metadata, report}`, or separate
   model-facing response schemas from the final saved-result schemas.
2. **Resolved (2026-08-19).** **Make the provenance guarantee part of the public execution path.** An optional
   `attach_provenance()` helper does not ensure that library callers use it; they can
   continue calling `analyze_case()` or `summarize_case()` directly. Either make the
   public methods return the assembled result or introduce a higher-level run API and
   state clearly which API guarantees provenance. The original-file hash must remain
   optional for callers that supply an already-parsed case rather than a file.
3. **Resolved (2026-08-19).** **Reconcile provider pacing with the enrichment budget.** At roughly one
   VirusTotal request every 15 seconds, only a few uncached requests fit within the
   current 60-second default budget. Define whether pacing waits consume that budget,
   whether excess requests become `skipped`, and how scheduling prevents a paced
   provider from starving faster providers. Atomic cache writes do not coordinate
   request start times across processes, so cross-process pacing needs an explicit
   lock or lease if it is intended to be stronger than best-effort.
   Answered under item 5: waits consume the budget, overflow is `skipped` with a reason
   naming the interval, starvation is removed by running unpaced providers to completion
   first, and cross-process pacing is documented as best-effort rather than made stronger.
4. **Resolved (2026-08-19).** **Specify IDN normalization behavior.** Choose and document the applicable IDNA
   standard or library (for example, modern UTS #46 processing versus Python's
   built-in codec), because their handling of some Unicode domain names differs.
   Answered under item 6: UTS #46 nontransitional via the `idna` package, chosen because
   IDNA 2003's transitional mapping can encode to a different domain than the case
   recorded. The two were compared on the suite's realistic host values first; they
   agreed on every validity outcome there.
