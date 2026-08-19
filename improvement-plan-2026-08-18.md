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

### 1. Report provenance block

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

### 2. Enum-constrain the decision vocabulary

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

### 5. Response cache plus provider pacing

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

### 6. IDN (internationalized domain) handling

`_DOMAIN_RE` in `enrichment.py` is ASCII-only, so a Unicode-form IDN fails syntax
validation and is never looked up — the exact shape homograph attacks use. IDNA-encode
Unicode domains to punycode before validation (marking invalid on codec failure) and
record both forms in the observation.

### 7. Full-URL and email lookups

Via URLhaus/ThreatFox as TODO already plans. Sequence **after** item 5, since new
providers multiply request volume.

## Tier 3 — dedicated audit mode (design before code)

### 8. `--audit` mode

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
- Bake in "absent from the export = not documented, not proof it did not occur" as a
  schema-level distinction: `insufficient_evidence` vs `fail`.
- Ship offline first — schema tests, prompt tests, dry-run/explain support, one
  recorded example — before any live run, matching how `--summary` was rolled out.
- Require human review before the result can close a case or change a compliance
  record (documentation and exit-behavior, not auto-write-back).

## Tier 4 — structural, propose-and-discuss

### 9. Prompt-injection hardening — DONE, see status above

Implemented 2026-08-18 as a two-layer measured fix: an untrusted-data rule in both
system prompts, plus BEGIN/END payload delimiters via `render_payload_message` in
`analyzer.py`. Two recorded eval cases (verdict override, canary digest) in
`evals/manifest.json` re-measure resistance per model. The original proposal here
(measurement only) is superseded; the measured result is recorded in
[`evals/baseline-2026-08-18.md`](evals/baseline-2026-08-18.md).

### 10. Deduplicate `source_data`

Measured duplication is 1.52x on `examples/splunk-soar.json` (M-7). Rather than
dropping `source_data` (the model genuinely uses it), send only the source fields the
normalizer did not already lift, or a diff-style residue. Trickiest change to make
safely — measure token savings on the recorded examples before committing to it.

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
any code.

Progress (2026-08-19): items 3 and 4 are done. They were taken first because they were
the only Tier 1 items with no open review question — items 1 and 2 are blocked on review
points 1 and 2 (where provenance lives, and which API guarantees it), and Tier 2 item 5
is blocked on review point 3 (whether pacing waits consume the enrichment budget). Those
three decisions are the gate on everything remaining.

## Review — to be verified before implementation

The plan is close to implementation-ready, but these design details should be
resolved before work begins:

1. **Keep locally generated metadata out of the model-facing schema.** Adding
   `report_metadata` directly to `InvestigationReport` or `CaseSummary` while passing
   that schema to `with_structured_output()` would expose the field to the model and
   invite it to populate data that must be generated locally. (The `with_structured_output()`
   call named here is gone as of the LiteLLM SDK migration; the same schema is now passed
   as `response_format=`, so the concern is unchanged and only the API name is stale.) Prefer a locally
   constructed envelope such as `{report_metadata, report}`, or separate
   model-facing response schemas from the final saved-result schemas.
2. **Make the provenance guarantee part of the public execution path.** An optional
   `attach_provenance()` helper does not ensure that library callers use it; they can
   continue calling `analyze_case()` or `summarize_case()` directly. Either make the
   public methods return the assembled result or introduce a higher-level run API and
   state clearly which API guarantees provenance. The original-file hash must remain
   optional for callers that supply an already-parsed case rather than a file.
3. **Reconcile provider pacing with the enrichment budget.** At roughly one
   VirusTotal request every 15 seconds, only a few uncached requests fit within the
   current 60-second default budget. Define whether pacing waits consume that budget,
   whether excess requests become `skipped`, and how scheduling prevents a paced
   provider from starving faster providers. Atomic cache writes do not coordinate
   request start times across processes, so cross-process pacing needs an explicit
   lock or lease if it is intended to be stronger than best-effort.
4. **Specify IDN normalization behavior.** Choose and document the applicable IDNA
   standard or library (for example, modern UTS #46 processing versus Python's
   built-in codec), because their handling of some Unicode domain names differs.
