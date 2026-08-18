# Case-audit guidance with `user_input`

These examples use `--user-input` to focus the normal case investigation on audit
questions. They do not introduce a separate audit mode: the analyzer still applies
the investigation system prompt and returns an `InvestigationReport`.

Preview any example without contacting an LLM:

```bash
uv run case-analyzer examples/splunk-soar.json \
  --format soar \
  --user-input "$(< examples/user-input-case-audit/evidence-quality.txt)" \
  --explain \
  --dry-run
```

Remove `--dry-run` to run the analysis after provider credentials are configured.
The command makes one provider-backed LLM request. To save a new result without
overwriting the recorded examples:

```bash
uv run case-analyzer examples/splunk-soar.json \
  --format soar \
  --user-input "$(< examples/user-input-case-audit/closure-readiness.txt)" \
  --output case-audit-closure-readiness.json
```

## Unsupported IP-verdict claim

[`ip-verdict-claim.json`](ip-verdict-claim.json) is a synthetic closed case whose
name, description, tags, severity, and analyst note repeatedly call `8.8.8.8`
malicious. The export contains the IP value but no connection record, detection
details, payload behavior, affected asset, or independently corroborated threat
intelligence. It tests whether the analyzer audits the evidence behind the recorded
`True Positive` disposition instead of treating repeated verdict words as proof.

Use [`ip-verdict-claim.txt`](ip-verdict-claim.txt) for both sides of the comparison:

```bash
uv run case-analyzer examples/user-input-case-audit/ip-verdict-claim.json \
  --format soar \
  --user-input "$(< examples/user-input-case-audit/ip-verdict-claim.txt)" \
  --output /tmp/ip-verdict-without-enrichment.json

uv run case-analyzer examples/user-input-case-audit/ip-verdict-claim.json \
  --format soar \
  --user-input "$(< examples/user-input-case-audit/ip-verdict-claim.txt)" \
  --enrich \
  --output /tmp/ip-verdict-with-enrichment.json
```

See the [recorded comparison](ip-verdict-comparison.md) and the corresponding
[without-enrichment](ip-verdict-analysis-without-enrichment.json) and
[with-enrichment](ip-verdict-analysis-with-enrichment.json) reports. The recorded run
rejected the unsupported `True Positive` wording in both cases, while also exposing
an important confidence-calibration issue discussed in the comparison.

Both commands make a live LLM request; the second also sends the public IP to RDAP
and to any configured reputation providers. Provider results and model wording can
change. RDAP ownership or a reputation service with no reports may weaken or
contradict the case narrative, but neither proves that traffic was benign, that the
address was not abused, or that a logged source address was not spoofed. A sound audit
should therefore separate the unsupported recorded verdict from the factual ownership
and reputation observations, identify the missing primary telemetry, and recommend a
verdict no stronger than the available evidence permits.

This scenario also overlaps with the
[`reasoning`](../reasoning/README.md) examples because it tests resistance to
conclusion-laden wording. It lives here because its direct question is whether an
existing analyst disposition is adequately supported; the paired enrichment run
shows how later evidence should affect that audit.

## Included guidance

- [`evidence-quality.txt`](evidence-quality.txt) checks evidence coverage,
  corroboration, contradictions, and missing telemetry.
- [`closure-readiness.txt`](closure-readiness.txt) asks whether the evidence supports
  the recorded disposition and whether follow-up work remains.
- [`response-process.txt`](response-process.txt) checks whether the exported case
  records expected investigation and response actions.
- [`ip-verdict-claim.txt`](ip-verdict-claim.txt) audits a malicious-IP conclusion
  against the actual telemetry and optional enrichment.

Use these prompts for analyst assistance, triage quality checks, or a pre-closure
review. The model must treat an action that is absent from the export as **not
documented**, not as proof that the action did not happen. A human should review the
result before it changes a case or closes an incident.

## When `user_input` is enough

`user_input` is a good fit when the desired result is still an incident analysis and
the audit questions only change its emphasis. No system-message or human-message code
change is required: the CLI adds this text to the generated `HumanMessage` alongside
the normalized case, while the existing system prompt continues to enforce evidence
grounding and prevent invented facts.

It is not enough for a formal or automated compliance audit that needs named controls,
per-control pass/fail/not-applicable status, citations, policy versions, exceptions,
or an approval trail. The current structured response has no fields for those items,
and `user_input` cannot change the `InvestigationReport` schema. That use case should
add a dedicated audit mode with its own system prompt and response schema. Applicable
policies or control definitions should be supplied as versioned `--knowledge` records;
they should not be embedded permanently in the general investigation prompt.
