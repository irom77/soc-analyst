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

## Included guidance

- [`evidence-quality.txt`](evidence-quality.txt) checks evidence coverage,
  corroboration, contradictions, and missing telemetry.
- [`closure-readiness.txt`](closure-readiness.txt) asks whether the evidence supports
  the recorded disposition and whether follow-up work remains.
- [`response-process.txt`](response-process.txt) checks whether the exported case
  records expected investigation and response actions.

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
