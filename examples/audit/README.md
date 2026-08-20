# `--audit`: control-by-control compliance assessment

`--audit` assesses a case against a set of controls supplied with `--knowledge` and
returns a `CaseAuditReport`: one entry per control, each with a status, a rationale, and
cited evidence paths. It is the dedicated mode that
[`../user-input-case-audit/`](../user-input-case-audit/README.md) says `user_input` cannot
provide — that approach still returns an `InvestigationReport`, which has no fields for
named controls, per-control status, policy versions, or exceptions.

Preview a run without contacting an LLM:

```bash
uv run case-analyzer examples/splunk-soar.json \
  --format soar \
  --audit \
  --knowledge examples/audit/controls.json \
  --explain --dry-run
```

The recorded output of exactly that command is
[`splunk-soar-audit-explain.txt`](splunk-soar-audit-explain.txt). Remove `--dry-run` to
make one provider-backed request. To save a result without overwriting anything recorded
here, pass `--output case-audit-result.json`.

## Status vocabulary

`status` is a closed set of four, and the split that matters is the last two:

| Status | Means |
|---|---|
| `pass` | The case records evidence satisfying the requirement. |
| `fail` | The case records evidence the requirement was **not** met. |
| `not_applicable` | The control's `applies_when` condition is not met by this case. |
| `insufficient_evidence` | The export does not record enough to decide. |

**Absence from an export is `insufficient_evidence`, not `fail`.** A case with no recorded
containment step does not document containment; it is not evidence that containment was
skipped. Collapsing the two would turn a gap in the record into a finding of
non-compliance, which is a much stronger claim than the evidence supports. `fail` needs
positive evidence of its own.

## What is checked in Python, not asked of the model

The model is not trusted with the claim an audit rests on. After the response validates,
`checks.py` verifies deterministically that:

- every supplied control received **exactly one** assessment,
- no assessment names a control that was not supplied,
- every assessment has a non-empty rationale, including `not_applicable`,
- every `pass` and every `fail` cites at least one evidence path,
- every cited `evidence_paths` entry resolves in the payload that was actually sent,
- `policy_refs` names every supplied policy and invents none.

Findings land in `case_analyzer_run.checks.problems` and are echoed on stderr. As
elsewhere in this tool, a resolving citation proves the model named a field that exists,
never that the field supports the status it was cited for.

**Only the first two decide the exit code.** A response that fails either of them did not
assess some supplied control, so the result is not an audit of the set it names, and the
command exits `7` — the report is still written, because the incomplete report is what a
person needs in order to see what went wrong. The remaining checks are defects *in* an
audit that did cover every control, so they are reported on stderr and recorded in the
result while the command exits `0`.

The control set itself is validated **before** the request, so a set with duplicate or
empty identifiers costs nothing to discover. `--dry-run` runs that validation too, which
is how you check a control file before paying for a call.

## Control record shape

Controls are ordinary `--knowledge` records. See
[`controls.json`](controls.json) for the shipped example.

```json
{
  "record_type": "control",
  "control_id": "IR-4.2",
  "policy_ref": "SOC-IRP",
  "policy_version": "2026.1",
  "title": "Containment executed for confirmed malware",
  "requirement": "When a case involves confirmed malware or C2 activity, a containment action must be executed...",
  "applies_when": "The case involves confirmed malware or command-and-control activity.",
  "evidence_expectation": "An action or timeline entry showing the action was performed.",
  "exceptions": ["Deferral approved in writing by the IR Manager and recorded on the case."]
}
```

Only `control_id` and `requirement` are required. Unknown fields are preserved and reach
the model, so a real policy export can carry its own framework mappings or ownership
fields without this schema anticipating them.

**This shape is provisional.** It was designed against the requirements written down in
`../user-input-case-audit/README.md`, not against a real policy export. Three decisions
are the ones most likely to need revisiting, and each is pinned by a test so it cannot
change silently:

1. **Controls are flat, and this is enforced.** No sub-controls, because nesting is
   exactly what makes "one assessment per control" ambiguous — a nested sub-control
   reaches the model but has no identity of its own, so coverage would report a clean
   audit of a set containing something nobody assessed. A record carrying a nested object
   or list with a `control_id` in it is refused before the request; flatten sub-controls
   into distinct ids (`IR-4.2.a`) when preparing records. Nested structure that is not
   control-shaped — a framework mapping, a review history — is left alone.
2. **Identity is `(policy_ref, control_id)`.** Two policies can each number a control
   `4.2` in one run. With a single policy it degrades to the bare id.
3. **`applies_when` is optional; a rationale is required for every status.** The field
   gives `not_applicable` a stated basis, and requiring a rationale regardless means the
   model has to write *something* rather than returning a bare status. It is a check on
   form, not on substance: `"n/a"` is a non-empty rationale and passes. Nothing here
   prevents an unhelpful audit that marks every control `not_applicable` with a
   one-syllable justification, and no local check can — judging whether a stated basis is
   real is the reviewer's job, which is why the result is decision support rather than a
   verdict.

## Limits

- **The recorded example here is a `--dry-run --explain` preview, not model output.** The
  mode shipped offline first — schema, validation, coverage check, prompt, and preview —
  matching how `--summary` was rolled out. Live behavior is measured separately by the
  three audit cases in the eval benchmark; the first run is recorded in
  [`../../evals/audit-mode-2026-08-20.md`](../../evals/audit-mode-2026-08-20.md). One
  sample, one model, three cases, and a control set written for the benchmark rather than
  taken from a real policy.
- The result is decision support for a human reviewer. It does not close a case, clear a
  control, or write back to any source platform, by design.
- Enrichment cannot evidence a process control. `case.case_analyzer_enrichment` describes
  observables, not what an analyst did, and the prompt says so.
- `--audit` and `--summary` are mutually exclusive.
- In `--audit`, **every** `--knowledge` record is read as a control. There is no way to
  supply supplementary non-control knowledge alongside the control set; a record declaring
  another `record_type` is refused.
- Coverage is a check on identity, not on substance. The exit code tells you whether every
  control was assessed, never whether it was assessed correctly.
