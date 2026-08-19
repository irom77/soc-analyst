# Run provenance and the closed decision vocabulary (2026-08-19)

A live run of `examples/splunk-soar.json` after two changes that both touch what the
provider sees or what gets saved: the locally generated `case_analyzer_run` block, and
`verdict`/`confidence` becoming closed sets in the request schema.

    uv run case-analyzer examples/splunk-soar.json --format soar \
      --output examples/provenance/splunk-soar-analysis-with-provenance.json

Route: `gemini-2.5-flash` through Google's OpenAI-compatibility endpoint — the default
configuration, not the native `gemini/` prefix.

## Why this one needed a live call

The provenance block is computed locally and is fully covered offline. The enum
constraint is not: it changes the JSON schema sent as `response_format`, and a provider
that mishandles `enum` would fail every run. Only a real request answers that.

## Result

| Check | Outcome |
| --- | --- |
| Provider accepted the enum-constrained schema | Yes — no `anyOf`, and the response validated |
| Verdict | `True Positive`, confidence `High` — both canonical, and unchanged from the runs in `examples/litellm-sdk/`, `examples/litellm-proxy/`, and `examples/citations/` |
| Findings cited | 4 of 4, 14 citations |
| Citations resolving in the payload | 14 of 14 |
| `case_analyzer_run.checks` | `{"ran": true, "problems": []}` |
| API key or base-URL userinfo anywhere in the output | None |

The verdict is the fourth consecutive recorded run to land on `True Positive` / `High`
for this case, so the enum did not change the answer — which is the claim it was meant
to support, not a surprise.

## What it confirms about the earlier citation fix

The `case.`-prefix ambiguity recorded in [`../citations/README.md`](../citations/README.md)
was fixed on both the prompt and resolver sides but re-verified only offline, against the
already-recorded response. This is a fresh live run against the corrected prompt, and all
14 citations resolve with no `case.` prefix written. The fix holds in the live path.

## The truncation question, one sample later

`truncated_fields` is empty again, but this run is more informative than the last: no
list is at its cap (`evidence_findings` 4 of 5, `ioc_indicators` 5 of 10,
`attack_timeline` 5 of 8, `remediations` 4 of 6, `unknowns` 3 of 5). The previous run had
three lists sitting exactly at their caps with nothing reported, which is consistent with
either a complete report or silent under-reporting. Seeing the model return sub-cap lists
when it has less to say weakens the under-reporting reading without settling it. Still
worth watching across eval runs.

## Scope

One case, one model, one route. The enum is provider-visible, so another provider needs
its own run before the constraint is assumed to work there — the same caveat that applies
to `response_format` generally.
