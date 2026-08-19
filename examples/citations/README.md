# Evidence citations and truncation reporting (2026-08-19)

A live run of `examples/splunk-soar.json` after adding `EvidenceFinding.source_paths`
and `InvestigationReport.truncated_fields`, recorded to show what the model actually
produces and what the local post-check catches.

    uv run case-analyzer examples/splunk-soar.json \
      --output examples/citations/splunk-soar-analysis-with-citations.json

Route: `gemini-2.5-flash` through Google's OpenAI-compatibility endpoint — the default
configuration, not the native `gemini/` prefix.

## Result

| Check | Outcome |
| --- | --- |
| Provider accepted the extended schema | Yes — no `anyOf` in the request, and the response validated |
| Verdict | `True Positive`, severity `High`, confidence `High` — unchanged from the runs recorded in `examples/litellm-sdk/` and `examples/litellm-proxy/` |
| Findings cited | 5 of 5 |
| Citations resolving in the payload | 16 of 16 |
| `truncated_fields` | empty |

## What the first run caught

The post-check reported **all 16 citations as unresolved**. The paths were correct; the
model wrote each one as `case.source_data.artifacts[0]…`, spelling out the root that
"rooted at the payload's `case` object" names. The canonical form — the one enrichment
already emits in `EnrichmentObservation.source_paths` — omits it.

Fixed on both sides, deliberately:

- the prompt now says to start at the first key *inside* `case` and not to write a
  leading `case.` segment;
- `resolve_case_path` tries the path as given first, and only then retries without a
  `case.` prefix, so the canonical form stays canonical and a genuine top-level key
  named `case` is never shadowed.

Rejecting the redundant spelling would have been defensible as spec enforcement, and
useless in practice: a check that reports 16 false defects on a correct report is a
check people learn to ignore. The recorded report above is the original response,
re-verified offline against the fixed resolver.

## An open question this run raises

`truncated_fields` came back empty while `evidence_findings` (5), `remediations` (6),
and `unknowns` (5) were each exactly at their cap. That is consistent with a report
that had nothing further to add, and equally consistent with under-reporting. The
post-check can only catch the opposite error — a truncation claim about a list that
sits below its cap — because nothing in the response can prove what was left out. Worth
watching across eval runs rather than treating this single sample as a result.

## Scope

One case, one model, one route. The schema change is provider-visible, so a different
provider needs its own run before the extended schema is assumed to work there — the
same caveat that applies to `response_format` generally.
