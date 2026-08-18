# Analysis comparison: with and without enrichment

This comparison records two live analyses run on August 18, 2026 with model
`gemini-2.5-flash`. Both used the same reduced Splunk SOAR export,
[`splunk-soar-enrichment-case.json`](splunk-soar-enrichment-case.json). The only command
line difference was `--enrich`.

| Result | Without enrichment | With enrichment |
|---|---|---|
| Full report | [`splunk-soar-analysis-without-enrichment.json`](splunk-soar-analysis-without-enrichment.json) | [`splunk-soar-analysis-with-enrichment.json`](splunk-soar-analysis-with-enrichment.json) |
| Verdict | `True Positive` | `Suspicious` |
| Severity | `High` | `High` |
| Confidence | `High` | `Medium` |
| Reputation claim | Described as confirming a malicious C2 beacon | Attributed to the imported artifact note as an internal claim |
| External provider evidence | None | Cloudflare DNS returned NXDOMAIN (`not_found`) |
| Interpretation of DNS result | Not applicable | Explicitly described as inconclusive for maliciousness |

## What changed

Without enrichment, the report elevated the artifact note—“Imported case enrichment
claims a malicious reputation score”—into a conclusion that the domain was confirmed
malicious. No independent provider evidence in that run supported the confirmation.

With enrichment, Cloudflare DNS returned NXDOMAIN for the synthetic domain. The analyzer
recorded that response as `not_found` with an `inconclusive` comparison, not as benign
evidence. The LLM preserved that distinction: it separated the suspected C2 label, the
imported reputation claim, and the external DNS observation into three findings. It
lowered the verdict to `Suspicious` and confidence to `Medium`, and identified the
domain's operational status and the reputation score's details as unknowns.

The enriched result is better calibrated to the available evidence, but it does not
show that the domain is benign. NXDOMAIN can mean that a domain is inactive, mistyped,
expired, or taken down; it does not establish reputation.

## Reproduce

Run from the repository root after configuring the provider variables documented in the
main README:

```bash
uv run case-analyzer examples/enrichment/splunk-soar-enrichment-case.json \
  --format soar \
  --output /tmp/case-analysis-without-enrichment.json

uv run case-analyzer examples/enrichment/splunk-soar-enrichment-case.json \
  --format soar \
  --enrich \
  --output /tmp/case-analysis-with-enrichment.json
```

The comparison is illustrative rather than deterministic. The commands are separate
LLM calls, so model variation may account for some differences, and live provider
results can change. Repeated trials would be needed to isolate the causal effect of
enrichment. The second command also sends extracted observables to external providers
and may consume configured-provider quota.
