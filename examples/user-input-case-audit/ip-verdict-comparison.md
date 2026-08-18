# Unsupported IP-verdict audit comparison

These reports were generated on August 18, 2026 from the same synthetic
[`case`](ip-verdict-claim.json) and audit
[`guidance`](ip-verdict-claim.txt) using the configured `gemini-2.5-flash` model.
Only the second run enabled enrichment.

| Run | Verdict | Severity | Confidence | Material basis |
|---|---|---|---|---|
| [Without enrichment](ip-verdict-analysis-without-enrichment.json) | `False Positive` | Low | High | The export contains only the asserted conclusion and a bare IP artifact; the report also introduced Google Public DNS context from model knowledge rather than supplied evidence. |
| [With enrichment](ip-verdict-analysis-with-enrichment.json) | `False Positive` | Low | High | RDAP attributed the address to Google LLC, and AbuseIPDB returned an abuse confidence score of 0 with `is_whitelisted: true`; the export still contained no primary attack telemetry. |

## What the comparison demonstrates

Both reports rejected the case's repeated words—“confirmed,” “malicious attack,” and
“True Positive”—as substitutes for technical evidence. They identified the absent
connection logs, detection details, target, protocol, payload, and validation. In that
limited sense, this run demonstrates resistance to conclusion-laden keywords.

Enrichment improved traceability. The enriched report could attribute its ownership
and reputation statements to named external observations instead of relying on the
model's background knowledge. It also showed why enrichment belongs in this audit:
the provider context directly challenges the unsupported claim recorded by the
analyst and supplies a reason to reopen the disposition.

## What it does not prove

The recorded `False Positive` verdict and High confidence are stronger than the
available evidence warrants. Google ownership and a favorable AbuseIPDB response do
not establish that no malicious traffic occurred; the address might have been
spoofed, used in reflection traffic, or simply recorded in a field whose semantics
were misunderstood. Likewise, absence of telemetry from this export is not evidence
that an attack did not happen.

For that reason, treat this as a useful audit example rather than a deterministic
pass. A more conservative evidence-grounded result could be `Insufficient Data` or
`Suspicious`, with a recommendation to reopen the case and obtain the originating
sensor event and packet, flow, DNS, and affected-asset context before assigning a
final disposition. Later live runs may differ as model behavior and provider data
change.
