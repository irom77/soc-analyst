# Enrichment examples

`splunk-soar-enrichment-case.json` is a reduced Splunk SOAR export containing one
domain artifact. `splunk-soar-enriched.json` records its normalized payload after a
live provider run. `splunk-soar-enrichment-live-run.txt` records the command, provider
summary, and result statuses. Together they demonstrate that analyzer-generated results
are stored under `case.case_analyzer_enrichment` without changing imported `source_data`.

`splunk-soar-enriched.2026-08-17.json` and `splunk-soar-enrichment-live-run.2026-08-17.txt`
keep the earlier recorded run for history. They predate the 2026-08-17 review fixes, so
they use the former `existing_case_context` field name, the `arin-rdap` provider label,
and a VirusTotal response that succeeded. Read them as a record of what the run produced
at the time, not as the current output shape.

Regenerate it from the repository root:

```bash
uv run case-analyzer examples/enrichment/splunk-soar-enrichment-case.json \
  --format soar \
  --enrich \
  --dry-run \
  --allow-enrichment-in-dry-run \
  --output examples/enrichment/splunk-soar-enriched.json
```

The command always contacts Cloudflare DNS and, for public IP addresses, the RDAP
registry that holds the range; `--allow-enrichment-in-dry-run` is required because
`--dry-run` otherwise sends no data anywhere. If `VIRUSTOTAL_API_KEY` is present in the
ignored `.env` file, it also contacts VirusTotal and adds a separate observation for
each eligible domain, globally routable IP address, or file hash. Provider results and
retrieval timestamps can change when the example is regenerated. The output never
contains the API key.

In the committed snapshot Cloudflare DNS returns no answer for the synthetic domain and
VirusTotal returns `HTTP 429`. Neither is a verdict: the absent DNS answer is recorded
as `inconclusive` rather than as evidence of benignness, and the quota error is retained
as an observation with `lookup_status: "error"` instead of aborting the run or blocking
the other provider. The imported note claiming a malicious reputation stays separate
under `artifact_context`, which describes the artifact that held the value rather than
the value itself. The earlier snapshot kept alongside it recorded a successful VirusTotal
response with no detections; both outcomes are normal, and provider results change
between regenerations.

Only one artifact and one VirusTotal-eligible observable are present here, so a `429` is
a public-tier quota condition rather than excessive requests from the example. When a
provider fails repeatedly within one run, `--enrichment-failure-threshold` stops calling
it and the remaining observables are recorded as `skipped` with a reason, which the
summary reports as `stopped_early=yes`.
