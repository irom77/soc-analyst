# Enrichment examples

`splunk-soar-enrichment-case.json` is a reduced Splunk SOAR export containing one
domain artifact. `splunk-soar-enriched.json` records its normalized payload after a
live provider run. `splunk-soar-enrichment-live-run.txt` records the command, provider
summary, and result statuses. Together they demonstrate that analyzer-generated results
are stored under `case.case_analyzer_enrichment` without changing imported `source_data`.

Regenerate it from the repository root:

```bash
uv run case-analyzer examples/enrichment/splunk-soar-enrichment-case.json \
  --format soar \
  --enrich \
  --dry-run \
  --output examples/enrichment/splunk-soar-enriched.json
```

The command always contacts Cloudflare DNS and ARIN RDAP. If `VIRUSTOTAL_API_KEY` is
present in the ignored `.env` file, it also contacts VirusTotal and adds a separate
observation for each eligible domain or globally routable IP address. Provider results
and retrieval timestamps can change when the example is regenerated. The output never
contains the API key.

The committed live-run snapshot records a VirusTotal `HTTP 429` response. This intentionally
shows that provider rate limits are retained as an observation with `lookup_status:
"error"`; they do not abort enrichment or prevent the remaining providers from running.
Only one artifact and one VirusTotal-eligible observable are present, so this response
is a provider quota condition rather than excessive requests from the example.
