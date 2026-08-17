# Enrichment examples

`splunk-soar-enriched.json` records the normalized dry-run payload produced from
[`../splunk-soar.json`](../splunk-soar.json). It demonstrates that analyzer-generated
results are stored under `case.case_analyzer_enrichment` without changing the imported
`source_data`.

Regenerate it from the repository root:

```bash
uv run case-analyzer examples/splunk-soar.json \
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

The committed snapshot records a VirusTotal `HTTP 429` response. This intentionally
shows that provider rate limits are retained as an observation with `lookup_status:
"error"`; they do not abort enrichment or prevent the remaining providers from running.
