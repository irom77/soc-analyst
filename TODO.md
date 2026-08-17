# TODO

- [ ] Address payload quality, duplicated `source_data`, provider cost and rate limits, and excessive noisy enrichment.
- [ ] Evaluate additional free enrichment providers in this order: AbuseIPDB for public-IP reputation, ThreatFox for domain/IP IOC matches, GreyNoise Community for internet-scanner context, and URLhaus after complete URL extraction is supported. Keep provider results separately attributed, cache responses, respect enrichment limits, and treat `not_found` as inconclusive. Document and enforce each provider's API quota, fair-use terms, and commercial-use restrictions before enabling it in operational workflows.
- [ ] Remove the deprecated `explain_case_analysis` and `explain-case-analysis` aliases in the next breaking release; use `case-analyzer --explain` instead.
