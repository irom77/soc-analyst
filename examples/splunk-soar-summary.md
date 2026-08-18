# Splunk SOAR Case Summary Result

This document records a live `--summary` run against the same [`splunk-soar.json`](splunk-soar.json) export used by the [Splunk SOAR case analysis result](splunk-soar-analysis.md). Where that document records an `InvestigationReport`, this one records what `--summary` returns instead: a narrative description of the case, with no verdict, severity re-rating, attack chain, IOC list, or remediation.

## Command

The analyzer was invoked from the repository root using the enabled structured-output LLM configuration:

```bash
uv run case-analyzer examples/splunk-soar.json \
  --format soar \
  --summary \
  --output /tmp/splunk-soar-summary.json
```

The model name, base URL, and API key were supplied through the `CASE_ANALYZER_*` environment variables. Credentials are not written to this document. `--enrich` was not used, so no observable was sent to a DNS, RDAP, or reputation provider; every enrichment-sounding statement below comes from the export itself.

## Result

The command exits `0` and prints a single-field `CaseSummary` document, 181 words across three paragraphs:

```json
{
  "summary": "Case 1042, titled \"Cobalt Strike Activity on WS-FIN-09,\" was reported by SOAR on August 14, 2026, at 18:22:10Z. ..."
}
```

The full text:

> Case 1042, titled "Cobalt Strike Activity on WS-FIN-09," was reported by SOAR on August 14, 2026, at 18:22:10Z. This high-severity, open incident is described as a multi-stage event involving phishing delivery, encoded script execution, and C2 staging, tagged with `c2_traffic`, `finance_subnet`, and `apt_activity`. The case has no recorded update timestamp.
>
> The incident began with a Splunk ES alert for suspicious process execution on host WS-FIN-09 (IP 10.20.4.115), where `powershell.exe` was launched with an encoded command by `excel.exe`. An analyst note indicates the decoded PowerShell payload attempted a download from a remote stage2 domain. This was followed by a firewall alert for outbound beacon traffic from WS-FIN-09 to 198.51.100.44 on port 443, identified as a persistent TLS session with periodic pulses.
>
> A key observable is the C2 beacon domain `stage2.malicious-domain.xyz`, which resolves to `198.51.100.44` on port 443. Automated threat intelligence enrichment noted the domain uses Fast Flux DNS and has a malicious reputation score of 89/100. An analyst comment confirmed this IOC matches a US-CERT advisory bulletin. Another comment indicates that host network isolation for WS-FIN-09 was approved by the SOC Lead.

## Evidence trace

Every value named in the summary was located in the export:

| Claim | Where it comes from |
| --- | --- |
| Case 1042, title, `high`, `open`, `2026-08-14T18:22:10Z` | Parent container `id`, `name`, `severity`, `status`, `create_time` |
| Phishing delivery, encoded script execution, C2 staging | Parent container `description` |
| `c2_traffic`, `finance_subnet`, `apt_activity` | Parent container `tags` |
| "no recorded update timestamp" | `update_time` and `end_time` are absent from the export |
| Splunk ES alert for suspicious process execution | Child container 1039, note 402 "Initial Triage Findings" |
| WS-FIN-09, `10.20.4.115`, `excel.exe` → `powershell.exe` | Child artifact 6088 `cef` block |
| Decoded payload's download intent | Child-artifact note 8092 "Base64 Deobfuscation Analysis" |
| `198.51.100.44`, port `443` | Child artifact 6095 `cef` block |
| Persistent TLS session with periodic pulses | Child-artifact note 8099 "Session Duration & Flow Analysis" |
| `stage2.malicious-domain.xyz` | Parent artifact 6101 `cef` block, alongside the same address and port |
| Fast Flux DNS, reputation 89/100 | Parent-artifact note 8101 "Threat Intelligence Enrichment", author `automation_playbook` |
| US-CERT advisory match | Parent-artifact comment 951 |
| Isolation approved by SOC Lead | Parent container comment 901 |

## What this demonstrates

The summary reaches evidence held only in nested child containers, child-artifact notes, and comments, the same depth the investigation run uses — but it reports that evidence rather than reasoning from it.

Attribution held where it matters. The Fast Flux and 89/100 reputation claims are stated as what an automated enrichment note recorded, not as established facts about the domain. The US-CERT match is stated as an analyst comment. The host-isolation line reports an approval already recorded in the case; it is not a recommendation the model made. The prompt's instruction to describe rather than conclude survived a case whose own notes are written in confident language.

The run also shows the intended absence: the case severity is repeated as a field value, and no verdict, priority, confidence, attack chain, or remediation appears anywhere in the output.

Two slips are preserved here as recorded, neither of which invents anything. The domain "resolves to `198.51.100.44` on port 443" attaches a port to a DNS resolution; artifact 6101 holds `destinationDnsDomain`, `destinationAddress`, and `destinationPort` as siblings in one `cef` block, so the evidence is right and only the sentence collapses three fields into one relationship. And the title is quoted as "Cobalt Strike Activity on WS-FIN-09", dropping the `CASE-2026-0814-01: ` prefix the container's `name` actually carries.

This is model-generated output over example data. A summary is an orientation aid, not a determination; an analyst must read the case itself before acting on anything described here.
