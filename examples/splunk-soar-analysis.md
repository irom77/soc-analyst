# Splunk SOAR Case Analysis Result

This document records a live LLM analysis of the corrected [`splunk-soar.json`](splunk-soar.json) export. The input contains a parent case, two child containers, container notes, artifacts, artifact notes, comments, and enrichment findings embedded in note content.

## Command

The analyzer was invoked from `case-analyzer/` using the repository's enabled structured-output LLM configuration:

```bash
uv run case-analyzer examples/splunk-soar.json \
  --format soar \
  --output /tmp/splunk-soar-analysis.json
```

The model name, base URL, and API key were supplied through the `CASE_ANALYZER_*` environment variables. Credentials are not written to this document.

## Normalization check

The corrected export is valid JSON. Its normalized payload contains:

| Evidence | Count |
| --- | ---: |
| Parent artifacts | 1 |
| Parent notes | 1 |
| Child containers | 2 |
| Child artifacts | 2 |
| Child-container notes | 1 |
| Child-artifact notes | 2 |

The SOAR adapter maps the parent container's common fields to the canonical case. The complete original export, including all nested child evidence, is retained under `case.source_data` and sent to the LLM.

## Result summary

| Field | LLM result |
| --- | --- |
| Verdict | True Positive |
| Severity | Critical |
| Impact | High |
| Priority | Critical |
| Confidence | High |

> A finance workstation (WS-FIN-09) was compromised via a phishing attachment, leading to the execution of an encoded PowerShell script. This script established a Cobalt Strike C2 beacon to a known malicious domain, indicating active adversary control and potential for further compromise.

## Affected assets

| Type | Value |
| --- | --- |
| Host | `WS-FIN-09` |
| IP address | `10.20.4.115` |

## Evidence findings

### Suspicious process execution

- Subject: `WS-FIN-09`
- Evidence: Microsoft Excel spawned a hidden, encoded PowerShell process: `powershell.exe -NonI -W Hidden -EncodedCommand <BASE64_PAYLOAD>`.
- LLM conclusion: this likely represents execution originating from the phishing attachment.

### Encoded PowerShell payload

- Subject: `powershell.exe`
- Evidence: the artifact note says the Base64 command was deobfuscated and attempted to download a payload with `IEX Net.WebClient` from a remote stage-two domain.
- LLM conclusion: the script acts as a dropper or downloader for a secondary payload.

### Outbound C2 beaconing

- Subject: `10.20.4.115`
- Evidence: a 450-second TLS session with periodic 30-second pulses from `WS-FIN-09` to `198.51.100.44:443`.
- LLM conclusion: the behavior is characteristic of C2 beaconing and is consistent with the case's Cobalt Strike identification.

### Malicious C2 domain

- Subject: `stage2.malicious-domain.xyz`
- Evidence: the threat-intelligence note reports Fast Flux DNS, an 89/100 malicious reputation score, and a match to an advisory bulletin.
- LLM conclusion: the infrastructure is malicious and associated with known threat activity.

## Attack chain

1. **Initial Access:** a user opened a malicious phishing attachment.
2. **Execution:** Excel launched an encoded PowerShell script that attempted to download another stage.
3. **Command and Control:** the host established a persistent TLS connection to the malicious domain with a regular beacon pattern.

## Timeline

| Timestamp | LLM-described event | Source evidence |
| --- | --- | --- |
| `2026-08-14T18:15:02.000Z` | Excel spawned suspicious PowerShell | Suspicious-execution child container |
| `2026-08-14T18:16:30.000Z` | Outbound beacon traffic detected | Firewall-alert child container |
| `2026-08-14T18:20:45.000Z` | PowerShell payload deobfuscated | Child artifact's deobfuscation note |
| `2026-08-14T18:22:15.000Z` | C2 domain observable created | Parent artifact |
| `2026-08-14T18:23:01.000Z` | Threat-intelligence enrichment confirmed malicious reputation | Parent artifact's enrichment note |
| `2026-08-14T18:25:30.000Z` | Host isolation approved | Parent case comment |

## Indicators

| Type | Value | Context |
| --- | --- | --- |
| Domain | `stage2.malicious-domain.xyz` | Reported C2 beacon domain |
| IP address | `198.51.100.44` | C2 destination address |
| Command line | `powershell.exe -NonI -W Hidden -EncodedCommand <BASE64_PAYLOAD>` | Encoded PowerShell execution |
| Port | `443` | TLS C2 communication destination |

## Recommended actions

| Priority | Action | Description |
| --- | --- | --- |
| High | Containment | Isolate `WS-FIN-09` to prevent further lateral movement or exfiltration. |
| High | Eradication | Perform forensic analysis, remove malware, and reimage the host to a trusted state. |
| High | Network blocking | Block the reported domain and IP address at firewalls, proxies, and DNS resolvers. |
| Medium | Detection improvement | Detect encoded PowerShell, Office-to-PowerShell process chains, and similar beacon patterns. |
| Medium | User awareness | Provide targeted phishing training to the affected user and finance department. |

## Unknowns retained by the LLM

- The phishing email's sender, subject, and full attachment name.
- The full decoded PowerShell payload beyond its download intent.
- The identity of the user who opened the attachment.
- Whether lateral movement or data exfiltration occurred.

## What this demonstrates

The generated report used evidence that exists only inside nested child containers and artifact notes. In particular, it used the child endpoint artifact for the Office-to-PowerShell relationship, its note for deobfuscation, the firewall child artifact for the 450-second session and 30-second beacon interval, and the parent artifact note for threat-intelligence enrichment.

This is model-generated analysis of example data, not a validated incident determination. An analyst must verify the evidence, conclusions, and proposed actions before operational use.
