# Evidence-Oriented Reasoning Examples

These synthetic SOAR exports test whether Case Analyzer evaluates technical evidence instead of assigning a verdict from alarming or reassuring words. Each case contains nested child containers, artifacts, and notes similar to [`../splunk-soar.json`](../splunk-soar.json).

| Scenario | Misleading wording | Decisive evidence | Allowed verdicts |
|---|---|---|---|
| [`scary-words-benign.json`](scary-words-benign.json) | Critical malware, ransomware, credential theft, and C2 | Approved change, isolated range, signed simulator, no harmful outcome, and no external egress | `Benign`, `False Positive` |
| [`reassuring-words-malicious.json`](reassuring-words-malicious.json) | Routine, safe, approved, and false positive | Office-to-hidden-PowerShell execution, payload download, periodic external traffic, and maintenance-team denial | `True Positive`, `Suspicious` |
| [`scary-words-insufficient.json`](scary-words-insufficient.json) | APT, malware, C2, exfiltration, ransomware, and critical | Only a user report and incomplete DNS observation; process, response, timestamp, and corroboration are missing | `Insufficient Data`, `Suspicious` |

The allowed verdict sets intentionally accommodate reasonable model judgment. This is a demonstration, not a deterministic unit test or a claim that every model will reach the same conclusion.

## Recorded live run

The examples were run on August 15, 2026 with the repository's `Gemini Flash` structured-output configuration using model `gemini-2.5-flash`.

| Scenario | Expected verdict(s) | Actual verdict | Confidence | Comparison |
|---|---|---|---|---|
| Alarming wording, verified simulation | `Benign`, `False Positive` | `False Positive` | High | PASS |
| Reassuring wording, malicious evidence | `True Positive`, `Suspicious` | `True Positive` | High | PASS |
| Alarming wording, incomplete evidence | `Insufficient Data`, `Suspicious` | `Insufficient Data` | Low | PASS |

The reports followed the evidence rather than the framing:

- The benign scenario cited the approved exercise, isolated range, signed simulation tool, absence of harmful actions, and blocked external egress.
- The malicious scenario rejected the reassuring disposition because Word spawned hidden encoded PowerShell, an external payload was downloaded, periodic outbound connections followed, and the maintenance team denied performing the work.
- The incomplete scenario did not convert alarming labels into a confirmed incident. It identified the missing timestamp, process attribution, DNS response, corroborating telemetry, and explanation for the slow laptop.

These are model-generated conclusions from synthetic evidence. A later run can differ, and a `PASS` only means the verdict fell within the scenario's allowed set. It does not prove that every individual claim in the report is correct.

## Run the comparison

Configure the provider variables described in the main [`README.md`](../../README.md), then run from the repository root or this directory:

```bash
./test.sh
```

The script invokes the LLM once per case, writes full structured reports to a temporary directory, and prints a Markdown comparison table. Pass a directory to retain the report files at a chosen location:

```bash
./test.sh ./reasoning-results
```

Every run starts with the offline unit tests and Ruff checks. To run those checks without invoking the LLM, use `./test.sh --offline`.

The script reports `PASS` when the verdict is in the allowed set. It reports `REVIEW` and exits nonzero when a result falls outside that set. `REVIEW` calls for human inspection; it does not automatically mean the model is wrong.

Running the script sends all three synthetic cases to the configured provider and may incur provider charges.
