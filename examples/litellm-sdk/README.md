# LiteLLM SDK: native provider API without a gateway (2026-08-19)

Records the first run after the analyzer moved from LangChain to the LiteLLM **SDK**.
The same model is reached through Google's **native** `generateContent` API with no
proxy in front of it — the translation now happens in process.

## How it was run

No `CASE_ANALYZER_BASE_URL` is set; the `gemini/` prefix is what selects the native API:

    CASE_ANALYZER_MODEL=gemini/gemini-2.5-flash
    CASE_ANALYZER_API_KEY=<google-key>

    uv run case-analyzer examples/splunk-soar.json \
      --output examples/litellm-sdk/splunk-soar-analysis-via-litellm-sdk.json

## Result

| Check | Outcome |
| --- | --- |
| `response_format=InvestigationReport` | Passed — output validates against the model |
| Report completeness | verdict `True Positive`, severity `High`, confidence `High`; 4 evidence findings, 4 attack-chain steps, 4 timeline entries, 4 IOCs, 4 remediations, 2 affected assets, 5 unknowns |
| Unit tests (`unittest discover`) | 96 passed |
| `ruff check src tests` | clean |

## Compared with the proxy run

[`../litellm-proxy/`](../litellm-proxy/README.md) recorded the same case through a
LiteLLM **proxy** against the same native API. Both produce the same schema and the
same judgment:

| Field | SDK (native) | Proxy |
| --- | --- | --- |
| `verdict` | `True Positive` | `True Positive` |
| `severity` / `confidence` | `High` / `High` | `High` / `High` |
| `evidence_findings` | 4 | 4 |
| `attack_chain` | 4 | 4 |
| `remediations` | 4 | 4 |
| `affected_assets` | 2 | 2 |
| `attack_timeline` | 4 | 6 |
| `ioc_indicators` | 4 | 3 |
| `unknowns` | 5 | 4 |

The last three rows differ by model nondeterminism, not by transport: temperature zero
does not make this model deterministic. The judgment fields and the evidence and
remediation counts match.

## Failure translation

Re-verified through the CLI after the migration:

| Scenario | Message | Exit |
| --- | --- | --- |
| Unreachable endpoint | `Could not get a response from the LLM endpoint; check the URL, network, and provider status.` | 5 |
| Unknown model | `LLM provider returned HTTP 404.` | 6 |
| Invalid API key | `LLM provider returned HTTP 400.` | 6 |

The unreachable-endpoint message changed with this migration. LiteLLM reports a refused
connection as a synthetic `InternalServerError` with status 500 and drops the original
exception, so it cannot be told apart from a genuine provider outage. Both mean no
answer was obtained, so both map to exit 5 — the documented code for connection
failures — under a message that covers either cause.

Google's OpenAI-compatibility shim answers an invalid key with HTTP 400 rather than
401, so that case reports 6. Exit 3 requires a provider that returns 401.

## Caveat

Structured output was verified for Gemini only, over both the native API and the
OpenAI-compatible shim. LiteLLM translates `response_format` per provider, so
Anthropic, Bedrock, or Vertex need their own run before being assumed to work.
`_NATIVE_PREFIXES` in `analyzer.py` is the list to extend when one is.
