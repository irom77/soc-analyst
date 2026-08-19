# LiteLLM proxy: non-OpenAI-compatible provider test (2026-08-19)

Verifies that the analyzer can drive a model that has **no OpenAI-compatible endpoint**,
without changing any application code, by routing through a LiteLLM proxy.

## Why this is a real test

Before this run the project reached `gemini-2.5-flash` through Google's
OpenAI-*compatibility* shim (`generativelanguage.googleapis.com/v1beta/openai`), so it
only ever spoke OpenAI wire format. Here the same model is reached through Google's
**native** `generateContent` API, confirmed from litellm debug output:

    https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent

The proxy performs the translation, so `src/case_analyzer/analyzer.py` is unchanged.

## Files

| Path | Purpose |
| --- | --- |
| [`litellm-config.yaml`](../../litellm-config.yaml) | Proxy configuration at the repository root. Declares the `gemini-native` alias, the upstream provider, and the `GEMINI_API_KEY` reference. Required — the proxy will not start without a config. |
| [`splunk-soar-analysis-via-litellm-proxy.json`](splunk-soar-analysis-via-litellm-proxy.json) | The `InvestigationReport` produced through the proxy during this run. |
| [`.env.example`](../../.env.example) | Carries the three commented `CASE_ANALYZER_*` values needed to point the CLI at the proxy. |

`litellm-config.yaml` contains no secrets. It refers to the provider key indirectly as
`os.environ/GEMINI_API_KEY`, which the proxy resolves from its own environment at
startup, so the file is safe to commit.

## Setup

The proxy is installed as an isolated `uv` tool, so it is **not** a project dependency:

    uv tool install --python 3.12 'litellm[proxy]' --with 'fastapi>=0.136.3,<0.140'

Two pins are required and both are load-bearing:

- `--python 3.12` — litellm's `uvloop` fails on Python 3.14
  (`BaseDefaultEventLoopPolicy` was removed from `asyncio.events`).
- `fastapi<0.140` — litellm 1.97.0 imports `get_flat_dependant`, which FastAPI removed
  in 0.140. litellm's own declared range (`fastapi>=0.136.3,<1.0`) is too loose and
  resolves to a broken combination.

Run the proxy from the repository root, pointing `--config` at
[`litellm-config.yaml`](../../litellm-config.yaml) and supplying the Google key in
*its* environment (not the analyzer's):

    GEMINI_API_KEY=<google-key> litellm --config litellm-config.yaml --port 4000

Add `--detailed_debug` to that command to log the full upstream request URL.

Point the analyzer at it (the client-side key is a placeholder; the proxy holds the real one):

    CASE_ANALYZER_MODEL=gemini-native
    CASE_ANALYZER_BASE_URL=http://localhost:4000/v1
    CASE_ANALYZER_API_KEY=sk-local

## Result

    uv run case-analyzer examples/splunk-soar.json \
      --output examples/litellm-proxy/splunk-soar-analysis-via-litellm-proxy.json

| Check | Outcome |
| --- | --- |
| `with_structured_output(InvestigationReport)` | Passed — output validates against the model |
| Report completeness | verdict `True Positive`, severity `High`; 4 evidence findings, 4 attack-chain steps, 6 timeline entries, 3 IOCs, 4 remediations, 4 unknowns |
| Unit tests (`unittest discover`) | 89 passed |
| `ruff check src tests` | clean |
| Application code changed | none |

Sanitized provider errors and CLI exit codes survive the extra hop:

| Scenario | Message | Exit |
| --- | --- | --- |
| Unknown model alias | `LLM provider returned HTTP 400.` | 6 |
| Unreachable endpoint | `Could not connect to the LLM endpoint; check the URL and network.` | 5 |

## Seeing the upstream URL

`api_base` in [`litellm-config.yaml`](../../litellm-config.yaml) is optional for routing —
LiteLLM derives the URL from the `gemini/` prefix. It is set explicitly so the upstream
host is reportable:

    curl -s http://localhost:4000/model/info -H 'Authorization: Bearer sk-local' \
      | jq '.data[0].litellm_params'

Without that line the field is absent entirely and nothing can display it. Note the
distinction: `/model/info` reports the configured **base**; only the `--detailed_debug`
log shows the **full per-request URL**, because the `:generateContent` suffix is built
at call time.

The admin dashboard at `/ui` additionally requires a Postgres `DATABASE_URL`. Without
one, the page renders but `POST /login` fails with `Not connected to DB!`, so a master
key alone is not sufficient.

## Caveat

Structured output was verified for Gemini's native API only. LiteLLM translates
`response_format` per provider, so Anthropic, Bedrock, or Vertex need their own run
before being assumed to work.
