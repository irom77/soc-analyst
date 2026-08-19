# LiteLLM SDK adoption plan (2026-08-19)

Follow-up to the proxy verification in [`examples/litellm-proxy/README.md`](examples/litellm-proxy/README.md).
The proxy answered the open question — structured output does translate to a native
provider — at the cost of a sidecar process. This plan covers replacing that sidecar
with the LiteLLM SDK, so a standalone CLI stays standalone.

Every claim below was measured on 2026-08-19 against `examples/splunk-soar.json` and the
real `InvestigationReport` schema, not taken from documentation.

## What the probes established

| Question | Answer |
| --- | --- |
| Does `ChatLiteLLM.with_structured_output(InvestigationReport)` work? | Yes — valid report, 4 findings, 4 attack-chain steps |
| Does `litellm.completion(response_format=InvestigationReport)` work? | Yes — same shape |
| Do either need Python 3.12, like the proxy did? | **No.** Both pass on 3.14. The `uvloop` breakage was the `[proxy]` extra only |
| Does the existing `openai.*` except-ladder still catch? | **Yes, entirely** — but it is replaced anyway, per finding 3 |

The exception result is the load-bearing one, because it means the sanitized-error
contract in `analyzer.py` survives without being rewritten:

| Failure injected | Exception raised | Caught by | Exit |
| --- | --- | --- | --- |
| Bad API key | `litellm.exceptions.AuthenticationError` | `except AuthenticationError` | 3 |
| Unreachable host | `litellm.exceptions.APIConnectionError` | `except APIConnectionError` | 5 |
| Unknown model | `litellm.exceptions.NotFoundError` | `except APIStatusError` | 6 |
| Slow endpoint, `timeout=1.0` | `litellm.exceptions.Timeout` | `except APITimeoutError` | 5 |

LiteLLM subclasses the OpenAI exception types deliberately, so all six handlers in
`_request_structured` keep working. This corrects the initial assumption that ~25 lines
of error mapping would need rewriting; the real figure is zero.

Two review findings qualify that result; see
[Review findings](#review-findings-2026-08-19) below. The ladder catches
`JSONSchemaValidationError` too, but that exception carries raw model output, and the
`openai` names the ladder is written against are not a declared dependency.

## Options

Resolved dependency counts (`uv pip compile`, Python 3.12), current baseline is 39:

| | Deps | Δ | Code change | Keeps LangChain |
| --- | --- | --- | --- | --- |
| Proxy (today) | 39 | 0 | none, but needs a sidecar (+107 in an isolated tool env) | yes |
| **A — `ChatLiteLLM`** | 65 | +26 | swap the client class | yes |
| **B — `litellm.completion`** | 49 | +10 | swap the client call, messages become dicts | **no** |

Option A looks like the smaller diff but costs more than twice the dependencies,
because `langchain-litellm` pulls in `langchain-core` *and* `litellm`. Option B drops
the LangChain layer entirely and is the lighter option despite touching more lines.

## Recommendation: Option B

The LangChain coupling is far shallower than its presence in `pyproject.toml` suggests.
It is confined to `analyzer.py`:

- lines 7–8 — the two imports
- lines 81–82 and 95–96 — `SystemMessage` / `HumanMessage` construction
- lines 136–137 — `with_structured_output(schema)` and its `.invoke(messages)`

Nothing else in `src/` touches a LangChain type. `cli.py:151` reads `messages[0].content`
and `cli.py:150,152` print the literal strings `"SystemMessage:"` and `"HumanMessage..."`,
which are user-visible labels rather than type references.

So the framework earns 26 dependencies for one constructor call and one method. Removing
it is the simplification; reaching a native provider is the occasion, not the reason.

## What replaces LangChain

Nothing new is introduced. LangChain sat between two libraries the project already
depends on directly — Pydantic, which defines and validates the schemas, and the HTTP
client that carries the request. Removing it means calling those two directly:

| LangChain surface used today | Replaced by |
| --- | --- |
| `SystemMessage(content=...)`, `HumanMessage(content=...)` | plain dicts: `{"role": "system", "content": ...}` — LiteLLM's native format |
| `ChatOpenAI(...)` construction | no client object; `litellm.completion(...)` is a function call |
| `.with_structured_output(schema)` | `response_format=schema` passed to that call |
| `.invoke(messages)` | the `completion(...)` call itself |
| implicit validation into a Pydantic instance | explicit `schema.model_validate_json(resp.choices[0].message.content)` |

`pydantic` is already a direct dependency and is unchanged by this work; `litellm`
replaces `langchain-openai` one-for-one in `pyproject.toml`. That is the whole
substitution — the net effect is one fewer abstraction layer, not a new framework.

Two properties are deliberately gained rather than merely preserved:

- **Validation becomes explicit and visible.** Today it happens inside
  `with_structured_output`; afterwards it is a line in `_request_structured` that the
  existing `except ValidationError` handler wraps. The `_validation_summary` helper
  already avoids echoing raw model output, so the injection-hardening posture holds.
- **No client-construction kwargs to get wrong.** `litellm.completion` accepts
  `timeout` under that exact name, and tolerates `api_base=None` when
  `CASE_ANALYZER_BASE_URL` is unset — both verified. This is precisely the trap that
  Option A walks into, below.

What is given up is the LangChain ecosystem: streaming helpers, callbacks, runnable
chaining, and agent wiring. None are used anywhere in `src/`, and nothing in `TODO.md`
or `improvement-plan-2026-08-18.md` anticipates them. LiteLLM covers streaming and
retries natively if that changes.

## Trap: `--llm-timeout` breaks silently under Option A

`ChatLiteLLM` has **no** `timeout` field. It is named `request_timeout`.

    ChatLiteLLM(model=..., timeout=12.5)  ->  ACCEPTED silently
                                              request_timeout is None
                                              model_kwargs is {}

The value is neither applied nor rejected — it vanishes. A direct
`ChatOpenAI` → `ChatLiteLLM` substitution therefore disables `--llm-timeout`, undoing
finding M-8, with no error at runtime.

**The current test suite will not catch this.** `tests/test_analyzer.py:130` asserts
`chat.call_args.kwargs["timeout"] == 12.5`, but `chat` is a `Mock`, which records any
kwarg regardless of whether the real class accepts it. The assertion passes while the
behavior is broken. Option B avoids the trap because `litellm.completion` takes
`timeout` directly, but the test weakness is worth fixing either way.

## Implementation steps

1. **Dependencies** — in `pyproject.toml`, replace `langchain-openai>=1.3.3` with
   `litellm`. No Python version pin is needed; 3.14 is fine.

   Be aware this moves `openai` from 3.1.0 to 2.54.0, because LiteLLM pins
   `openai>=2.20.0,<3.0.0`. It arrives only as a transitive dependency after finding 3
   removes the `openai` import, so nothing in `src/` should notice — but it is a major
   version downgrade of an installed package and belongs in the commit message.

2. **Messages** — in `analyzer.py`, change `build_analysis_messages` and
   `build_summary_messages` to return
   `[{"role": "system", "content": ...}, {"role": "user", "content": ...}]`.
   Both already build their content through `render_payload_message`, so the
   BEGIN/END injection delimiters carry over untouched.

3. **`cli.py:151`** — `messages[0].content` becomes `messages[0]["content"]`. Keep the
   printed `SystemMessage:` / `HumanMessage:` labels so `--explain` output and
   `tests/test_cli.py:32` stay stable.

4. **`_request_structured`** — replace the `ChatOpenAI` construction and
   `with_structured_output(schema).invoke(...)` with:

       resp = litellm.completion(model=..., api_key=..., api_base=...,
                                 messages=messages, temperature=0,
                                 num_retries=0, timeout=timeout,
                                 response_format=schema)
       return schema.model_validate_json(resp.choices[0].message.content)

   Note `num_retries`, not `max_retries`. Do **not** set
   `litellm.enable_json_schema_validation` — see finding 1. Pydantic is the sole
   validator, so no code path can raise `JSONSchemaValidationError` with raw model
   output attached.

   Rewrite the `except` ladder against `litellm.exceptions` per the table in finding 3,
   and remove the `openai` import. The mapping is one-for-one except that
   `APITimeoutError` becomes `Timeout` and `APIStatusError` splits into `NotFoundError`
   and `BadRequestError`.

   The existing `except ValidationError` handler becomes more load-bearing here, since
   validation moves from LangChain into our explicit `model_validate_json` call. The
   `_validation_summary` helper already avoids echoing raw model output, so the
   injection-hardening posture is unchanged.

5. **Model naming** — `CASE_ANALYZER_MODEL` gains provider-prefix meaning. In scope
   that means `gemini/gemini-2.5-flash` for the native API; the prefix mechanism is
   general, so other providers would work the same way but are explicitly not verified.
   A bare name still routes to OpenAI, so existing configurations keep working.
   Document the prefix in `.env.example`, `README.md`, and `case-analyzer-code.md:247-249`.
   `CASE_ANALYZER_BASE_URL` maps to `api_base` and stays optional — passing `None`
   is tolerated, verified.

   Also correct the `--base-url` help text in **both** places it appears,
   `cli.py:48` and `explain_cli.py:20`, which currently read "OpenAI-compatible
   endpoint" — inaccurate once a native provider is reachable.

6. **Tests** — two distinct pieces of work:

   - Retarget the four `patch("case_analyzer.analyzer.ChatOpenAI")` sites at
     `tests/test_analyzer.py:65,82,116,140` to
     `patch("case_analyzer.analyzer.litellm.completion")`. Assertions on
     `call_args.kwargs` move from constructor to call kwargs, and `max_retries`
     becomes `num_retries` (`timeout` keeps its name).
   - Convert the **nine** `.content` attribute assertions — lines 41, 42, 51, 52, 53,
     54, 73, 157, 158 — to dictionary access. Lines 157–158 assert the
     injection-hardening text, so verify their meaning is preserved, not just their
     syntax.

7. **Guard against the silent-kwarg class of bug** — add an offline regression test
   that exercises LiteLLM's real completion path, not a mock: start a local
   `HTTPServer` that sleeps well past the deadline, point `api_base` at it, call with
   `timeout=1.0`, and assert the call terminates early with exit 5. Probed at 1.67s,
   no credentials and no traffic beyond loopback.

   Scope it honestly: this verifies **our forwarding contract** — that the configured
   timeout reaches the provider call under the name LiteLLM actually reads — rather
   than proving LiteLLM's timeout implementation. That is the property that would have
   caught the `ChatLiteLLM` `request_timeout` trap, and the one a mock cannot check.

## Verification

- `uv run python -m unittest discover -s tests -t .` and `uv run ruff check src tests`
- `--dry-run` and `--explain` on `examples/splunk-soar.json`, confirming `--explain`
  output is byte-identical to today's
- One live run against `gemini/gemini-2.5-flash` — compare against
  `examples/litellm-proxy/splunk-soar-analysis-via-litellm-proxy.json`
- Re-run the eval benchmark, particularly the two prompt-injection cases, since the
  message envelope changes shape. Record results in a new file under `evals/results/`
  rather than replacing the recorded baseline.
- Confirm exit codes 3 / 5 / 6 still come back from the three failure injections above

## Review findings (2026-08-19)

Raised in review of the first draft, each re-verified by probe before being accepted.

### 1. Drop LiteLLM-side schema validation — accepted, with one correction

`litellm.enable_json_schema_validation = True` lets LiteLLM raise its own
`JSONSchemaValidationError` before our `model_validate_json` runs, and that exception
embeds the raw model response in its message:

    message = f"litellm.JSONSchemaValidationError: model={model}, returned an
               invalid response={raw_response}, for schema={schema}."

**Correction to the finding:** it does not bypass the exception ladder. Its MRO is
`JSONSchemaValidationError -> APIResponseValidationError -> APIError -> OpenAIError`,
so `except OpenAIError` catches it and returns exit 6. Verified with a canary string:
the CLI prints only `LLM error: LLM request failed (JSONSchemaValidationError).` and
the canary does **not** appear.

**But the underlying risk is real.** Because the handler re-raises `from exc`, the raw
response survives on `__cause__` and in any formatted traceback — verified. The CLI is
safe; a library caller of `analyze_case()`, or any logger that formats the exception
chain, is not. That is exactly what `_validation_summary` exists to prevent.

**Resolution:** do not set `enable_json_schema_validation`. Pydantic is the sole
validator. The LiteLLM-side check is redundant given `num_retries=0` and no fallbacks,
and the module-global assignment would change process-wide behavior for any library
consumer — undesirable independent of the leak. Step 4 below is amended accordingly.

### 2. Reframe the timeout test — accepted

The first draft asked for a test against the "real client path," which is meaningless
under Option B, since there is no client object. Patching `litellm.completion` and
asserting on `timeout=` would reproduce the very mock weakness the plan criticizes.

The suggested alternative was probed and works offline, with no credentials and no
network beyond loopback: a local `HTTPServer` that sleeps 10s, called with
`timeout=1.0`, raised `litellm.exceptions.Timeout` after **1.67s**, caught by
`except APITimeoutError` for exit 5. Step 7 is rewritten to specify that test.

### 3. Catch LiteLLM's own exception classes — accepted, and the risk is larger than reported

The finding is that keeping `from openai import ...` while declaring only `litellm`
creates an undeclared direct dependency. Confirmed, and one measurement makes it worse:

    litellm  Requires-Dist: openai>=2.20.0,<3.0.0
    current environment:    openai 3.1.0
    Option B resolves to:   openai 2.54.0

Adopting LiteLLM therefore *downgrades* `openai` by a major version, and LiteLLM — not
this project — controls that pin. Depending on the identity of classes from a package
whose version is chosen by another dependency is not a boundary worth keeping.

**Resolution:** catch LiteLLM's public exception classes and drop the `openai` import
entirely. All required names exist. Note the rename: `litellm.exceptions.Timeout`, not
`APITimeoutError`.

| Current (`openai`) | Replacement (`litellm.exceptions`) | Exit |
| --- | --- | --- |
| `AuthenticationError` | `AuthenticationError` | 3 |
| `RateLimitError` | `RateLimitError` | 4 |
| `APITimeoutError` | `Timeout` | 5 |
| `APIConnectionError` | `APIConnectionError` | 5 |
| `APIStatusError` | `NotFoundError`, `BadRequestError` | 6 |
| `OpenAIError` | `APIError` | 6 |

### 4. Wider documentation and test surface — accepted

- `--base-url` is described as an "OpenAI-compatible endpoint" in **two** places,
  `cli.py:48` and `explain_cli.py:20`. Both become inaccurate for native Gemini.
- Test work is more than the four `patch` sites. `tests/test_analyzer.py` has **nine**
  `.content` attribute assertions — lines 41, 42, 51, 52, 53, 54, 73, 157, 158 — all of
  which become dictionary access. Lines 157–158 assert the injection-hardening text, so
  they matter beyond mechanical retargeting.

### Sequencing against the improvement plan — accepted

Migrate before Tier 1. The review's supporting points are adopted as constraints:
provenance hashes stay stable only if the exact system and rendered payload strings are
untouched, so this change must convert the surrounding message objects and nothing
else; locally generated provenance must stay outside the schema passed as
`response_format`, per `improvement-plan-2026-08-18.md:201`; and the full eval rerun is
justified because a changed transport adapter can move results even with identical text.

## Decisions (settled 2026-08-19)

- **Scope is Gemini only.** No Anthropic, Bedrock, or Vertex verification is required
  for this change. Should a provider be added later, it needs its own recorded run,
  because LiteLLM translates `response_format` per provider and only the native Gemini
  path has been measured. `litellm.supports_response_schema(model=...)` is available to
  gate that at runtime if it ever becomes a supported configuration.
- **The proxy config and example stay.** `litellm-config.yaml` and
  `examples/litellm-proxy/` are kept as a documented alternative. The two approaches are
  not exclusive: the proxy remains the better answer for centralized keys, budgets, or a
  shared multi-user deployment, while the SDK is the better answer for a standalone CLI.
  Neither file is deleted by this plan.
- **Dropping LangChain is accepted long-term.** Option B is confirmed.
