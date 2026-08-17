# Repository Instructions

## Scope

- Keep changes surgical and limited to the requested case-analyzer behavior.
- Use `uv` for Python dependency management and command execution.
- Update and commit `TODO.md` when it records work relevant to the requested change.

## Skills

- Use Superpowers skills only when the user explicitly requests them.

## Credentials and external services

- Keep provider credentials in the ignored `.env`; document variable names with placeholder values in `.env.example`.
- Never commit credentials, tokens, or live provider secrets.
- Treat live LLM and enrichment calls as network operations that may incur cost or consume rate limits.

## Verification and examples

- Use `--dry-run` or an equivalent preview when verifying behavior without contacting an LLM.
- Run live examples only when the task calls for provider-backed verification and credentials are configured.
- Preserve original case exports and recorded example results unless the user explicitly requests that they be updated.
- Keep newly generated walkthrough or analysis output in a dedicated file rather than replacing an existing recorded result.
