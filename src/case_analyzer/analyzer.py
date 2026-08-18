import json
import os
from importlib.resources import files
from typing import Any

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    AuthenticationError,
    OpenAIError,
    RateLimitError,
)
from pydantic import ValidationError

from .schemas import CanonicalCase, InvestigationReport


class LLMProviderError(RuntimeError):
    """Sanitized provider failure suitable for display by the CLI."""

    def __init__(self, message: str, exit_code: int):
        super().__init__(message)
        self.exit_code = exit_code


def _system_prompt() -> str:
    return files("case_analyzer.prompts").joinpath("investigation.md").read_text(encoding="utf-8")


def build_analysis_payload(
    case: CanonicalCase,
    *,
    knowledge_records: list[dict[str, Any]] | None = None,
    user_input: str = "",
) -> dict[str, Any]:
    payload = {
        # `mode="json"` keeps every value JSON-serializable, including the
        # enrichment timestamps, which are `datetime` fields.
        "case": case.model_dump(mode="json", exclude_none=True),
        "knowledge": {"records": knowledge_records or []},
    }
    if user_input:
        payload["user_input"] = user_input
    return payload


def build_analysis_messages(
    case: CanonicalCase,
    *,
    knowledge_records: list[dict[str, Any]] | None = None,
    user_input: str = "",
) -> list:
    payload = build_analysis_payload(case, knowledge_records=knowledge_records, user_input=user_input)
    return [
        SystemMessage(content=_system_prompt()),
        HumanMessage(content=json.dumps(payload, ensure_ascii=False)),
    ]


def _validation_summary(exc: ValidationError, limit: int = 3) -> str:
    """Describe a schema mismatch without echoing the raw model output."""
    parts = [
        f"{'.'.join(str(item) for item in error['loc']) or '<root>'} ({error['type']})"
        for error in exc.errors()[:limit]
    ]
    return "; ".join(parts) or "no field detail available"


def analyze_case(
    case: CanonicalCase,
    *,
    knowledge_records: list[dict[str, Any]] | None = None,
    user_input: str = "",
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    timeout: float | None = None,
) -> InvestigationReport:
    # Make the standalone CLI usable without manually exporting provider
    # variables. Existing environment variables retain precedence over .env.
    load_dotenv()
    selected_model = model or os.getenv("CASE_ANALYZER_MODEL") or os.getenv("OPENAI_MODEL")
    if not selected_model:
        raise ValueError("Set CASE_ANALYZER_MODEL or pass --model.")
    selected_key = api_key or os.getenv("CASE_ANALYZER_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not selected_key:
        raise ValueError("Set CASE_ANALYZER_API_KEY or pass --api-key.")
    try:
        llm = ChatOpenAI(
            model=selected_model,
            base_url=base_url or os.getenv("CASE_ANALYZER_BASE_URL") or os.getenv("OPENAI_BASE_URL"),
            api_key=selected_key,
            temperature=0,
            max_retries=0,
            timeout=timeout,
        )
        structured_llm = llm.with_structured_output(InvestigationReport)
        return structured_llm.invoke(
            build_analysis_messages(case, knowledge_records=knowledge_records, user_input=user_input)
        )
    except ValidationError as exc:
        raise LLMProviderError(
            "The model response did not match the InvestigationReport schema: "
            f"{_validation_summary(exc)}.",
            6,
        ) from exc
    except AuthenticationError as exc:
        raise LLMProviderError("LLM authentication failed; check the configured API key.", 3) from exc
    except RateLimitError as exc:
        raise LLMProviderError(
            "LLM rate limit or quota was exceeded; retry later or check provider limits.", 4
        ) from exc
    except APITimeoutError as exc:
        raise LLMProviderError("LLM request timed out; check the endpoint and try again.", 5) from exc
    except APIConnectionError as exc:
        raise LLMProviderError("Could not connect to the LLM endpoint; check the URL and network.", 5) from exc
    except APIStatusError as exc:
        raise LLMProviderError(f"LLM provider returned HTTP {exc.status_code}.", 6) from exc
    except OpenAIError as exc:
        raise LLMProviderError(f"LLM request failed ({type(exc).__name__}).", 6) from exc
