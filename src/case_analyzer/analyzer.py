import json
import os
from importlib.resources import files
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv
from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    AuthenticationError,
    OpenAIError,
    RateLimitError,
)

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
        "case": case.model_dump(exclude_none=True),
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


def analyze_case(
    case: CanonicalCase,
    *,
    knowledge_records: list[dict[str, Any]] | None = None,
    user_input: str = "",
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
) -> InvestigationReport:
    # Make the standalone CLI usable without manually exporting provider
    # variables. Existing environment variables retain precedence over .env.
    load_dotenv()
    selected_model = model or os.getenv("CASE_ANALYZER_MODEL") or os.getenv("OPENAI_MODEL")
    if not selected_model:
        raise ValueError("Set CASE_ANALYZER_MODEL or pass --model.")
    try:
        llm = ChatOpenAI(
            model=selected_model,
            base_url=base_url or os.getenv("CASE_ANALYZER_BASE_URL") or os.getenv("OPENAI_BASE_URL"),
            api_key=api_key or os.getenv("CASE_ANALYZER_API_KEY") or os.getenv("OPENAI_API_KEY"),
            temperature=0,
            max_retries=0,
        )
        structured_llm = llm.with_structured_output(InvestigationReport)
        return structured_llm.invoke(
            build_analysis_messages(case, knowledge_records=knowledge_records, user_input=user_input)
        )
    except AuthenticationError as exc:
        raise LLMProviderError("LLM authentication failed; check the configured API key.", 3) from exc
    except RateLimitError as exc:
        raise LLMProviderError("LLM rate limit or quota was exceeded; retry later or check provider limits.", 4) from exc
    except APITimeoutError as exc:
        raise LLMProviderError("LLM request timed out; check the endpoint and try again.", 5) from exc
    except APIConnectionError as exc:
        raise LLMProviderError("Could not connect to the LLM endpoint; check the URL and network.", 5) from exc
    except APIStatusError as exc:
        raise LLMProviderError(f"LLM provider returned HTTP {exc.status_code}.", 6) from exc
    except OpenAIError as exc:
        raise LLMProviderError(f"LLM request failed ({type(exc).__name__}).", 6) from exc
