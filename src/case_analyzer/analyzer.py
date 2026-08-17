import json
import os
from importlib.resources import files
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv

from .schemas import CanonicalCase, InvestigationReport


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
    llm = ChatOpenAI(
        model=selected_model,
        base_url=base_url or os.getenv("CASE_ANALYZER_BASE_URL") or os.getenv("OPENAI_BASE_URL"),
        api_key=api_key or os.getenv("CASE_ANALYZER_API_KEY") or os.getenv("OPENAI_API_KEY"),
        temperature=0,
    )
    structured_llm = llm.with_structured_output(InvestigationReport)
    return structured_llm.invoke(
        build_analysis_messages(case, knowledge_records=knowledge_records, user_input=user_input)
    )
