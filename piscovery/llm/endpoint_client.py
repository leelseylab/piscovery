import asyncio

from ..core.models import Config, EndpointAnalysis, EndpointInfo
from .client import _call_llm
from .endpoint_prompt import SYSTEM_PROMPT, _parse, _summary


async def analyse_endpoint(config: Config, ep: EndpointInfo) -> EndpointAnalysis:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Analyse this endpoint observation:\n\n{_summary(ep)}"},
    ]
    raw = await asyncio.to_thread(_call_llm, config, messages, 0.3, True)
    if raw is None:
        return EndpointAnalysis(description="[LLM endpoint analysis failed]")
    return _parse(raw)
