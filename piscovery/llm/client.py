import asyncio
import http.client
import json
import ssl
import urllib.error
import urllib.request
from typing import Optional

from ..core.models import Config, LLMAnalysis, PageInfo
from .prompt import SYSTEM_PROMPT, _build_page_summary, _parse_analysis


def _call_llm(
    config: Config,
    messages: list,
    temperature: float = 0.3,
    json_mode: bool = False,
) -> Optional[str]:
    url = f"{config.llm_base_url.rstrip('/')}/chat/completions"
    payload: dict = {
        "model": config.llm_model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": 4096,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {config.llm_api_key}",
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=config.llm_timeout, context=ctx) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return body["choices"][0]["message"]["content"]
    except (urllib.error.URLError, OSError, KeyError, ValueError, TimeoutError, http.client.HTTPException):
        return None


async def check_llm(config: Config) -> bool:
    try:
        result = await asyncio.to_thread(
            _call_llm, config,
            [{"role": "user", "content": "Reply with OK"}],
            0.0,
        )
        return result is not None
    except Exception:
        return False


async def analyse_page(config: Config, page: PageInfo) -> LLMAnalysis:
    summary = _build_page_summary(page)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Analyse this HTTP packet capture for pentest reconnaissance:\n\n{summary}"},
    ]

    raw = await asyncio.to_thread(_call_llm, config, messages, 0.3, True)
    if raw is None:
        return LLMAnalysis(description="[LLM analysis failed]")

    return _parse_analysis(raw)
