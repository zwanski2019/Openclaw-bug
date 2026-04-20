"""LLM client: OpenRouter primary, Ollama fallback for sensitive data.

Task-type routing:
  - planner  → smart model (claude-3.5 / gpt-4)
  - analyzer → cheap/free model (llama-3.3 free tier works)
  - report   → smart model
  - local    → Ollama (forced, for scope-sensitive content)
"""
from __future__ import annotations
import json
import httpx
from typing import AsyncIterator, Literal
from tenacity import retry, stop_after_attempt, wait_exponential
from openclaw.config import settings

TaskType = Literal["planner", "analyzer", "report", "local"]


class LLMClient:
    def __init__(self) -> None:
        self._http = httpx.AsyncClient(timeout=120.0)

    def _model_for(self, task: TaskType) -> tuple[str, str]:
        """Returns (backend, model). backend in {'openrouter', 'ollama'}."""
        if task == "local" or not settings.has_openrouter():
            return ("ollama", settings.ollama_model)
        return ("openrouter", {
            "planner": settings.openrouter_model_planner,
            "analyzer": settings.openrouter_model_analyzer,
            "report": settings.openrouter_model_report,
        }[task])

    @retry(stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, min=2, max=10))
    async def complete(
        self,
        messages: list[dict],
        task: TaskType = "planner",
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> str:
        backend, model = self._model_for(task)
        if backend == "openrouter":
            return await self._openrouter_complete(messages, model, temperature, max_tokens)
        return await self._ollama_complete(messages, model, temperature, max_tokens)

    async def stream(
        self,
        messages: list[dict],
        task: TaskType = "planner",
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        backend, model = self._model_for(task)
        if backend == "openrouter":
            async for chunk in self._openrouter_stream(messages, model, temperature, max_tokens):
                yield chunk
        else:
            async for chunk in self._ollama_stream(messages, model, temperature, max_tokens):
                yield chunk

    # ── OpenRouter ─────────────────────────────────────────────
    async def _openrouter_complete(self, messages, model, temp, max_tokens):
        r = await self._http.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.openrouter_api_key}",
                "HTTP-Referer": "https://zwanski.bio",
                "X-Title": "OpenClaw",
            },
            json={
                "model": model,
                "messages": messages,
                "temperature": temp,
                "max_tokens": max_tokens,
            },
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    async def _openrouter_stream(self, messages, model, temp, max_tokens):
        async with self._http.stream(
            "POST",
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.openrouter_api_key}",
                "HTTP-Referer": "https://zwanski.bio",
                "X-Title": "OpenClaw",
            },
            json={
                "model": model,
                "messages": messages,
                "temperature": temp,
                "max_tokens": max_tokens,
                "stream": True,
            },
        ) as r:
            r.raise_for_status()
            async for line in r.aiter_lines():
                if not line.startswith("data: "):
                    continue
                payload = line[6:].strip()
                if payload == "[DONE]":
                    break
                try:
                    delta = json.loads(payload)["choices"][0]["delta"].get("content")
                    if delta:
                        yield delta
                except (json.JSONDecodeError, KeyError, IndexError):
                    continue

    # ── Ollama ─────────────────────────────────────────────────
    async def _ollama_complete(self, messages, model, temp, max_tokens):
        r = await self._http.post(
            f"{settings.ollama_base_url}/api/chat",
            json={
                "model": model,
                "messages": messages,
                "options": {"temperature": temp, "num_predict": max_tokens},
                "stream": False,
            },
        )
        r.raise_for_status()
        return r.json()["message"]["content"]

    async def _ollama_stream(self, messages, model, temp, max_tokens):
        async with self._http.stream(
            "POST",
            f"{settings.ollama_base_url}/api/chat",
            json={
                "model": model,
                "messages": messages,
                "options": {"temperature": temp, "num_predict": max_tokens},
                "stream": True,
            },
        ) as r:
            r.raise_for_status()
            async for line in r.aiter_lines():
                if not line.strip():
                    continue
                try:
                    chunk = json.loads(line)
                    content = chunk.get("message", {}).get("content")
                    if content:
                        yield content
                except json.JSONDecodeError:
                    continue

    async def aclose(self) -> None:
        await self._http.aclose()


# Singleton for convenience
_client: LLMClient | None = None

def get_llm() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient()
    return _client
