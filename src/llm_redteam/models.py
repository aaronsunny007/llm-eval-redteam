"""Chat-model clients and the targets (systems under test) built on them.

Two layers:

* ``ChatModel`` - a raw LLM endpoint. Used by targets, by the LLM-based guards and by
  the judge. Implementations: Ollama, any OpenAI-compatible server, and a scripted
  fake for tests.
* ``Target`` - the application being red-teamed. Either a chat model plus a system
  prompt we control (``ChatTarget``), or an opaque HTTP service such as a deployed RAG
  API (``HTTPTarget``) where only the request/response shape is known.
"""

from __future__ import annotations

import json
import os
import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

import httpx

Messages = list[dict[str, str]]


class ModelError(RuntimeError):
    pass


# --------------------------------------------------------------------------- models


class ChatModel(ABC):
    name: str

    @abstractmethod
    def chat(
        self, messages: Messages, *, json_schema: dict | None = None, max_tokens: int | None = None
    ) -> str: ...


class OllamaChat(ChatModel):
    """Ollama ``/api/chat``. Deterministic by default (temperature 0, fixed seed)."""

    def __init__(
        self,
        model: str,
        base_url: str | None = None,
        temperature: float = 0.0,
        seed: int = 7,
        max_tokens: int = 400,
        num_ctx: int = 4096,
        timeout: float = 600.0,
    ) -> None:
        self.model = model
        self.name = f"ollama:{model}"
        self.base_url = (base_url or os.getenv("OLLAMA_HOST") or "http://localhost:11434").rstrip(
            "/"
        )
        if not self.base_url.startswith("http"):
            self.base_url = "http://" + self.base_url
        self.options = {"temperature": temperature, "seed": seed, "num_ctx": num_ctx}
        self.max_tokens = max_tokens
        self._client = httpx.Client(timeout=timeout)

    def chat(self, messages, *, json_schema=None, max_tokens=None):
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {**self.options, "num_predict": max_tokens or self.max_tokens},
        }
        if json_schema is not None:
            body["format"] = json_schema
        try:
            r = self._client.post(f"{self.base_url}/api/chat", json=body)
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise ModelError(f"{self.name}: {exc}") from exc
        return r.json()["message"]["content"]


class OpenAICompatChat(ChatModel):
    """Any ``/v1/chat/completions`` server (OpenAI, vLLM, LM Studio, Groq, Together...)."""

    def __init__(
        self,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        api_key_env: str = "OPENAI_API_KEY",
        temperature: float = 0.0,
        seed: int = 7,
        max_tokens: int = 400,
        timeout: float = 300.0,
    ) -> None:
        self.model = model
        self.name = f"openai:{model}"
        self.base_url = base_url.rstrip("/")
        self.api_key = os.getenv(api_key_env, "")
        self.temperature, self.seed, self.max_tokens = temperature, seed, max_tokens
        self._client = httpx.Client(timeout=timeout)

    def chat(self, messages, *, json_schema=None, max_tokens=None):
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "seed": self.seed,
            "max_tokens": max_tokens or self.max_tokens,
        }
        if json_schema is not None:
            body["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        try:
            r = self._client.post(f"{self.base_url}/chat/completions", json=body, headers=headers)
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise ModelError(f"{self.name}: {exc}") from exc
        return r.json()["choices"][0]["message"]["content"] or ""


class ScriptedChat(ChatModel):
    """A fake model driven by a Python function. Used by the test suite and CI."""

    def __init__(self, fn: Callable[[Messages], str], name: str = "scripted") -> None:
        self.fn = fn
        self.name = name
        self.calls: list[Messages] = []

    def chat(self, messages, *, json_schema=None, max_tokens=None):
        self.calls.append(messages)
        return self.fn(messages)


def build_chat_model(spec: dict[str, Any]) -> ChatModel:
    """Create a model from a config block such as ``{provider: ollama, model: mistral}``."""
    spec = dict(spec)
    provider = spec.pop("provider", "ollama")
    if provider == "ollama":
        return OllamaChat(**spec)
    if provider in ("openai", "openai_compatible"):
        return OpenAICompatChat(**spec)
    raise ValueError(f"unknown model provider {provider!r}")


# --------------------------------------------------------------------------- targets


def render_plain(prompt: str, context: list[str]) -> str:
    """The default, undefended way a RAG app pastes retrieved documents into the prompt."""
    if not context:
        return prompt
    docs = "\n\n".join(f"[Document {i}]\n{doc}" for i, doc in enumerate(context, start=1))
    return f"Retrieved documents:\n\n{docs}\n\nUser question: {prompt}"


class Target(ABC):
    name: str
    #: Whether the harness controls the system prompt (needed by prompt-level defences).
    controls_prompt: bool = False

    @abstractmethod
    def respond(
        self,
        prompt: str,
        context: list[str],
        *,
        system_prompt: str | None = None,
        render: Callable[[str, list[str]], str] = render_plain,
        suffix: str | None = None,
    ) -> str: ...


class ChatTarget(Target):
    """A chat model wrapped in an application system prompt."""

    controls_prompt = True

    def __init__(self, model: ChatModel, system_prompt: str) -> None:
        self.model = model
        self.system_prompt = system_prompt
        self.name = model.name

    def respond(self, prompt, context, *, system_prompt=None, render=render_plain, suffix=None):
        user = render(prompt, context)
        if suffix:
            user = f"{user}\n\n{suffix}"
        messages = [
            {"role": "system", "content": system_prompt or self.system_prompt},
            {"role": "user", "content": user},
        ]
        return self.model.chat(messages)


_PLACEHOLDER = re.compile(r"\$\{(prompt|context|context_text|ENV:[A-Za-z_][A-Za-z0-9_]*)\}")


class HTTPTarget(Target):
    """An opaque JSON-over-HTTP application, e.g. a deployed RAG service.

    ``body`` is a JSON template. String values may contain ``${prompt}``,
    ``${context_text}`` (documents joined by blank lines) or ``${ENV:NAME}``; a value that
    is exactly ``"${context}"`` is replaced by the list of documents. ``response_path`` is
    a dotted path into the JSON response, e.g. ``answer`` or ``data.choices.0.text``.
    """

    def __init__(
        self,
        url: str,
        body: dict[str, Any] | None = None,
        response_path: str = "answer",
        headers: dict[str, str] | None = None,
        timeout: float = 120.0,
        name: str | None = None,
    ) -> None:
        self.url = url
        self.body = body or {"prompt": "${prompt}", "context": "${context}"}
        self.response_path = response_path
        self.headers = headers or {}
        self.name = name or f"http:{url}"
        self._client = httpx.Client(timeout=timeout)

    def _fill(self, value: Any, prompt: str, context: list[str]) -> Any:
        if isinstance(value, dict):
            return {k: self._fill(v, prompt, context) for k, v in value.items()}
        if isinstance(value, list):
            return [self._fill(v, prompt, context) for v in value]
        if not isinstance(value, str):
            return value
        if value == "${context}":
            return context

        def sub(m: re.Match[str]) -> str:
            key = m.group(1)
            if key == "prompt":
                return prompt
            if key in ("context", "context_text"):
                return "\n\n".join(context)
            return os.getenv(key[4:], "")

        return _PLACEHOLDER.sub(sub, value)

    def respond(self, prompt, context, *, system_prompt=None, render=render_plain, suffix=None):
        if suffix:
            prompt = f"{prompt}\n\n{suffix}"
        body = self._fill(self.body, prompt, context)
        headers = {k: self._fill(v, prompt, context) for k, v in self.headers.items()}
        try:
            r = self._client.post(self.url, json=body, headers=headers)
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise ModelError(f"{self.name}: {exc}") from exc
        node: Any = r.json()
        for part in self.response_path.split("."):
            node = node[int(part)] if isinstance(node, list) else node[part]
        return node if isinstance(node, str) else json.dumps(node)
