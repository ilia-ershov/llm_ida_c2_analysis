"""DeepSeek LLM client — the agent's orchestrator / semantic mapper.

Thin wrapper over the OpenAI SDK pointed at the DeepSeek API. Provides plain
text completion and a JSON-mode helper with light retry / repair.
"""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any

from .config import Config


class LLMError(RuntimeError):
    pass


# Hard wall-clock ceiling per API call, enforced in a background thread
# rather than relying on httpx's read-timeout: DeepSeek's reasoning models
# appear to trickle keep-alive bytes during long "thinking" phases, which
# resets httpx's per-chunk read timeout even though no real content has
# arrived — observed live as a 180s httpx timeout never firing across a 1+
# hour hang. A thread-based deadline bounds total wait time regardless of
# what the transport does internally.
#
# Deliberately a plain daemon Thread, NOT concurrent.futures.ThreadPoolExecutor:
# the executor's worker threads are non-daemon, and Python registers an
# atexit hook that joins every outstanding worker before the interpreter can
# exit — so if a call is genuinely stuck, giving up on future.result(timeout=)
# only stops OUR wait; the process itself would still hang at exit waiting
# for that thread. A daemon thread is simply abandoned on process exit.
_CALL_DEADLINE_S = 240.0


def _call_with_deadline(fn, *, deadline: float = _CALL_DEADLINE_S):
    box: dict = {}

    def runner():
        try:
            box["value"] = fn()
        except Exception as exc:  # noqa: BLE001 - re-raised on the calling thread
            box["error"] = exc

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    t.join(timeout=deadline)
    if t.is_alive():
        raise TimeoutError(f"DeepSeek call exceeded {deadline:.0f}s wall-clock deadline")
    if "error" in box:
        raise box["error"]
    return box.get("value")


class DeepSeek:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError as exc:  # pragma: no cover
                raise LLMError("openai SDK not installed (pip install openai)") from exc
            if not self.cfg.deepseek_api_key:
                raise LLMError("DEEPSEEK_API_KEY is not set")
            self._client = OpenAI(
                api_key=self.cfg.deepseek_api_key,
                base_url=self.cfg.deepseek_base_url,
                # Without an explicit timeout a stalled connection (dropped
                # packet, server-side hang) blocks forever with no exception —
                # observed live as a multi-hour hang with ~0% CPU and no log
                # growth. 180s is generous for a single completion even with
                # a large tool-call context; the retry loop in chat()/complete()
                # then gets a real chance to back off and retry.
                timeout=180.0,
            )
        return self._client

    def _extra_body(self) -> dict:
        return {"thinking": {"type": "enabled" if self.cfg.thinking_enabled else "disabled"}}

    def complete(self, system: str, user: str, *, temperature: float = 0.2,
                 max_tokens: int = 4096, retries: int = 3) -> str:
        last_err = None
        for attempt in range(retries):
            try:
                resp = _call_with_deadline(lambda: self.client.chat.completions.create(
                    model=self.cfg.deepseek_model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    stream=False,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    reasoning_effort=self.cfg.reasoning_effort,
                    extra_body=self._extra_body(),
                ))
                return resp.choices[0].message.content or ""
            except Exception as exc:  # network / rate limit / API / deadline
                last_err = exc
                time.sleep(1.5 * (attempt + 1))
        raise LLMError(f"DeepSeek completion failed after {retries} tries: {last_err}")

    def chat(self, messages: list, *, tools: list | None = None,
             tool_choice: str = "auto", temperature: float = 0.2,
             max_tokens: int = 4096, retries: int = 3):
        """Low-level chat turn for the agentic loop. Returns the raw response
        message object (has ``.content`` and ``.tool_calls``)."""
        last_err = None
        for attempt in range(retries):
            try:
                kwargs = dict(
                    model=self.cfg.deepseek_model,
                    messages=messages,
                    stream=False,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    reasoning_effort=self.cfg.reasoning_effort,
                    extra_body=self._extra_body(),
                )
                if tools:
                    kwargs["tools"] = tools
                    kwargs["tool_choice"] = tool_choice
                resp = _call_with_deadline(lambda: self.client.chat.completions.create(**kwargs))
                return resp.choices[0].message
            except Exception as exc:
                last_err = exc
                time.sleep(1.5 * (attempt + 1))
        raise LLMError(f"DeepSeek chat failed after {retries} tries: {last_err}")

    def json(self, system: str, user: str, *, max_tokens: int = 4096) -> Any:
        """Request a JSON response and parse it, tolerating code fences / prose."""
        sys_json = system + (
            "\n\nRespond with a single valid JSON value and nothing else. "
            "Do not wrap it in markdown fences or add commentary."
        )
        text = self.complete(sys_json, user, temperature=0.1, max_tokens=max_tokens)
        return _extract_json(text)


def _extract_json(text: str) -> Any:
    text = text.strip()
    # Strip ```json ... ``` fences if present.
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    # Fall back to the first balanced {...} or [...] block.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(text)):
            if text[i] == opener:
                depth += 1
            elif text[i] == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except Exception:
                        break
    raise LLMError(f"could not parse JSON from LLM response: {text[:200]!r}")
