"""Runtime configuration for reverse_agent, sourced from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv() -> None:
    """Load KEY=VALUE lines from a local .env file into os.environ (without
    overriding variables already set in the environment). Looks in the current
    working directory and the project root. No external dependency."""
    seen: set[Path] = set()
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]
    for path in candidates:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved in seen or not resolved.is_file():
            continue
        seen.add(resolved)
        for raw in resolved.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val


_load_dotenv()


def _env(name: str, default: str) -> str:
    val = os.environ.get(name)
    return val if val else default


@dataclass
class Config:
    # DeepSeek LLM (OpenAI-compatible API).
    deepseek_api_key: str = field(default_factory=lambda: os.environ.get("DEEPSEEK_API_KEY", ""))
    deepseek_base_url: str = field(default_factory=lambda: _env("DEEPSEEK_BASE_URL", "https://api.deepseek.com"))
    deepseek_model: str = field(default_factory=lambda: _env("DEEPSEEK_MODEL", "deepseek-v4-flash"))
    # "low" | "medium" | "high"; forwarded to the API as reasoning_effort.
    reasoning_effort: str = field(default_factory=lambda: _env("DEEPSEEK_REASONING_EFFORT", "high"))
    # Disable DeepSeek "thinking" tokens by default to keep latency/cost predictable.
    thinking_enabled: bool = field(default_factory=lambda: _env("DEEPSEEK_THINKING", "disabled") == "enabled")

    # IDA Pro MCP (headless idalib server).
    ida_host: str = field(default_factory=lambda: _env("IDA_MCP_HOST", "127.0.0.1"))
    ida_port: int = field(default_factory=lambda: int(_env("IDA_MCP_PORT", "8745")))

    # When True, the LLM node is skipped and a deterministic heuristic mapper is
    # used instead. Useful for CI / running without a DeepSeek key.
    offline: bool = False

    @property
    def has_llm(self) -> bool:
        return bool(self.deepseek_api_key) and not self.offline

    @property
    def ida_url(self) -> str:
        """MCP endpoint (streamable-http transport)."""
        return f"http://{self.ida_host}:{self.ida_port}/mcp"

    # Backwards-compatible alias.
    @property
    def ida_sse_url(self) -> str:
        return self.ida_url
