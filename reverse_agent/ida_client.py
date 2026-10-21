"""Synchronous client for the IDA Pro MCP server (streamable-http transport).

Runs a dedicated asyncio event loop in a background thread and keeps one MCP
session open, exposing a simple blocking ``call(tool, **args)`` interface so the
LangGraph nodes (which are plain synchronous functions) can drive IDA.

Uses the streamable-http transport rather than SSE: SSE keeps a long-lived
chunked GET stream that intermittently drops under rapid tool calls, killing the
session mid-analysis. streamable-http is request/response and far more robust.
"""
from __future__ import annotations

import asyncio
import json
import threading
import time
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


def _is_transport_error(exc: Exception) -> bool:
    name = type(exc).__name__
    text = str(exc)
    return (name in ("ClosedResourceError", "BrokenResourceError", "ConnectionError", "TimeoutError")
            or "ClosedResourceError" in text or "peer closed" in text
            or "connection" in text.lower())


class IDAClient:
    def __init__(self, sse_url: str, connect_timeout: float = 60.0):
        self.sse_url = sse_url
        self.connect_timeout = connect_timeout
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._session: ClientSession | None = None
        self._ctx_stack: list[Any] = []
        self._tools: list[str] = []

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _submit(self, coro, timeout: float = 120.0):
        # Without a timeout, a wedged MCP call (dropped connection the
        # transport doesn't notice, a decompile that hangs IDA) blocks this
        # thread's .result() forever with no exception and no log output —
        # observed live as a multi-hour silent hang. A bounded wait means a
        # stuck call surfaces as a real, catchable error instead.
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout=timeout)

    # -- lifecycle -----------------------------------------------------------
    def connect(self) -> "IDAClient":
        """Wait for the server to accept SSE connections, then open a session."""
        deadline = time.time() + self.connect_timeout
        last_err = None
        while time.time() < deadline:
            try:
                self._submit(self._open())
                return self
            except Exception as exc:  # server not up yet
                last_err = exc
                time.sleep(1.0)
        raise RuntimeError(f"could not connect to IDA MCP at {self.sse_url}: {last_err}")

    async def _open(self):
        self._read_ctx = streamablehttp_client(self.sse_url)
        # streamablehttp_client yields (read, write, get_session_id_callback).
        read, write, *_ = await self._read_ctx.__aenter__()
        self._ctx_stack.append(self._read_ctx)
        self._session_ctx = ClientSession(read, write)
        self._session = await self._session_ctx.__aenter__()
        self._ctx_stack.append(self._session_ctx)
        await self._session.initialize()
        tools = await self._session.list_tools()
        self._tools = [t.name for t in tools.tools]

    def close(self):
        try:
            self._submit(self._close())
        except Exception:
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)

    async def _close(self):
        for ctx in reversed(self._ctx_stack):
            try:
                await ctx.__aexit__(None, None, None)
            except Exception:
                pass
        self._ctx_stack.clear()

    # -- calls ---------------------------------------------------------------
    @property
    def tools(self) -> list[str]:
        return list(self._tools)

    def call(self, tool: str, **arguments) -> Any:
        """Invoke an MCP tool and return its parsed result (JSON if possible).

        On a transient transport drop (the FastMCP SSE stream occasionally
        resets under load) reconnect once and retry, so a single hiccup does not
        abort a long analysis or lose the final database save."""
        try:
            return self._submit(self._call(tool, arguments))
        except Exception as exc:
            if not _is_transport_error(exc):
                raise
            try:
                self._submit(self._reopen())
            except Exception:
                raise exc
            return self._submit(self._call(tool, arguments))

    async def _reopen(self):
        # Best-effort teardown, then a fresh SSE session to the same server.
        try:
            await self._close()
        except Exception:
            pass
        await self._open()

    async def _call(self, tool: str, arguments: dict) -> Any:
        result = await self._session.call_tool(tool, arguments)
        if result.isError:
            texts = [c.text for c in result.content if getattr(c, "type", None) == "text"]
            raise RuntimeError(f"tool {tool} failed: {' '.join(texts) or result.content}")
        # Prefer structured content: FastMCP always populates this for tools
        # with an output schema, wrapping non-object returns under 'result'.
        sc = getattr(result, "structuredContent", None)
        if sc is not None:
            if isinstance(sc, dict) and set(sc.keys()) == {"result"}:
                return sc["result"]
            return sc
        # No output schema (e.g. untyped-dict returns). Parse the text blocks.
        parts = [c.text for c in result.content if getattr(c, "type", None) == "text"]
        if not parts:
            return None
        joined = "\n".join(parts)
        try:
            return json.loads(joined)
        except Exception:
            return joined

    def try_call(self, tool: str, default=None, **arguments):
        """Like call() but returns `default` on any error (tool missing, etc.)."""
        if tool not in self._tools:
            return default
        try:
            return self.call(tool, **arguments)
        except Exception:
            return default
