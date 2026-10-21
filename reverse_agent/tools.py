"""Tool layer for the DeepSeek-driven reverse-engineering agent.

Defines the OpenAI-style tool schemas DeepSeek can call and a dispatcher that
maps each call onto the IDA Pro MCP client, a findings notebook, and a
sandboxed code-execution layer (run_python / run_bash) for anything the fixed
IDA toolset doesn't cover. This is what turns DeepSeek into an agent that
actually drives IDA to reverse-engineer the binary — deliberately binary-only:
no packet capture is available here (see graph.py's docstring for why).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field, asdict
from typing import Any

from .ida_client import IDAClient
from .tasks import TaskTracker, DEFAULT_STAGES, AGENT_GATED_STAGES
from . import verify as verify_mod

SANDBOX_TIMEOUT_S = 60
SANDBOX_OUTPUT_LIMIT = 6000


MAX_RESULT_CHARS = 7000

# Categories whose claims are about exact binary layout (struct fields, table
# strides, frame formats) — these must be backed by TWO independent sources
# (raw bytes + disassembly), per the RE plan's off-by-one-in-dispatch-table
# lesson. record_finding rejects these without evidence attached.
TWO_SOURCE_CATEGORIES = {"dispatch", "structure", "frame_format"}

# Which RE-plan stage a finding category belongs to, for auto-touching the
# task tracker (see tasks.TaskTracker.touch_stage).
_STAGE_FOR_CATEGORY = {
    "crypto": "crypto", "auth": "crypto", "key_exchange": "crypto",
    "dispatch": "protocol_dispatch", "structure": "protocol_dispatch",
    "frame_format": "protocol_dispatch",
}


def _truncate(text: str, limit: int = MAX_RESULT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit} chars]"


# ---------------------------------------------------------------------------
# Tool schemas (OpenAI function-calling format)
# ---------------------------------------------------------------------------
def _fn(name, desc, props, required=None):
    return {"type": "function", "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object", "properties": props, "required": required or []},
    }}


TOOL_SCHEMAS = [
    _fn("get_metadata", "Get binary metadata: path, base, size, hashes, architecture.", {}),
    _fn("get_entry_points", "List program entry points (e.g. _start / main candidates).", {}),
    _fn("list_functions", "List functions (paginated). Use to survey the binary.",
        {"offset": {"type": "integer", "description": "start index (default 0)"},
         "count": {"type": "integer", "description": "how many (default 100, max 400)"}}),
    _fn("get_function_by_name", "Resolve a function by name to its address/info.",
        {"name": {"type": "string"}}, ["name"]),
    _fn("decompile", "Decompile the function containing an address to C pseudocode. Your primary RE tool.",
        {"address": {"type": "string", "description": "hex address, e.g. 0x805a590"}}, ["address"]),
    _fn("disassemble_function", "Disassemble the function containing an address (assembly listing).",
        {"address": {"type": "string"}}, ["address"]),
    _fn("get_xrefs_to", "List code cross-references to an address (who calls/uses it).",
        {"address": {"type": "string"}}, ["address"]),
    _fn("list_strings", "List strings in the binary (paginated).",
        {"offset": {"type": "integer"}, "count": {"type": "integer", "description": "default 200"}}),
    _fn("get_string_xrefs", "Find strings containing a substring and the code that references them.",
        {"substring": {"type": "string"}}, ["substring"]),
    _fn("list_network_strings", "List strings that look network-relevant (domains, URLs, verbs, socket keywords).", {}),
    _fn("find_syscall_sites", "Locate int-0x80 syscalls, classified (socketcall sub-functions etc.).", {}),
    _fn("find_immediate_refs", "Find code that uses given 32-bit integers as immediates (packed IPs, magic constants, ports).",
        {"values": {"type": "array", "items": {"type": "integer"}}}, ["values"]),
    _fn("find_byte_pattern", "Find a raw byte sequence (hex string) in the image; returns addresses.",
        {"hex_pattern": {"type": "string", "description": "e.g. '08080808' or 'expand 32-byte k' as hex"}}, ["hex_pattern"]),
    _fn("read_bytes", "Read N bytes at an address, returned as hex (for keys, nonces, tables).",
        {"address": {"type": "string"}, "size": {"type": "integer"}}, ["address", "size"]),
    _fn("rename_function", "Rename a function in the IDA database to a meaningful name (valid C identifier). Do this as you understand functions.",
        {"address": {"type": "string"}, "new_name": {"type": "string"}}, ["address", "new_name"]),
    _fn("set_comment", "Attach an explanatory comment at an address in the IDA database.",
        {"address": {"type": "string"}, "comment": {"type": "string"}}, ["address", "comment"]),
    _fn("run_python",
        "Execute a Python snippet in a subprocess for anything the fixed IDA toolset doesn't cover: custom crypto/format verification, scratch calculations, or "
        "ad-hoc analysis of raw bytes. `unicorn`, `capstone`, `Crypto` (pycryptodome), and `hashlib` are importable. The binary's own file path is available as the "
        "variable `BINARY_PATH` (str) — open it directly with `open(BINARY_PATH, 'rb')` for anything you need straight from the file (e.g. independent ELF header "
        "parsing) rather than trusting a single source. Print whatever you want to see; stdout/stderr are returned. This stage is binary-only by design — network "
        "code (sockets, HTTP clients, etc.) is rejected; live C2 connectivity is a separate, deliberate, opt-in step on the generated client, not something to "
        f"reach for mid-exploration. Times out after {SANDBOX_TIMEOUT_S}s.",
        {"code": {"type": "string", "description": "Python source to execute"}},
        ["code"]),
    _fn("run_bash",
        "Run a shell command in a subprocess — e.g. `file`, `sha256sum`/`shasum`, `strings`, or any other CLI tool available on this machine, per the triage stage of "
        f"the plan. Network commands are rejected (same reasoning as run_python). Times out after {SANDBOX_TIMEOUT_S}s.",
        {"command": {"type": "string", "description": "shell command to run"}},
        ["command"]),
    _fn("record_finding",
        "Record a structured finding into your analysis notebook. Call this whenever you conclude something concrete about the binary — it becomes the basis of the report and client. "
        "Findings in category dispatch/structure/frame_format MUST include a 'layout_evidence' object from two_source_layout_check (bytes + independent disasm) — call that tool first. "
        "Findings in category crypto MUST include 'emulation_verified' (true/false) — run verify_primitive first if a reference implementation exists; if none exists, set it false and say so plainly instead of claiming an RFC match.",
        {"category": {"type": "string",
                      "description": "one of: overview, config, crypto, endpoint, transport, auth, key_exchange, frame_format, dispatch, attack, protocol_strings, structure, indicator, gap"},
         "title": {"type": "string"},
         "detail": {"type": "string", "description": "precise technical description, with values (keys, magics, offsets, formats)"},
         "addresses": {"type": "array", "items": {"type": "string"}, "description": "relevant hex addresses / IDA symbols"},
         "confidence": {"type": "string", "description": "high|medium|low"},
         "layout_evidence": {"type": "object", "description": "REQUIRED for dispatch/structure/frame_format: output of two_source_layout_check"},
         "emulation_verified": {"type": "boolean", "description": "REQUIRED for crypto: whether verify_primitive confirmed a match against a reference implementation"}},
        ["category", "title", "detail"]),
    _fn("two_source_layout_check",
        "Cross-check a struct/table/frame layout claim against TWO independent sources: raw bytes (read_bytes) AND an independent Capstone disassembly of those same bytes, alongside IDA's own disassembly. "
        "Use this BEFORE recording any dispatch/structure/frame_format finding — this is what catches an off-by-one in a dispatch table.",
        {"address": {"type": "string"}, "size": {"type": "integer", "description": "bytes to read/disassemble, e.g. table_size*entry_size"}},
        ["address", "size"]),
    _fn("verify_primitive",
        "Execute the REAL binary function in a Unicorn emulator (binary's actual segments mapped in) against test input, and diff the output against a pycryptodome/hashlib reference implementation. "
        "This is the ONLY thing that counts as 'verified' for a crypto primitive — matching your own Python against an RFC vector says nothing about what this binary does. "
        "Supported primitive names: md5, sha1, sha256, rc4, chacha20, aes-ecb, xor. Assumes cdecl calling convention with args (buf_ptr,buf_len[,key_ptr,key_len],out_ptr) — if the real signature "
        "differs, this will legitimately fail; record the mismatch honestly rather than retrying blindly.",
        {"function_address": {"type": "string"}, "primitive": {"type": "string"},
         "input_hex": {"type": "string", "description": "test input bytes as hex"},
         "key_hex": {"type": "string", "description": "key/nonce bytes as hex, if the primitive takes one"},
         "out_size": {"type": "integer", "description": "expected output size in bytes (default: reference digest/ciphertext length)"}},
        ["function_address", "primitive", "input_hex"]),
    _fn("plan_tasks",
        "Populate your subtask tracker for the RE plan's stages. Call this ONCE near the start with concrete, binary-specific tasks grouped under stages: "
        + ", ".join(DEFAULT_STAGES) + ". You must cover every stage with at least one task before you may finish.",
        {"items": {"type": "array", "items": {
            "type": "object",
            "properties": {"stage": {"type": "string"}, "title": {"type": "string"}},
            "required": ["stage", "title"]}}},
        ["items"]),
    _fn("update_task",
        "Update a subtask's status as you make progress. Use 'blocked' (with a note explaining why) instead of silently dropping a hard stage (e.g. crypto verification) — a stated blocker is honest, a dropped stage is not.",
        {"task_id": {"type": "integer"}, "status": {"type": "string", "description": "pending|in_progress|done|blocked"},
         "note": {"type": "string"}},
        ["task_id", "status"]),
    _fn("list_tasks", "List your current subtask tracker (all stages/tasks and their status).", {}),
    _fn("finish",
        "Call when the binary is sufficiently reverse-engineered to write the report and client. Refused if any RE-plan stage has no tasks, or has tasks stuck pending/in_progress with no 'blocked' "
        "explanation. Provide a short overall summary.",
        {"summary": {"type": "string"}}, ["summary"]),
]


@dataclass
class Finding:
    category: str
    title: str
    detail: str
    addresses: list[str] = field(default_factory=list)
    confidence: str = "medium"


class ToolDispatcher:
    # Idempotent read-only tools whose results can be cached within a run.
    CACHEABLE = {
        "get_metadata", "get_entry_points", "list_functions", "get_function_by_name",
        "decompile", "disassemble_function", "get_xrefs_to", "list_strings",
        "get_string_xrefs", "list_network_strings", "find_syscall_sites",
        "find_immediate_refs", "find_byte_pattern", "read_bytes",
    }

    def __init__(self, client: IDAClient, binary_path: str = ""):
        self.client = client
        self.binary_path = binary_path
        self.findings: list[Finding] = []
        self.annotations: list[dict] = []
        self.finished = False
        self.finish_summary = ""
        self.call_count = 0
        self._cache: dict[str, str] = {}
        self.tasks = TaskTracker()
        self.emulation_results: list[dict] = []
        # Titles of findings rejected for missing layout_evidence, so an
        # identical resubmission under a different category (the observed
        # dodge) is still caught.
        self._rejected_layout_claims: set[str] = set()

    # -- main entry ----------------------------------------------------------
    def dispatch(self, name: str, arguments: dict) -> str:
        self.call_count += 1
        key = name + ":" + json.dumps(arguments, sort_keys=True, default=str)
        if name in self.CACHEABLE and key in self._cache:
            return self._cache[key] + "\n[note: identical call already made earlier — cached result]"
        try:
            result = self._dispatch(name, arguments)
        except Exception as exc:
            return json.dumps({"error": f"{type(exc).__name__}: {exc}"})
        text = _truncate(result) if isinstance(result, str) else _truncate(json.dumps(result, default=str))
        if name in self.CACHEABLE:
            self._cache[key] = text
        return text

    def _dispatch(self, name: str, args: dict) -> Any:
        c = self.client
        if name == "get_metadata":
            return c.call("get_metadata")
        if name == "get_entry_points":
            return c.call("get_entry_points")
        if name == "list_functions":
            count = min(int(args.get("count", 100)), 400)
            return c.call("list_functions", offset=int(args.get("offset", 0)), count=count)
        if name == "get_function_by_name":
            return c.call("get_function_by_name", name=args["name"])
        if name == "decompile":
            return c.call("decompile", address=args["address"])
        if name == "disassemble_function":
            return c.call("disassemble_function", address=args["address"])
        if name == "get_xrefs_to":
            return c.call("get_xrefs_to", address=args["address"])
        if name == "list_strings":
            count = min(int(args.get("count", 200)), 500)
            return c.call("list_strings", offset=int(args.get("offset", 0)), count=count)
        if name == "get_string_xrefs":
            return c.call("get_string_xrefs", substring=args["substring"])
        if name == "list_network_strings":
            return c.call("list_network_strings")
        if name == "find_syscall_sites":
            return c.call("find_syscall_sites")
        if name == "find_immediate_refs":
            return c.call("find_immediate_refs", values=[int(v) for v in args["values"]])
        if name == "find_byte_pattern":
            return c.call("find_byte_pattern", hex_pattern=args["hex_pattern"])
        if name == "read_bytes":
            return self._read_bytes(args["address"], int(args["size"]))
        if name == "rename_function":
            return self._rename(args["address"], args["new_name"])
        if name == "set_comment":
            return self._comment(args["address"], args["comment"])
        if name == "run_python":
            return self._run_python(args.get("code", ""))
        if name == "run_bash":
            return self._run_bash(args.get("command", ""))
        if name == "record_finding":
            return self._record(args)
        if name == "two_source_layout_check":
            self.tasks.touch_stage("protocol_dispatch")
            return verify_mod.two_source_layout_check(self.client, args["address"], int(args["size"]))
        if name == "verify_primitive":
            self.tasks.touch_stage("crypto")
            return self._verify_primitive(args)
        if name == "plan_tasks":
            return {"ok": True, "tasks": self.tasks.plan(args.get("items", []))}
        if name == "update_task":
            return self.tasks.update(int(args["task_id"]), args.get("status", ""), args.get("note", ""))
        if name == "list_tasks":
            return {"tasks": self.tasks.as_dicts(), "digest": self.tasks.digest()}
        if name == "finish":
            return self._try_finish(args)
        return {"error": f"unknown tool {name}"}

    # -- helpers -------------------------------------------------------------
    def _read_bytes(self, address: str, size: int) -> dict:
        size = max(0, min(size, 1024))
        # Our headless server exposes `read_bytes` (hex + ascii).
        res = self.client.try_call("read_bytes", default=None, address=address, size=size)
        if isinstance(res, dict):
            return res
        return {"address": address, "size": size, "hex": res}

    def _valid_identifier(self, name: str) -> bool:
        return bool(name) and not name[0].isdigit() and all(ch.isalnum() or ch == "_" for ch in name)

    def _rename(self, address: str, new_name: str) -> dict:
        if not self._valid_identifier(new_name):
            return {"error": f"invalid identifier: {new_name!r}"}
        # Use the headless-safe helper (the stock rename_function refreshes the
        # Hex-Rays UI, which breaks the SSE transport under idalib).
        res = self.client.call("rename_func", function_address=address, new_name=new_name)
        if isinstance(res, dict) and not res.get("ok", True):
            return {"error": res.get("error", "rename failed")}
        self.annotations.append({"address": address, "action": "rename_function", "value": new_name})
        return {"ok": True, "renamed": address, "to": new_name}

    def _comment(self, address: str, comment: str) -> dict:
        self.client.call("set_comment_at", address=address, comment=comment)
        self.annotations.append({"address": address, "action": "comment", "value": comment})
        return {"ok": True, "address": address}

    def _record(self, args: dict) -> dict:
        category = args.get("category", "overview")
        title = args.get("title", "")
        ev = args.get("layout_evidence")
        has_evidence = isinstance(ev, dict) and ev.get("bytes_hex") and (ev.get("capstone_disasm") or ev.get("ida_disasm"))

        needs_layout_evidence = category in TWO_SOURCE_CATEGORIES
        if not needs_layout_evidence:
            # Resubmission memory: this is the SAME claim (identical title) as
            # something already rejected for missing evidence, just filed
            # under a different category. Deliberately narrow: no keyword scan
            # (caught ordinary words like "entry" in "entry point" and
            # rejected unrelated overview/endpoint findings), and no address
            # overlap either (two genuinely different findings routinely cite
            # the same address for context — e.g. a global-state finding and a
            # dispatch-table finding both mention a neighboring symbol; that's
            # not a resubmission). Exact title match is the one signal narrow
            # enough not to collide with legitimate, unrelated findings.
            if title and title in self._rejected_layout_claims:
                needs_layout_evidence = True

        if needs_layout_evidence and not has_evidence:
            if title:
                self._rejected_layout_claims.add(title)
            reason = (f"category '{category}' is a binary-layout claim" if category in TWO_SOURCE_CATEGORIES
                     else "this matches a dispatch/structure/frame_format finding you already tried to "
                          "record and that was rejected for missing evidence — relabeling its category "
                          "does not satisfy the requirement")
            return {"error": f"{reason}, and requires 'layout_evidence' from two_source_layout_check "
                             "with both bytes_hex and a disasm listing populated. Call "
                             "two_source_layout_check(address, size) first, then retry record_finding "
                             "with the category you actually mean."}

        if category == "crypto" and "emulation_verified" not in args:
            return {"error": "category 'crypto' requires 'emulation_verified' (true/false). "
                             "Call verify_primitive first if a reference implementation exists for this "
                             "primitive; if none exists, pass emulation_verified=false and say so in 'detail' "
                             "instead of claiming an RFC match."}

        if category in _STAGE_FOR_CATEGORY:
            self.tasks.touch_stage(_STAGE_FOR_CATEGORY[category])

        f = Finding(
            category=category,
            title=args.get("title", ""),
            detail=args.get("detail", ""),
            addresses=args.get("addresses", []) or [],
            confidence=args.get("confidence", "medium"),
        )
        self.findings.append(f)
        result = {"ok": True, "recorded": f.title, "total_findings": len(self.findings)}
        if category == "crypto" and args.get("emulation_verified") is False:
            result["note"] = "recorded as NOT verified — make sure the report says so plainly, not 'matches RFC'"
        return result

    def _verify_primitive(self, args: dict) -> dict:
        v = verify_mod.verify_primitive(
            self.client, args["function_address"], args["primitive"], args["input_hex"],
            key_hex=args.get("key_hex", ""), out_size=int(args.get("out_size", 0) or 0),
        )
        rec = {"function_address": args["function_address"], "primitive": args["primitive"],
               "verified": v.verified, "reason": v.reason,
               "emulated_hex": v.emulated_hex, "reference_hex": v.reference_hex}
        self.emulation_results.append(rec)
        return rec

    def _try_finish(self, args: dict) -> dict:
        open_stages = self.tasks.open_stages(AGENT_GATED_STAGES)
        if open_stages:
            return {"error": "cannot finish yet — these RE-plan stages still have unresolved tasks: "
                             + ", ".join(open_stages) + ". Either complete them, or mark the remaining "
                             "task(s) 'blocked' with a note explaining why (an honest blocker is fine; "
                             "a silently dropped stage is not)."}

        has_crypto_findings = any(f.category == "crypto" for f in self.findings)
        if has_crypto_findings and not self.emulation_results:
            return {"error": "cannot finish yet — you have crypto findings but never called "
                             "verify_primitive, so none of them are backed by real execution. Either run "
                             "verify_primitive against at least one identified primitive, or if none of "
                             "your crypto findings can be verified this way, say so explicitly in the "
                             "finding details (not silently)."}

        self.finished = True
        self.finish_summary = args.get("summary", "")
        return {"ok": True}

    # -- sandboxed code execution --------------------------------------------
    _NETWORK_TOKENS = (
        "socket", "urllib", "requests", "http.client", "httplib", "ftplib", "smtplib",
        "telnetlib", "paramiko", "asyncio.open_connection", "curl ", "wget ", " nc ",
        "netcat", "ssh ", "scp ",
    )

    def _reject_if_networky(self, text: str) -> str | None:
        low = text.lower()
        for tok in self._NETWORK_TOKENS:
            if tok in low:
                return (f"rejected: contains {tok!r} — this stage is binary-only. Live C2 "
                        "connectivity is a separate, deliberate, opt-in step on the generated "
                        "client (--live-connect-test), not something to reach for mid-exploration.")
        return None

    def _run_python(self, code: str) -> dict:
        veto = self._reject_if_networky(code)
        if veto:
            return {"error": veto}
        prelude = (
            "import sys\n"
            f"BINARY_PATH = {self.binary_path!r}\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
            fh.write(prelude + code)
            path = fh.name
        try:
            proc = subprocess.run([sys.executable, path], capture_output=True, text=True,
                                  timeout=SANDBOX_TIMEOUT_S)
            out = (proc.stdout + proc.stderr)[-SANDBOX_OUTPUT_LIMIT:]
            return {"exit_code": proc.returncode, "output": out}
        except subprocess.TimeoutExpired:
            return {"error": f"timed out after {SANDBOX_TIMEOUT_S}s"}
        finally:
            os.unlink(path)

    def _run_bash(self, command: str) -> dict:
        veto = self._reject_if_networky(command)
        if veto:
            return {"error": veto}
        try:
            proc = subprocess.run(command, shell=True, capture_output=True, text=True,
                                  timeout=SANDBOX_TIMEOUT_S)
            out = (proc.stdout + proc.stderr)[-SANDBOX_OUTPUT_LIMIT:]
            return {"exit_code": proc.returncode, "output": out}
        except subprocess.TimeoutExpired:
            return {"error": f"timed out after {SANDBOX_TIMEOUT_S}s"}

    # -- state for synthesis -------------------------------------------------
    def findings_as_dicts(self) -> list[dict]:
        return [asdict(f) for f in self.findings]

    def findings_digest(self, limit: int = 60) -> str:
        """Compact notebook rendering, injected back into the model each turn."""
        if not self.findings:
            return "(empty)"
        lines = []
        for i, f in enumerate(self.findings[-limit:]):
            addrs = (" @ " + ", ".join(f.addresses[:6])) if f.addresses else ""
            lines.append(f"- [{f.category}] {f.title}{addrs}")
        return "\n".join(lines)
