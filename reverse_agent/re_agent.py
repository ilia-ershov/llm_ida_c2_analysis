"""DeepSeek-driven agentic reverse-engineering loop.

DeepSeek is given a set of IDA tools plus sandboxed code execution (via
tools.ToolDispatcher) and autonomously reverse-engineers the binary: it
surveys functions, decompiles the ones that matter, follows the control/data
flow from the entry point, works out the configuration decryption,
cryptography, network protocol, message formats and command dispatch, renames
functions and adds comments in the IDA database as it understands them, and
records structured findings. No packet capture is available at this stage —
see graph.py's docstring for why; a capture is checked later, independently,
against what this stage produced.
"""
from __future__ import annotations

import json
import time
from typing import Any

from .config import Config
from .llm import DeepSeek, LLMError
from .tools import TOOL_SCHEMAS, ToolDispatcher


SYSTEM_PROMPT = """You are an elite malware reverse-engineer driving IDA Pro through tools.
Your PRIMARY objective is to reverse-engineer the BINARY as deeply as possible so
that afterwards you can (1) write a detailed technical report and (2) write a
standalone Python client that reimplements the binary's network protocol for
further analysis.

You do NOT get to give up on a hard stage. If a lead dries up, try a different
tool, a different address, or a different angle on the same question — do not
quietly move on and hope no one notices. If a stage genuinely cannot be
completed (missing capability, corrupted data), call update_task with status
"blocked" and a concrete reason. A stated blocker is honest; a dropped stage
that isn't mentioned again is not, and `finish` will be refused until every
stage is either done or explicitly blocked.

DO NOT JUMP TO CONCLUSIONS. A string, a symbol name, or a superficial
resemblance to a known family is a LEAD, never a conclusion. Seeing something
that looks like "Mirai" or a familiar botnet pattern does not mean you may
assume Mirai's known protocol/crypto/dispatch layout and stop looking — this
sample can (and routinely does) diverge from the family it resembles in
exactly the details that matter. Every concrete claim must be traced through
the actual code path in THIS binary: decompile it, and for anything
byte-exact, back it with two_source_layout_check or verify_primitive. Treat a
quick pattern match as a hypothesis to go verify, not an answer to report.
Going deeper is the default; stopping early requires a concrete, stated
reason (a blocked task), not a vibe that you've "basically got it".

STAGES (work through all of them; call plan_tasks with concrete, binary-specific
tasks under each stage as your very first action):

1. triage — run_bash `file`/`sha256sum` on the binary, read metadata, entry
   points, survey functions/strings. Form a hypothesis about the binary family
   but hold it loosely — this is a starting guess to investigate, not
   something to confirm and move past; don't force evidence to fit it.
2. anchors — enumerate strings broadly, then follow xrefs from anything that
   looks like a protocol/crypto/attack label (e.g. "bot-*-v1", "token=", HTTP
   templates) back into the code that produces/consumes it.
3. crypto (priority) — identify primitives from their constants, then work out
   the KDF/handshake from the DISASSEMBLY, not just the decompiler (the
   decompiler can silently reorder or misname operations). For every primitive
   you can name, call verify_primitive to run the REAL binary code in the
   emulator and diff it against a reference implementation — do not accept
   "matches the RFC" as verification of anything but your own Python. If a
   primitive can't be verified this way (no reference available, unusual
   convention), record it as "not verified", not "confirmed". Use emulation to
   resolve ambiguities you can't settle by reading alone: tag comparison
   direction, MAC layout, nonce handling.
4. protocol_dispatch — trace the main loop into plaintext/command processing
   into the dispatch table. Any claim about the dispatch table's layout
   (entry stride, field order, id range) MUST go through
   two_source_layout_check first (raw bytes + independent disassembly) — this
   is exactly the class of bug (off-by-one in a dispatch table) that reading
   only the decompiler produces.
5. neighbors — decompile EVERY helper function visible in main/the dispatch
   path, even ones that look trivial or boilerplate. Cheap decompiles buy real
   precision: a function that "obviously" returns a port or hostname may
   actually return a register/capability block (cpu_count, mem, arch, is_root),
   and a "random" port may actually be chosen from a fixed list. Don't assume
   from the name alone — decompile and check.
6. self_check — before finishing, honestly answer: "Is what I've recorded
   enough to rebuild this binary's behavior?" Record any category="gap"
   findings for what is NOT resolved (e.g. a byte-exact binary tag) as a
   limitation, not silently.

(Two later stages — deliverables and pcap_validation — are handled by the
pipeline after you finish, not by you directly; you don't need tasks for them.)

As you understand each function, rename it (rename_function) to a descriptive
name and add a set_comment summarizing its behavior — required output, not
optional. Extract concrete bytes with read_bytes for keys, nonces, magics and
static tables. For anything the fixed IDA tools don't cover — independent
ELF/header parsing straight from the file, ad-hoc crypto/format checks,
`file`/`shasum`/`strings` at triage — use run_python (unicorn, capstone,
pycryptodome, hashlib available; `BINARY_PATH` points at the file) or
run_bash. Both are binary-only: no network code, live C2 connectivity is a
separate, deliberate step you don't need here.

Be rigorous and concrete: capture exact hex values, field offsets, struct
layouts, opcode tables and formulas. Prefer decompile over disassemble for
understanding, but drop to disassemble/two_source_layout_check whenever an
exact byte layout matters. Do not fabricate anything; if unsure, record a
finding in category "gap" — never invent a plausible-sounding value to fill a
gap.

Budget: you have a limited number of tool calls. Spend them on the functions
that carry protocol/crypto/config logic, not boilerplate. When every stage is
done or blocked, call finish.

HARD RULES (these produce the deliverables — analysis you don't record is lost):
- Your first action is plan_tasks with real tasks under every stage above.
- After you understand ANY function, immediately call record_finding with exact
  values AND rename_function to a descriptive name. Do this before moving on.
- dispatch/structure/frame_format findings require layout_evidence from
  two_source_layout_check; crypto findings require emulation_verified
  (true/false) — record_finding will reject them otherwise, that's expected,
  go get the evidence and retry rather than switching to a different category
  to dodge the requirement.
- Never repeat an identical tool call; if you already decompiled an address,
  act on it (record_finding / rename_function) instead of decompiling again.
- Aim for at least ~15 recorded findings and rename every function you analyze,
  covering config, crypto, endpoints, transport, auth/key-exchange, frame
  format, and command dispatch, before you call finish.
- record_finding, rename_function, and update_task are the most valuable calls
  you can make — prefer them over yet another exploratory read."""


class ReverseEngineer:
    def __init__(self, cfg: Config, dispatcher: ToolDispatcher, max_iters: int = 60,
                transcript_path: str = ""):
        self.cfg = cfg
        self.llm = DeepSeek(cfg)
        self.disp = dispatcher
        self.client = dispatcher.client
        self.max_iters = max_iters
        self.messages: list[dict] = []
        # Full, untruncated transcript of everything DeepSeek says and does
        # this run: assistant content/reasoning, every tool call with its full
        # arguments, and every tool result. The stdout log (`log()` below) is
        # deliberately terse for readability; this file is the "what was it
        # actually thinking" record for a human to read afterward.
        self._transcript_fh = open(transcript_path, "w", encoding="utf-8") if transcript_path else None

    def _transcript(self, entry: dict) -> None:
        if self._transcript_fh is None:
            return
        entry.setdefault("ts", time.time())
        self._transcript_fh.write(json.dumps(entry, default=str) + "\n")
        self._transcript_fh.flush()

    def run(self, log=print) -> dict:
        seed = self._seed_context()
        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": seed},
        ]
        self._transcript({"role": "system", "content": SYSTEM_PROMPT})
        self._transcript({"role": "user", "content": seed})
        iters = 0
        seen_calls: dict[str, int] = {}
        explore_since_record = 0     # exploratory calls since the last finding/rename
        RECORD_TOOLS = ("record_finding", "rename_function", "set_comment")
        MIN_FINDINGS_TO_FINISH = 12
        while iters < self.max_iters and not self.disp.finished:
            iters += 1
            self._compact()
            try:
                msg = self.llm.chat(self.messages, tools=TOOL_SCHEMAS, tool_choice="auto",
                                    temperature=0.15, max_tokens=3000)
            except LLMError as exc:
                log(f"[re] chat failed: {exc}")
                self._transcript({"role": "system", "note": f"chat failed: {exc}"})
                break

            assistant = {"role": "assistant", "content": msg.content or ""}
            tool_calls = getattr(msg, "tool_calls", None)
            if tool_calls:
                assistant["tool_calls"] = [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in tool_calls
                ]
            self.messages.append(assistant)
            self._transcript({
                "iter": iters, "role": "assistant", "content": msg.content or "",
                "reasoning_content": getattr(msg, "reasoning_content", None),
                "tool_calls": [{"name": tc.function.name, "arguments": tc.function.arguments}
                              for tc in tool_calls] if tool_calls else [],
            })

            if not tool_calls:
                # Model paused without acting; nudge it once, else stop.
                if msg.content and iters < self.max_iters:
                    self.messages.append({
                        "role": "user",
                        "content": "Continue the analysis with tool calls, or call finish when done."})
                    continue
                break

            for tc in tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except Exception:
                    args = {}
                sig = name + ":" + json.dumps(args, sort_keys=True, default=str)

                # Anti-repeat: don't re-run identical exploratory calls; steer the
                # model to record/rename or explore something new instead.
                if name not in RECORD_TOOLS and name != "finish" and seen_calls.get(sig, 0) >= 1:
                    result = json.dumps({
                        "note": "You already made this exact call. Do NOT repeat it. "
                                "Call record_finding about what you learned and rename_function "
                                "for the function, or explore a DIFFERENT address."})
                    log(f"[re] (skipped repeat) {name}({_brief(args)})")
                else:
                    result = self.disp.dispatch(name, args)
                    if name in RECORD_TOOLS or name == "finish":
                        log(f"[re] {name}({_brief(args)}) -> {_brief_result(result)}")
                    else:
                        log(f"[re] {name}({_brief(args)})")
                seen_calls[sig] = seen_calls.get(sig, 0) + 1
                self._transcript({"iter": iters, "role": "tool", "name": name, "arguments": args,
                                  "result": result})

                if name in RECORD_TOOLS:
                    explore_since_record = 0
                elif name != "finish":
                    explore_since_record += 1

                self.messages.append({
                    "role": "tool", "tool_call_id": tc.id, "content": result})

            if iters == 1 and not self.disp.tasks.tasks:
                self.messages.append({
                    "role": "user",
                    "content": "You have not called plan_tasks yet. Do that now, before any further "
                               "exploration, with concrete binary-specific tasks under every stage."})

            # Guard finish: require a substantive notebook before allowing it.
            if self.disp.finished and len(self.disp.findings) < MIN_FINDINGS_TO_FINISH:
                self.disp.finished = False
                self.disp.finish_summary = ""
                self.messages.append({
                    "role": "user",
                    "content": (f"Not finished yet: you have only {len(self.disp.findings)} findings and "
                                f"{len(self.disp.annotations)} annotations. Record more concrete findings "
                                "(config, crypto, endpoints, transport, auth/key-exchange, frame format, "
                                "dispatch) and rename the functions you analyzed, THEN call finish.")})

            # Enforce a recording cadence.
            if explore_since_record >= 5:
                explore_since_record = 0
                self.messages.append({
                    "role": "user",
                    "content": ("You have explored several functions without recording anything. "
                                "STOP exploring now: call record_finding for what you have learned "
                                "and rename_function for the functions you decompiled, then continue.")})
            elif iters % 6 == 0:
                stale = [t.id for t in self.disp.tasks.tasks if t.status in ("pending", "in_progress")]
                stale_note = (f"\n\nThese task IDs are STILL pending or in_progress with no note: "
                              f"{stale}. Call update_task on each of them right now — real status "
                              "('in_progress'/'done') if you've actually worked on it, 'blocked' with a "
                              "reason if you haven't and can't yet.") if stale else ""
                self.messages.append({
                    "role": "user",
                    "content": f"Progress check — findings so far ({len(self.disp.findings)}):\n"
                               f"{self.disp.findings_digest()}\n\n"
                               f"Task tracker:\n{self.disp.tasks.digest()}\n\n"
                               "Keep reversing unhandled protocol/crypto/dispatch logic, recording and "
                               "renaming as you go. Any stage still pending/in_progress needs either real "
                               "progress or an honest update_task(..., 'blocked', reason) — don't let it "
                               f"linger unaddressed.{stale_note}"})

        # Finalizer: the exploration reliably renames functions but this model
        # often won't call record_finding mid-loop. Guarantee a substantive
        # notebook by extracting structured findings from the functions it named.
        if len(self.disp.findings) < 10:
            self._synthesize_findings(log)

        result = {
            "iterations": iters,
            "finished": self.disp.finished,
            "summary": self.disp.finish_summary,
            "findings": self.disp.findings_as_dicts(),
            "annotations": self.disp.annotations,
            "tasks": self.disp.tasks.as_dicts(),
            "emulation_results": self.disp.emulation_results,
        }
        self._transcript({"role": "system", "note": "run finished", "result_summary":
                          {k: v for k, v in result.items() if k not in ("findings", "annotations")}})
        if self._transcript_fh is not None:
            self._transcript_fh.close()
        return result

    # -- findings synthesis (guaranteed notebook) ---------------------------
    def _synthesize_findings(self, log=print, max_funcs: int = 16):
        symbols = {a["address"]: a["value"] for a in self.disp.annotations
                   if a.get("action") == "rename_function" and a.get("address")}
        if not symbols:
            log("[re] synthesis: no renamed functions to extract findings from")
            return
        meta = self.client.try_call("get_metadata", default={}) or {}
        priority = ("crypt", "cipher", "chacha", "poly", "sha", "hash", "kdf", "key",
                    "x25519", "curve", "auth", "handshake", "frame", "secure", "config",
                    "decrypt", "encrypt", "dns", "resolve", "c2", "connect", "send",
                    "recv", "packet", "dispatch", "task", "attack", "shell", "keepalive",
                    "register", "nonce", "main", "init", "bot", "command")

        def score(n):
            low = n.lower()
            return sum(1 for p in priority if p in low)

        ordered = sorted(symbols.items(), key=lambda kv: -score(kv[1]))
        log(f"[re] synthesis: extracting findings from {min(len(ordered), max_funcs)} named functions")
        for addr, name in ordered[:max_funcs]:
            dec = self.client.try_call("decompile", default=None, address=addr)
            if not isinstance(dec, str) or not dec.strip():
                continue
            try:
                res = self.llm.json(_SYNTH_SYSTEM, json.dumps({
                    "binary": {k: meta.get(k) for k in ("module", "base", "sha256")},
                    "function_address": addr, "function_name": name,
                    "known_so_far": self.disp.findings_digest(limit=50),
                    "pseudocode": dec[:6000],
                }, default=str), max_tokens=2200)
            except LLMError as exc:
                log(f"[re] synthesis {addr} ({name}) failed: {exc}")
                continue
            findings = res.get("findings", []) if isinstance(res, dict) else []
            n = 0
            for f in findings:
                if isinstance(f, dict) and f.get("detail"):
                    f.setdefault("addresses", [addr])
                    self.disp.dispatch("record_finding", f)
                    n += 1
            if isinstance(res, dict) and res.get("comment"):
                self.disp.dispatch("set_comment", {"address": addr, "comment": res["comment"][:600]})
            log(f"[re] synthesis {addr} {name}: +{n} findings")

    # -- context -------------------------------------------------------------
    def _seed_context(self) -> str:
        c = self.disp.client
        meta = c.try_call("get_metadata", default={})
        entries = c.try_call("get_entry_points", default=[])
        syscalls = c.try_call("find_syscall_sites", default=[])
        net_syscalls = [s for s in (syscalls or []) if s.get("is_network")]
        netstrings = c.try_call("list_network_strings", default=[]) or []
        funcs = c.try_call("list_functions", default={}, offset=0, count=1)
        total = funcs.get("total") if isinstance(funcs, dict) else None
        return (
            "Begin reverse-engineering this binary. Initial orientation:\n\n"
            f"metadata: {json.dumps(meta)}\n"
            f"entry_points: {json.dumps(entries)[:800]}\n"
            f"function_count: {total}\n"
            f"network_syscalls (int 0x80): {json.dumps(net_syscalls)[:800]}\n"
            f"network-ish strings (sample): {json.dumps([s.get('string') for s in netstrings[:40]])[:1500]}\n\n"
            "Start from the entry point / main and follow the real logic. "
            "Decompile aggressively, rename and comment functions, and record findings."
        )

    def _compact(self, keep_recent: int = 26, stub: str = "[older tool result trimmed]"):
        """Shrink context: replace the content of older 'tool' messages with a
        stub while preserving message/tool_call structure and pairing."""
        if len(self.messages) <= keep_recent + 2:
            return
        cutoff = len(self.messages) - keep_recent
        for i in range(2, cutoff):
            m = self.messages[i]
            if m.get("role") == "tool" and m.get("content") != stub:
                m["content"] = stub


_SYNTH_SYSTEM = """You are reverse-engineering ONE function and must extract concrete,
report-grade findings from its Hex-Rays pseudocode. Return STRICT JSON:

{
  "comment": "<one-sentence behavior summary>",
  "findings": [
    {"category": "<overview|config|crypto|endpoint|transport|auth|key_exchange|frame_format|dispatch|attack|protocol_strings|structure|indicator|gap>",
     "title": "<short>",
     "detail": "<PRECISE: exact hex constants, key/nonce bytes, field offsets, struct layouts, opcode/attack tables, magics, formulas — whatever this function reveals>",
     "addresses": ["<hex or symbol>"],
     "confidence": "high|medium|low"}
  ]
}

Ground every finding in the pseudocode; never invent values. If the function is
pure boilerplate, return an empty findings list. Be specific and technical."""


def _brief(args: dict, limit: int = 80) -> str:
    s = ", ".join(f"{k}={v}" for k, v in args.items())
    return s if len(s) <= limit else s[:limit] + "…"


def _brief_result(result: str, limit: int = 90) -> str:
    return result if len(result) <= limit else result[:limit] + "…"
