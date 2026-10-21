"""LangGraph orchestration — binary-first reverse-engineering pipeline.

    re_explore(agentic, staged, BINARY ONLY) -> write_client -> pcap_validate -> write_report -> save_idb

DeepSeek is the centre: `re_explore` runs a staged agentic loop (triage,
anchors, crypto, protocol/dispatch, neighbors, self-check — see
`re_agent.SYSTEM_PROMPT` / `tasks.DEFAULT_STAGES`) in which DeepSeek drives IDA
Pro plus the verification tools (two_source_layout_check, verify_primitive,
run_python, run_bash) to reverse-engineer the binary. Deliberately no PCAP
tool is available here: a capture is a huge shortcut ("the traffic already
tells you the protocol") that pulls the agent toward pattern-matching instead
of tracing the actual code, and it isn't ground truth for what the BINARY
does — the binary is. The capture is only parsed later, at `pcap_validate`,
as an end-to-end corroboration step after the analysis is already complete.
`write_client` has DeepSeek author a protocol client with a real, executed
`--selftest`. `write_report` authors the report last, so it can fold in what
actually got verified (or didn't).
"""
from __future__ import annotations

import json
import os
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from .config import Config
from .ida_client import IDAClient
from .llm import DeepSeek
from .pcap import parse_pcap
from .tools import ToolDispatcher
from .re_agent import ReverseEngineer
from . import report as report_mod
from . import client_gen


class AgentState(TypedDict, total=False):
    binary_path: str
    pcap_path: str
    out_dir: str
    max_iters: int
    pcap: dict
    metadata: dict
    evidence: dict
    re_result: dict
    report_md: str
    client_py: str
    client_selftest_ok: bool
    client_selftest_output: str
    pcap_validation: dict
    log: list


class NetmapAgent:
    def __init__(self, cfg: Config, client: IDAClient):
        self.cfg = cfg
        self.client = client
        self.llm = DeepSeek(cfg) if cfg.has_llm else None
        self.graph = self._build()

    def _build(self):
        g = StateGraph(AgentState)
        g.add_node("re_explore", self.re_explore_node)
        g.add_node("write_report", self.report_node)
        g.add_node("write_client", self.client_node)
        g.add_node("pcap_validate", self.pcap_validate_node)
        g.add_node("save_idb", self.save_node)
        g.add_edge(START, "re_explore")
        g.add_edge("re_explore", "write_client")
        g.add_edge("write_client", "pcap_validate")
        g.add_edge("pcap_validate", "write_report")
        g.add_edge("write_report", "save_idb")
        g.add_edge("save_idb", END)
        return g.compile()

    def run(self, binary_path: str, pcap_path: str, out_dir: str, max_iters: int = 500) -> AgentState:
        init: AgentState = {
            "binary_path": binary_path, "pcap_path": pcap_path,
            "out_dir": out_dir, "max_iters": max_iters, "log": [],
        }
        return self.graph.invoke(init, {"recursion_limit": 50})

    # -- nodes ---------------------------------------------------------------
    def re_explore_node(self, state: AgentState) -> AgentState:
        metadata = self.client.try_call("get_metadata", default={}) or {}
        if self.llm is None:
            self._log(state, "LLM disabled — reverse-engineering agent requires DeepSeek; "
                             "recording metadata only")
            return {"re_result": {"iterations": 0, "finished": False, "summary": "",
                                  "findings": [], "annotations": [], "tasks": [],
                                  "emulation_results": []},
                    "evidence": {"metadata": metadata}, "metadata": metadata}
        # No PCAP tool here, deliberately: this stage sees ONLY the binary
        # (via IDA + run_python/run_bash), so it traces actual code instead of
        # pattern-matching against traffic it hasn't earned yet.
        disp = ToolDispatcher(self.client, binary_path=state["binary_path"])
        transcript_path = os.path.join(state["out_dir"], "deepseek_transcript.jsonl")
        agent = ReverseEngineer(self.cfg, disp, max_iters=state.get("max_iters", 500),
                                transcript_path=transcript_path)
        self._log(state, f"full DeepSeek transcript (content + reasoning + every tool call/result) "
                         f"-> {transcript_path}")
        self._log(state, f"reverse-engineering agent starting (max {state.get('max_iters', 500)} iters)…")
        result = agent.run(log=lambda m: self._log(state, m, echo=False))
        self._log(state, f"RE done: {result['iterations']} iters, {len(result['findings'])} findings, "
                         f"{len(result['annotations'])} annotations, finished={result['finished']}")
        return {"re_result": result, "evidence": {"metadata": metadata}, "metadata": metadata}

    def report_node(self, state: AgentState) -> AgentState:
        md = report_mod.build_report(state, self.llm, self.client)
        os.makedirs(state["out_dir"], exist_ok=True)
        with open(os.path.join(state["out_dir"], "report.md"), "w") as fh:
            fh.write(md)
        with open(os.path.join(state["out_dir"], "analysis.json"), "w") as fh:
            json.dump({
                "binary": state["binary_path"],
                "metadata": state.get("metadata", {}),
                "re_result": state.get("re_result", {}),
            }, fh, indent=2, default=str)
        with open(os.path.join(state["out_dir"], "endpoints.json"), "w") as fh:
            json.dump(report_mod.endpoint_summary(state), fh, indent=2, default=str)
        self._log(state, "report.md + analysis.json + endpoints.json written")
        return {"report_md": md}

    def client_node(self, state: AgentState) -> AgentState:
        if self.llm is None:
            return {"client_py": ""}
        try:
            result = client_gen.generate_client(state, self.llm, self.client)
        except Exception as exc:
            self._log(state, f"client generation failed: {exc}")
            return {"client_py": "", "client_selftest_ok": False, "client_selftest_output": str(exc)}
        code = result["code"]
        with open(os.path.join(state["out_dir"], "client.py"), "w") as fh:
            fh.write(code)
        status = "PASSED" if result["selftest_ok"] else "FAILED"
        self._log(state, f"client.py written ({len(code.splitlines())} lines); --selftest {status}")
        return {"client_py": code, "client_selftest_ok": result["selftest_ok"],
                "client_selftest_output": result["selftest_output"]}

    def pcap_validate_node(self, state: AgentState) -> AgentState:
        """Stage 8 of the RE plan: the real test of the whole recovered stack is
        whether the generated client can decrypt an actual captured payload —
        not whether it passes its own self-authored --selftest. The capture is
        parsed HERE, for the first time — re_explore never saw it, so this is
        a genuine independent check rather than the model grading its own
        homework against traffic it already used to reach its conclusions."""
        pcap: dict = {}
        pcap_path = state.get("pcap_path")
        if pcap_path and os.path.exists(pcap_path):
            try:
                summary = parse_pcap(pcap_path)
                pcap = summary.to_dict()
                self._log(state, f"pcap parsed for corroboration: {summary.packet_count} packets, "
                                 f"{len(summary.dns)} dns, {len(summary.flows)} flows")
            except Exception as exc:
                self._log(state, f"pcap parse skipped: {exc}")
        else:
            self._log(state, "no pcap provided; skipping pcap validation")
        streams = pcap.get("streams", [])
        client_py = state.get("client_py", "")
        if not streams or not client_py or not state.get("client_selftest_ok"):
            reason = ("no pcap streams" if not streams else
                      "no client.py" if not client_py else
                      "client.py --selftest did not pass — skipping pcap decode as unreliable")
            self._log(state, f"pcap validation skipped: {reason}")
            return {"pcap": pcap, "pcap_validation": {"attempted": False, "reason": reason}}
        result = client_gen.try_decode_streams(client_py, streams, out_dir=state["out_dir"])
        self._log(state, f"pcap validation: {result.get('summary', result)}")
        return {"pcap": pcap, "pcap_validation": result}

    def save_node(self, state: AgentState) -> AgentState:
        idb_path = os.path.join(state["out_dir"], os.path.basename(state["binary_path"]) + ".i64")
        save = self.client.try_call("save_database", default={}, path=idb_path)
        self._log(state, f"annotated IDA database saved -> "
                         f"{save.get('path') if isinstance(save, dict) else save}")
        return {}

    # -- helpers -------------------------------------------------------------
    def _log(self, state: AgentState, msg: str, echo: bool = True):
        state.setdefault("log", []).append(msg)
        if echo:
            print(f"[netmap] {msg}", flush=True)
        else:
            print(f"  {msg}", flush=True)
