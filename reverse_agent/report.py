"""Deep reverse-engineering report generation.

The report is authored by DeepSeek from the agent's findings, the symbols it
applied to the IDA database, and decompilations of the functions it renamed.
Deterministic scope and implementation-evidence tables are appended by code so
the report is always grounded in verifiable addresses.
"""
from __future__ import annotations

import json
import os
from typing import Any

from .ida_client import IDAClient
from .llm import DeepSeek


REPORT_SYSTEM = """You are writing a precise, technical malware reverse-engineering report,
in the style of a professional threat-intelligence write-up. You are given the
findings, applied IDA symbols, and decompilations produced by an automated RE
pass over a binary. Write a thorough Markdown report.

Rules:
- Ground every claim in the supplied evidence (findings, decompilations, symbols,
  addresses). Do NOT invent addresses, keys, IPs, ports, opcodes, or formats.
- Be concrete: include exact hex values, field offsets, struct layouts, packet
  diagrams (ASCII), opcode/attack tables, KDF labels, magics.
- Use IDA symbol names and addresses when referring to functions.
- Prefer tables and fenced code blocks for layouts and enumerations.
- If something is uncertain or was not fully recovered, say so in a "Residual
  Gaps" section rather than guessing.
- Traffic/PCAP is secondary for endpoints/ports, but you ARE given a
  `pcap_validation` result: if it attempted a decode, report whether that
  succeeded as a data point on confidence.
- Include a "Reconstructability Self-Check" section that directly answers: is
  this report sufficient for someone else to rebuild the binary's behavior?
  Use `task_tracker` (any stage left pending/blocked), `emulation_verification_results`
  (any crypto NOT verified), and `client_selftest_passed` to ground this answer
  in fact — don't just assert confidence.

Recommended section structure (include those that apply, in this order):
Scope; Overview; Encrypted/Obfuscated Configuration; Endpoint Selection;
Transport; Authentication & Key Exchange; Secure Frame Format; Payload Dispatch;
Command/Attack Handlers; Protocol Strings; Indicators; Implementation Evidence;
Reconstructability Self-Check; Residual Gaps.

Output ONLY the Markdown report (no preamble, no code fences around the whole thing)."""


# ---------------------------------------------------------------------------
# Independent completeness grading — deliberately NOT the same call that wrote
# the report, and given ONLY the rendered report text (no findings, no
# decompilations). A model grading its own work with its own context tends to
# agree with itself; a fresh call with only the finished artifact is a much
# harder, more honest test of whether the artifact stands on its own.
# ---------------------------------------------------------------------------
_GRADE_BINARY_SYSTEM = """You are an independent, skeptical reviewer auditing a
reverse-engineering report. You have NO access to the original binary,
decompilations, or the analyst's findings notebook — ONLY the report text
below. Judge, strictly, whether this report ALONE is sufficient for a
competent reverse engineer to rebuild the binary's network protocol behavior
(packet formats, crypto, dispatch, endpoint selection) without ever touching
the binary.

Be harsh: a claim that reads confidently but omits an exact byte value, an
offset, or a concrete algorithm/parameter is a gap, not a pass. A report that
already lists a gap in its own "Residual Gaps" section is being honest, but
the gap is still real — list it yourself too, don't give credit for confessing.

Respond with STRICT JSON only:
{"sufficient": true|false, "confidence": "high|medium|low",
 "gaps": ["<concrete, specific missing item>", ...]}"""

_GRADE_CLIENT_SYSTEM = """You are an independent reviewer. You have NOT seen the
original binary — ONLY the report text below. Judge whether someone could
write a WORKING protocol client from it: build and parse every packet/frame
format, implement every crypto primitive with its actual parameters, and
reproduce the handshake — using NO other source of truth than this text.

Be harsh: prose describing a format is not the same as an exact byte layout
with field sizes and order; naming a cipher is not the same as giving its
key/nonce/mode/parameters. List every concrete item a client implementation
would need that the report does not actually supply (not "the crypto isn't
verified" in the abstract — name the missing key, the missing offset, the
missing struct field).

Respond with STRICT JSON only:
{"sufficient": true|false, "confidence": "high|medium|low",
 "missing_for_client": ["<concrete, specific missing item>", ...]}"""


def _grade(report_text: str, system: str, llm: DeepSeek) -> dict:
    try:
        return llm.json(system, report_text[:14000], max_tokens=4000)
    except Exception as exc:
        return {"sufficient": None, "error": str(exc)}


def _reconstructability_appendix(binary_verdict: dict, client_verdict: dict) -> str:
    parts = ["\n## Appendix H — Independent Reconstructability Review\n"]
    parts.append("Generated by a SEPARATE grading call that saw only the finished report text "
                 "above (no findings, no decompilations, no binary access) — the same information "
                 "a third party reading this report would have. Not authored by the report-writing "
                 "LLM, and not self-graded.\n\n")

    def _section(title: str, verdict: dict, gaps_key: str, question: str):
        parts.append(f"### {title}\n\n")
        parts.append(f"**Question:** {question}\n\n")
        if verdict.get("sufficient") is None:
            parts.append(f"_Grading call failed: {verdict.get('error', 'unknown error')}_\n\n")
            return
        verdict_str = "YES" if verdict.get("sufficient") else "NO"
        parts.append(f"**Verdict:** {verdict_str} (confidence: {verdict.get('confidence', 'unknown')})\n\n")
        gaps = verdict.get(gaps_key, [])
        if gaps:
            parts.append("Specific gaps identified:\n\n")
            for g in gaps:
                parts.append(f"- {g}\n")
            parts.append("\n")
        elif verdict.get("sufficient"):
            parts.append("No gaps identified by the reviewer.\n\n")

    _section("Can the binary's behavior be rebuilt from this report alone?", binary_verdict,
             "gaps", "Given only this report, could a reverse engineer rebuild the binary's "
                     "network protocol behavior?")
    _section("Can client.py be rewritten from this report alone?", client_verdict,
             "missing_for_client", "Given only this report, could someone write a working "
                                   "protocol client (packet build/parse, crypto, handshake)?")
    return "".join(parts)


def _symbol_map(annotations: list[dict]) -> dict[str, str]:
    out = {}
    for a in annotations:
        if a.get("action") == "rename_function" and a.get("address"):
            out[a["address"]] = a["value"]
    return out


def _gather_key_decompilations(client: IDAClient, symbols: dict[str, str],
                               max_funcs: int = 14, chars: int = 1800) -> list[dict]:
    out = []
    for addr, name in list(symbols.items())[:max_funcs]:
        dec = client.try_call("decompile", default=None, address=addr)
        if isinstance(dec, str) and dec.strip():
            out.append({"address": addr, "name": name, "pseudocode": dec[:chars]})
    return out


def build_report(state: dict, llm: DeepSeek | None, client: IDAClient) -> str:
    binary = state.get("binary_path", "")
    evidence = state.get("evidence", {})
    meta = evidence.get("metadata", {}) or state.get("metadata", {})
    re_result = state.get("re_result", {})
    findings = re_result.get("findings", [])
    annotations = re_result.get("annotations", [])
    pcap = state.get("pcap", {})
    symbols = _symbol_map(annotations)

    if llm is not None:
        key_decomp = _gather_key_decompilations(client, symbols)
        context = {
            "binary_metadata": meta,
            "overall_summary": re_result.get("summary", ""),
            "findings": findings,
            "applied_symbols": symbols,
            "comments": [a for a in annotations if a.get("action") == "comment"],
            "key_decompilations": key_decomp,
            "pcap_corroboration": {
                "dns": pcap.get("dns"),
                "flows": pcap.get("flows"),
                "endpoints": pcap.get("endpoints"),
            },
            "task_tracker": re_result.get("tasks", []),
            "emulation_verification_results": re_result.get("emulation_results", []),
            "client_selftest_passed": state.get("client_selftest_ok"),
            "pcap_validation": state.get("pcap_validation", {}),
        }
        user = ("Write the reverse-engineering report from this evidence:\n\n"
                + json.dumps(context, indent=2, default=str))
        try:
            body = llm.complete(REPORT_SYSTEM, user, temperature=0.2, max_tokens=8000)
        except Exception as exc:
            body = _fallback_body(state, findings, symbols, f"(LLM report failed: {exc})")
    else:
        body = _fallback_body(state, findings, symbols, "")

    # Always append an authoritative, code-generated evidence appendix.
    appendix = _evidence_appendix(binary, meta, symbols, annotations, pcap, state)
    full = body.rstrip() + "\n\n" + appendix

    binary_verdict: dict = {}
    client_verdict: dict = {}
    if llm is not None:
        binary_verdict = _grade(full, _GRADE_BINARY_SYSTEM, llm)
        if binary_verdict.get("sufficient") is False and binary_verdict.get("gaps"):
            repair = ("An independent review (which saw only this report text, not your "
                      "findings) judged it insufficient to rebuild the binary's behavior. "
                      "Specific gaps:\n- " + "\n- ".join(binary_verdict["gaps"]) +
                      "\n\nExpand or sharpen the report to address these — add concrete "
                      "values/offsets/algorithms wherever the evidence actually supports them. "
                      "Do NOT fabricate anything you don't have; if a gap is genuinely "
                      "unresolved, state precisely what's missing rather than padding around it.")
            try:
                body2 = llm.complete(REPORT_SYSTEM, user + "\n\n" + repair, temperature=0.2, max_tokens=8000)
                full2 = body2.rstrip() + "\n\n" + appendix
                binary_verdict = _grade(full2, _GRADE_BINARY_SYSTEM, llm)
                full = full2
            except Exception:
                pass  # keep the first-pass report + its verdict
        client_verdict = _grade(full, _GRADE_CLIENT_SYSTEM, llm)

    full += _reconstructability_appendix(binary_verdict, client_verdict)
    return full


def _fallback_body(state: dict, findings: list[dict], symbols: dict[str, str], note: str) -> str:
    lines = [f"# Reverse-Engineering Report — `{os.path.basename(state.get('binary_path',''))}`", ""]
    if note:
        lines += [f"> {note}", ""]
    lines += ["## Findings", ""]
    by_cat: dict[str, list[dict]] = {}
    for f in findings:
        by_cat.setdefault(f.get("category", "overview"), []).append(f)
    for cat, items in by_cat.items():
        lines.append(f"### {cat}")
        for f in items:
            addrs = (" (" + ", ".join(f.get("addresses", [])) + ")") if f.get("addresses") else ""
            lines.append(f"- **{f.get('title','')}**{addrs}: {f.get('detail','')}")
        lines.append("")
    return "\n".join(lines)


def _md_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_None._\n"
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        cells = ["" if c is None else str(c).replace("|", "\\|").replace("\n", " ") for c in r]
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


def _evidence_appendix(binary: str, meta: dict, symbols: dict[str, str],
                       annotations: list[dict], pcap: dict, state: dict) -> str:
    parts = ["## Appendix A — Scope & Hashes\n"]
    parts.append(_md_table(["Field", "Value"], [
        ["Binary", os.path.basename(binary)],
        ["SHA-256", meta.get("sha256")],
        ["MD5", meta.get("md5")],
        ["Image base", meta.get("base")],
        ["File size", meta.get("filesize")],
    ]))

    parts.append("\n## Appendix B — Applied IDA Symbols (Implementation Evidence)\n")
    parts.append("Functions renamed in the IDA database (`" + os.path.basename(binary) + ".i64`) during analysis.\n\n")
    parts.append(_md_table(["Address", "Symbol"], [[a, n] for a, n in symbols.items()]))

    comments = [a for a in annotations if a.get("action") == "comment"]
    if comments:
        parts.append("\n## Appendix C — IDA Comments\n")
        parts.append(_md_table(["Address", "Comment"], [[c["address"], c["value"]] for c in comments]))

    if pcap.get("dns") or pcap.get("flows"):
        parts.append("\n## Appendix D — Captured Traffic (corroboration)\n")
        dns_rows = [[d.get("frame"), "response" if d.get("is_response") else "query",
                     d.get("query"), ", ".join(d.get("a", []) + d.get("aaaa", [])) or "—"]
                    for d in pcap.get("dns", [])]
        parts.append("DNS:\n\n" + _md_table(["Frame", "Type", "Query", "Answers"], dns_rows))
        flow_rows = [[f.get("proto"), f.get("endpoint_a"), f.get("endpoint_b"),
                      f.get("frames_total"), f.get("bytes_total")] for f in pcap.get("flows", [])]
        parts.append("\nFlows:\n\n" + _md_table(["Proto", "A", "B", "Frames", "Bytes"], flow_rows))

    re_result = state.get("re_result", {})

    tasks = re_result.get("tasks", [])
    if tasks:
        parts.append("\n## Appendix E — RE Plan Stage Tracker\n")
        parts.append("Deterministic, generated from the agent's own task tracker — not authored by "
                     "the report-writing LLM. A stage left `pending`/`in_progress` here means it was "
                     "*not* completed and the deliverables above should be read with that gap in mind.\n\n")
        parts.append(_md_table(["#", "Stage", "Task", "Status", "Note"],
                               [[t["id"], t["stage"], t["title"], t["status"], t.get("note", "")]
                                for t in tasks]))

    emu = re_result.get("emulation_results", [])
    if emu:
        parts.append("\n## Appendix F — Crypto Primitive Verification (Emulation)\n")
        parts.append("Each row is a real binary function executed in Unicorn and diffed against a "
                     "pycryptodome/hashlib reference — the only thing this project counts as "
                     "'verified' for a crypto primitive.\n\n")
        parts.append(_md_table(["Function", "Primitive", "Verified", "Reason"],
                               [[e["function_address"], e["primitive"],
                                 "yes" if e["verified"] else "NO", e["reason"]]
                                for e in emu]))
    elif any(f.get("category") == "crypto" for f in re_result.get("findings", [])):
        parts.append("\n## Appendix F — Crypto Primitive Verification (Emulation)\n")
        parts.append("_No primitives were run through `verify_primitive`. Any crypto findings above "
                     "are unverified against real binary execution — treat them as decompiler-derived "
                     "hypotheses, not confirmed behavior._\n")

    parts.append("\n## Appendix G — Client Self-Test & PCAP Validation\n")
    st_ok = state.get("client_selftest_ok")
    st_out = state.get("client_selftest_output", "")
    parts.append(_md_table(["Check", "Result"], [
        ["`client.py --selftest` executed", "PASSED" if st_ok else ("FAILED" if st_ok is not None else "not run")],
    ]))
    if st_out and not st_ok:
        parts.append(f"\n```\n{st_out[-1500:]}\n```\n")
    pv = state.get("pcap_validation", {})
    if pv.get("attempted"):
        parts.append(f"\nPCAP decode check: {pv.get('summary', '(no summary)')}\n")
    elif pv.get("reason"):
        parts.append(f"\nPCAP decode check not attempted: {pv['reason']}\n")

    parts.append("\n---\n_Report body authored by DeepSeek from an automated IDA Pro (idalib) "
                 "reverse-engineering pass; appendices E-G generated deterministically from "
                 "the task tracker, emulation harness, and self-test/pcap runs; Appendix H is an "
                 "independent grading pass with no access to the analysis (see build_report)._\n")
    return "\n".join(parts)


def endpoint_summary(state: dict) -> dict:
    pcap = state.get("pcap", {})
    re_result = state.get("re_result", {})
    indicators = [f for f in re_result.get("findings", []) if f.get("category") in ("indicator", "endpoint")]
    return {
        "indicators": indicators,
        "dns": [{"query": d.get("query"), "answers": d.get("a", []), "frame": d.get("frame")}
                for d in pcap.get("dns", []) if d.get("is_response")],
        "flows": pcap.get("flows", []),
        "endpoints": pcap.get("endpoints", []),
    }
