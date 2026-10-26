# reverse_agent — LLM agent for malware C2 reverse engineering

> Built in summer 2026 during an information-security internship. Published with
> the permission of the internship supervisor; no samples, captures or results
> from the internship are included.

A **DeepSeek-driven reverse-engineering agent**. It drives a **headless IDA Pro**
instance over the **IDA Pro MCP** protocol to reverse-engineer a binary, and uses
the **DeepSeek** LLM as the analyst: DeepSeek decompiles and understands the
functions, renames/annotates them in the IDA database, records structured
findings, and from those writes (1) a deep technical **report** and (2) a
standalone **`client.py`** that reimplements the sample's protocol for further
analysis. A packet capture, if supplied, is used only as **secondary
corroboration** of endpoints/ports.

```
                         ┌──────────────── DeepSeek (staged reverse-engineer + author) ──────────┐
                         │                                                                       │
  binary ─▶ IDA Pro MCP (idalib, headless) ◀── decompile / xrefs / rename / comment / read_bytes ┘
                         │            ◀── two_source_layout_check (Capstone) / verify_primitive (Unicorn)
                         ├─▶ staged agentic RE loop ─▶ task tracker + findings notebook + IDA annotations
  pcap (optional) ─▶ tshark ─┘  (corroboration)          │
                                                          ├─▶ client.py   (protocol reimplementation, real --selftest)
                                                          ├─▶ pcap_validate (decode real capture with the client)
                                                          ├─▶ report.md   (deep RE write-up + deterministic verification appendix)
                                                          ├─▶ <binary>.i64 (annotated IDA database)
                                                          └─▶ analysis.json / endpoints.json
```

## What it does

1. **Reverse-engineers the binary through a staged plan (DeepSeek-driven).**
   The agentic loop works through explicit stages — triage, string/xref
   anchors, crypto, protocol/dispatch, "neighbor" helpers, self-check (see
   `reverse_agent/tasks.py`) — tracked with a subtask tracker the model must
   populate and update. `finish` is refused while any stage is left
   unaddressed (pending/in-progress with no explanation); a stage can be
   marked `blocked` with a reason, but not silently dropped.
2. **Verifies claims instead of trusting the decompiler once.** Any
   dispatch-table/struct/frame-format finding must go through
   `two_source_layout_check` (raw bytes + an independent Capstone disassembly,
   alongside IDA's own) before it can be recorded — this is what catches an
   off-by-one in a dispatch table. Any crypto finding must go through
   `verify_primitive`, which executes the REAL binary function in a Unicorn
   emulator (binary's actual segments, via `list_segments`) and diffs the
   result against a pycryptodome/hashlib reference — "matches the RFC" in
   Python proves nothing about what the binary does.
3. **Writes a protocol client** (`client.py`) with a real, executed
   `--selftest` (round-trips every packet format, checks crypto against test
   vectors) — compiling is necessary but not sufficient, so the pipeline
   actually runs it and feeds failures back to DeepSeek for repair.
4. **Validates end-to-end against the capture.** `pcap_validate` feeds real
   captured payloads through the generated client's decode path as a final,
   independent check that the whole recovered stack holds together.
5. **Writes a deep report** (`report.md`) in a threat-intel style, plus a
   deterministic verification appendix (task-tracker status, emulation
   results, self-test/pcap outcome) that the report LLM cannot omit or
   embellish — generated straight from the run's own data.
6. **Persists an annotated IDA database** (`<binary>.i64`) with every rename
   and comment applied over MCP.

## Requirements

- IDA Pro 9.x (for `idalib`). Launch the GUI once to accept the license.
- Python 3.11+.
- A **DeepSeek API key** (the RE agent needs it; without it only metadata is emitted).
- `tshark` (Wireshark) on `PATH` — optional, only for the corroboration pass.

## Setup

```bash
./setup.sh "/Applications/IDA Professional 9.4.app"
source .venv/bin/activate
```

Put your key in `.env` (auto-loaded) or export it:

```
DEEPSEEK_API_KEY=sk-...
DEEPSEEK_MODEL=deepseek-v4-flash   # optional
```

`setup.sh` creates `.venv`, installs dependencies, installs the `idapro` wheel
from your IDA install, and activates idalib.

## Usage

```bash
# Full reverse-engineering pass (binary + optional pcap):
python -m reverse_agent --binary samples/<name> --pcap samples/<name>.pcap --out out

# Binary only:
python -m reverse_agent --binary /path/to/sample --out out

# Convenience wrapper (activates the venv, defaults --out to out/):
./run.sh --binary samples/<name> --pcap samples/<name>.pcap
```

Options: `--max-iters N` (RE tool-call budget, default 500), `--model <deepseek-model>`,
`--pcap <file>` (optional), `--mcp-host`, `--mcp-port`, `--keep-server`, `--offline`
(metadata-only; no RE).

A full pass makes many DeepSeek calls and takes several minutes; raise/lower
`--max-iters` to trade depth for time.

### Output (`out/`)

| File | Contents |
| --- | --- |
| `report.md` | Deep reverse-engineering report (threat-intel style) + deterministic verification appendix |
| `client.py` | Standalone Python reimplementation of the sample's protocol, with a real `--selftest` |
| `<binary>.i64` | IDA database with all agent renames/comments applied |
| `analysis.json` | Findings + applied annotations + metadata + task tracker + emulation results |
| `endpoints.json` | Indicators, DNS, flows (corroboration) |
| `ida_server.log` | Headless IDA MCP server log |

## Architecture / modules

| Module | Role |
| --- | --- |
| `reverse_agent/ida_server.py` | Headless IDA Pro MCP server (idalib): full `ida-pro-mcp` toolset + RE helpers (`decompile`, `find_syscall_sites`, `find_immediate_refs`, `find_byte_pattern`, `read_bytes`, `list_segments`, …) + `save_database` |
| `reverse_agent/ida_client.py` | Synchronous MCP (streamable-http) client, with reconnect-on-drop |
| `reverse_agent/tasks.py` | Subtask tracker for the RE plan's stages; gates the agent's `finish` call |
| `reverse_agent/verify.py` | Independent verification: Capstone second-source disassembly (`two_source_layout_check`) + Unicorn-based real-code emulation diffed against pycryptodome/hashlib (`verify_primitive`) |
| `reverse_agent/emu.py` | Unicorn emulation harness (binary segments mapped in, i386 cdecl calling convention, minimal syscall shim) |
| `reverse_agent/tools.py` | OpenAI-style tool schemas + dispatcher (findings notebook, task tracker, verification gates, annotations, cache) |
| `reverse_agent/re_agent.py` | DeepSeek's staged agentic RE loop (triage/anchors/crypto/dispatch/neighbors/self-check) + findings-synthesis finalizer |
| `reverse_agent/report.py` | Deep report authored by DeepSeek + deterministic evidence appendix (scope, symbols, task tracker, emulation verification, self-test/pcap results) |
| `reverse_agent/client_gen.py` | DeepSeek writes `client.py`; compiled AND actually run with `--selftest`, with a repair loop against real failures; also drives the pcap decode check |
| `reverse_agent/pcap.py` | tshark → structured capture summary (corroboration + Stage 8 validation input) |
| `reverse_agent/graph.py` | LangGraph pipeline: `re_explore (binary only) → write_client → pcap_validate → write_report → save_idb` |
| `reverse_agent/cli.py` | Starts the IDA MCP server, runs the graph, tears down |

## How the IDA Pro MCP is wired

The agent uses the [`ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp)
toolset, but instead of the interactive GUI plugin it launches the project's
`idalib` server (`reverse_agent.ida_server`) so analysis runs fully headless.
That process opens the binary with `idapro.open_database(...)`, registers the
full `ida-pro-mcp` RPC tool set over an MCP streamable-http endpoint, and adds
the reverse-engineering, verification, and `save_database` helpers this agent
needs. DeepSeek is an ordinary MCP client of that server.

## Verification, not vibes

Two rules the plan is built around, both enforced in code rather than left to
the model's discipline:

- **Every binary-layout claim needs two independent sources.** A
  dispatch-table/struct/frame-format finding is rejected by `record_finding`
  unless it carries `layout_evidence` from `two_source_layout_check` — raw
  bytes (`get_bytes`/`read_bytes`) *and* an independent Capstone disassembly of
  those same bytes, not just IDA's decompiler read twice. This is what would
  have caught an off-by-one in a dispatch table before it shipped.
- **A crypto primitive is "verified" only if the real binary code ran and
  matched a reference.** `record_finding` requires an explicit
  `emulation_verified` flag on crypto findings; `verify_primitive` is the only
  way to set it true, by executing the actual function in Unicorn (with the
  binary's real segments mapped via `list_segments`) and diffing the output
  against pycryptodome/hashlib. Your own Python matching an RFC vector is not
  evidence about what this binary does.

The agent also can't quietly give up: it must `plan_tasks` its stages up
front, and `finish` is refused while any stage is left unaddressed — a stage
can be marked `blocked` with a reason, but not silently dropped.

## Samples and safety

The repository ships **no malware samples or packet captures**. Put your own
inputs under `samples/` (git-ignored) and run the agent, IDA and any generated
`client.py` only inside an isolated, snapshot-able VM with no access to
production networks. The generated client speaks the sample's real C2
protocol, so never point it at live infrastructure.

## Notes & limitations

- Automated RE is best-effort: the report and client are grounded in the
  decompilation, but details can be imperfect — spot-check against the binary for
  high-stakes use. The report's "Residual Gaps" section lists what was not fully
  recovered.
- Statically-linked stripped binaries have no import symbols, so the agent works
  from the entry point, syscalls, constants and strings.
- `deepseek-v4-flash` is fast but not the most disciplined agent; the loop uses
  anti-repeat/record guards plus a synthesis finalizer to guarantee a substantive
  notebook. A stronger model (`--model deepseek-chat`) generally yields deeper
  findings.

## License

MIT — see [LICENSE](LICENSE). Built during an information-security internship and
published with the supervisor's permission; it contains no samples, captures or
results from the internship.
