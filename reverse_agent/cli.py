"""Command-line entrypoint for reverse_agent.

Starts a headless IDA Pro MCP server (idalib) for the target binary, connects
the agent to it, runs the LangGraph pipeline, and tears everything down.

    python -m reverse_agent --binary samples/<name> --pcap samples/<name>.pcap --out out/
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from .config import Config
from .ida_client import IDAClient
from .graph import NetmapAgent
from . import client_gen


def _start_ida_server(binary: str, host: str, port: int, log_path: str) -> subprocess.Popen:
    log = open(log_path, "w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "reverse_agent.ida_server", binary,
         "--host", host, "--port", str(port)],
        stdout=log, stderr=subprocess.STDOUT,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    return proc


def _wait_ready(log_path: str, proc: subprocess.Popen, timeout: float = 180) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with open(log_path) as fh:
                if "NETMAP_IDA_READY" in fh.read():
                    return True
        except FileNotFoundError:
            pass
        time.sleep(1.0)
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="reverse_agent",
        description="Correlate IDA Pro disassembly with PCAP traffic using DeepSeek.")
    parser.add_argument("--binary", required=True, help="Target binary to analyze")
    parser.add_argument("--pcap", help="Optional PCAP capture (secondary corroboration)")
    parser.add_argument("--out", default="out", help="Output directory (default: out)")
    parser.add_argument("--model", help="DeepSeek model (default: env DEEPSEEK_MODEL or deepseek-v4-flash)")
    parser.add_argument("--max-iters", type=int, default=500,
                        help="Max reverse-engineering tool-call iterations (default 500)")
    parser.add_argument("--offline", action="store_true",
                        help="Skip the LLM (metadata-only; no RE — DeepSeek is required for full analysis)")
    parser.add_argument("--mcp-port", type=int, default=8745)
    parser.add_argument("--mcp-host", default="127.0.0.1")
    parser.add_argument("--keep-server", action="store_true",
                        help="Leave the IDA MCP server running after completion")
    parser.add_argument("--live-connect-test", action="store_true",
                        help="AFTER analysis, deliberately open one raw TCP connection to the "
                             "recovered C2 endpoint and immediately close it (no protocol data "
                             "sent) to sanity-check the recovered host/port. Opt-in only — never "
                             "run automatically, since it contacts real (possibly malicious) "
                             "infrastructure. Requires --live-connect-host/--live-connect-port "
                             "if no endpoint was found in the report.")
    parser.add_argument("--live-connect-host", default="", help="Override C2 host for --live-connect-test")
    parser.add_argument("--live-connect-port", default="", help="Override C2 port for --live-connect-test")
    args = parser.parse_args(argv)

    binary = str(Path(args.binary).resolve())
    pcap = str(Path(args.pcap).resolve()) if args.pcap else ""
    out_dir = str(Path(args.out).resolve())
    os.makedirs(out_dir, exist_ok=True)

    if not os.path.exists(binary):
        parser.error(f"binary not found: {binary}")
    if pcap and not os.path.exists(pcap):
        parser.error(f"pcap not found: {pcap}")

    cfg = Config(ida_host=args.mcp_host, ida_port=args.mcp_port, offline=args.offline)
    if args.model:
        cfg.deepseek_model = args.model
    if not cfg.has_llm and not args.offline:
        print("[netmap] DEEPSEEK_API_KEY not set — the reverse-engineering agent needs "
              "DeepSeek. Running metadata-only (--offline).", file=sys.stderr)
        cfg.offline = True

    server_log = os.path.join(out_dir, "ida_server.log")
    print(f"[netmap] starting headless IDA Pro MCP server for {binary} ...")
    proc = _start_ida_server(binary, cfg.ida_host, cfg.ida_port, server_log)
    client = None
    try:
        if not _wait_ready(server_log, proc):
            tail = ""
            try:
                tail = open(server_log).read()[-1500:]
            except Exception:
                pass
            raise RuntimeError(f"IDA MCP server failed to start. Log tail:\n{tail}")
        print(f"[netmap] IDA MCP server ready at {cfg.ida_sse_url}")

        client = IDAClient(cfg.ida_sse_url).connect()
        print(f"[netmap] connected; {len(client.tools)} MCP tools available")

        agent = NetmapAgent(cfg, client)
        mode = "DeepSeek (" + cfg.deepseek_model + ")" if cfg.has_llm else "metadata-only (offline)"
        print(f"[netmap] reverse-engineer: {mode}")
        state = agent.run(binary, pcap, out_dir, max_iters=args.max_iters)

        print("\n[netmap] done. Artefacts:")
        for name in ("report.md", "client.py", "analysis.json", "endpoints.json",
                     os.path.basename(binary) + ".i64"):
            p = os.path.join(out_dir, name)
            if os.path.exists(p):
                print(f"  - {p}")

        if args.live_connect_test:
            client_py_path = os.path.join(out_dir, "client.py")
            if not os.path.exists(client_py_path):
                print("[netmap] --live-connect-test requested but no client.py was generated; skipping.")
            else:
                print("[netmap] --live-connect-test: opening ONE raw TCP connection to the "
                      "recovered C2 endpoint (no data will be sent) ...")
                result = client_gen.run_live_connect_test(
                    client_py_path, host=args.live_connect_host, port=args.live_connect_port)
                print(f"[netmap] live connect-test verdict: {result['verdict']} — {result['output']}")
        return 0
    finally:
        if client is not None:
            client.close()
        if not args.keep_server:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
