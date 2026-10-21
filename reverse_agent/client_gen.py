"""Generate a standalone Python client that reimplements the binary's protocol.

DeepSeek writes `client.py` from the reverse-engineering findings and the
decompilations of the protocol/crypto functions, so analysts can talk to (or
decode traffic from) the sample for further analysis. The output is compiled
with py_compile and, if it fails, sent back to DeepSeek once for repair.
"""
from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
import tempfile

from .ida_client import IDAClient
from .llm import DeepSeek


CLIENT_SYSTEM = """You are writing a standalone Python 3 client that reimplements the
network protocol of a reverse-engineered binary, for further analysis. You are
given the RE findings and decompilations of the relevant functions.

Requirements:
- Output a SINGLE self-contained Python module (standard library only; you may
  use `hashlib`, `socket`, `struct`, `select`, `dataclasses`, `secrets`).
- Encode everything you actually recovered: protocol constants (magics, keys,
  nonces, ports, opcode/attack tables), the cryptographic primitives that were
  identified (hash/KDF/cipher/AEAD/MAC/key-exchange), and functions to BUILD and
  PARSE each packet/frame format, matching the field offsets and byte orders in
  the findings.
- Provide offline decode helpers (e.g. decode_frame/decode_payload) AND a
  connect/handshake path where understood, plus a `main()` (argparse host/port)
  usable for live analysis. Guard live actions behind `if __name__ == '__main__'`.
- Use exact values from the evidence. Where a detail was not recovered, insert a
  clearly-marked `# TODO:` and a safe placeholder — never fabricate keys/opcodes.
- Include a module docstring citing the binary SHA-256 and the IDA symbols the
  logic came from. Prefer dataclasses and small pure functions.
- REQUIRED: implement `--selftest` as a CLI flag (no network access, no
  argparse-required positional args needed to run it) that, when passed,
  round-trips every packet/frame format you implemented (build then parse back
  the same values) AND, where a crypto primitive was recovered, encrypts/hashes
  a fixed test vector and asserts the expected output. It must print
  "SELFTEST OK" and exit 0 on success, or print each failing assertion and
  exit 1 on failure. This is the real check that the client actually works —
  a script that only compiles proves nothing.
- REQUIRED: implement `--live-connect-test [HOST] [PORT]` as a CLI flag (HOST
  defaults to a C2 host discovered in the findings if you have one, PORT to a
  discovered C2 port). This does ONLY a raw TCP connect and IMMEDIATE
  disconnect — open the socket with a short timeout (5s), call connect(),
  and close() it right away. NEVER send or receive a single byte of protocol
  data — this is a reachability check, not a live engagement. Print exactly
  one of: "CONNECT OK" (connect() succeeded) and exit 0; "CONNECT REFUSED"
  (ConnectionRefusedError — the port actively rejected the connection, a
  signal the endpoint/port info might be wrong) and exit 2; or
  "CONNECT UNREACHABLE" (timeout, DNS failure, network unreachable —
  inconclusive, could be sinkholed/firewalled/offline, not a verdict on your
  recovered info) and exit 3. If no C2 endpoint was recovered at all, print
  "CONNECT SKIPPED: no endpoint known" and exit 3 without attempting anything.

Output ONLY the Python source code (no markdown fences, no commentary)."""


def _relevant_symbols(annotations: list[dict]) -> dict[str, str]:
    out = {}
    for a in annotations:
        if a.get("action") == "rename_function" and a.get("address"):
            out[a["address"]] = a["value"]
    return out


def _protocol_decompilations(client: IDAClient, symbols: dict[str, str],
                             max_funcs: int = 16, chars: int = 2200) -> list[dict]:
    # Prioritise functions whose names hint at protocol/crypto/config logic.
    priority = ("crypt", "cipher", "chacha", "poly", "sha", "hash", "kdf", "key",
                "x25519", "auth", "handshake", "frame", "secure", "config", "decrypt",
                "encrypt", "dns", "c2", "connect", "send", "recv", "packet", "dispatch",
                "task", "attack", "shell", "keepalive", "register", "nonce")

    def score(name: str) -> int:
        low = name.lower()
        return sum(1 for p in priority if p in low)

    ordered = sorted(symbols.items(), key=lambda kv: -score(kv[1]))
    out = []
    for addr, name in ordered[:max_funcs]:
        dec = client.try_call("decompile", default=None, address=addr)
        if isinstance(dec, str) and dec.strip():
            out.append({"address": addr, "name": name, "pseudocode": dec[:chars]})
    return out


def _strip_fences(code: str) -> str:
    m = re.search(r"```(?:python)?\s*(.*?)```", code, re.DOTALL)
    if m:
        return m.group(1).strip() + "\n"
    return code.strip() + "\n"


def _compiles(code: str) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write(code)
        path = fh.name
    try:
        py_compile.compile(path, doraise=True)
        return True, ""
    except py_compile.PyCompileError as exc:
        return False, str(exc)
    finally:
        os.unlink(path)


def run_selftest(code: str, timeout: float = 30.0) -> tuple[bool, str]:
    """Actually execute `client.py --selftest` in a subprocess — the real check
    that the client works, not just that it parses. Returns (ok, output)."""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write(code)
        path = fh.name
    try:
        proc = subprocess.run(
            [sys.executable, path, "--selftest"],
            capture_output=True, text=True, timeout=timeout,
        )
        out = (proc.stdout + proc.stderr).strip()
        ok = proc.returncode == 0 and "SELFTEST OK" in out
        return ok, out[-4000:]
    except subprocess.TimeoutExpired:
        return False, "selftest timed out (hung, or accidentally tried to open a real network connection)"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        os.unlink(path)


_DECODE_CANDIDATES = ("decode_frame", "decode_payload", "parse_frame", "parse_packet",
                      "decrypt_frame", "decrypt_payload")

_DECODE_DRIVER = f"""
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("_generated_client", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fn = None
for name in {_DECODE_CANDIDATES!r}:
    if hasattr(mod, name):
        fn = getattr(mod, name)
        break
packets = json.loads(sys.argv[2])
out = []
if fn is None:
    print(json.dumps({{"error": "no decode function found (tried {_DECODE_CANDIDATES!r})"}}))
    sys.exit(0)
for pkt in packets:
    try:
        data = bytes.fromhex(pkt["hex"])
        result = fn(data)
        out.append({{"frame": pkt["frame"], "ok": True, "result": repr(result)[:200]}})
    except Exception as exc:
        out.append({{"frame": pkt["frame"], "ok": False, "error": f"{{type(exc).__name__}}: {{exc}}"}})
print(json.dumps(out))
"""


def try_decode_streams(code: str, streams: list[dict], out_dir: str, timeout: float = 20.0) -> dict:
    """Stage 8 validation: feed real captured payload bytes to whichever decode
    function client.py exposes and see if anything comes back non-garbage. This
    is corroboration, not proof (a decode call not raising isn't the same as a
    correct decode) — report it as such."""
    client_path = os.path.join(tempfile.mkdtemp(prefix="netmap_pcapcheck_"), "client.py")
    with open(client_path, "w") as fh:
        fh.write(code)
    packets = []
    for st in streams:
        for pkt in st.get("packets", []):
            if pkt.get("hex"):
                packets.append({"frame": pkt.get("frame"), "hex": pkt["hex"]})
    if not packets:
        return {"attempted": False, "reason": "no non-empty payloads in the capture"}

    driver_path = os.path.join(os.path.dirname(client_path), "_decode_driver.py")
    with open(driver_path, "w") as fh:
        fh.write(_DECODE_DRIVER)
    try:
        proc = subprocess.run(
            [sys.executable, driver_path, client_path, json.dumps(packets[:40])],
            capture_output=True, text=True, timeout=timeout,
        )
        raw = proc.stdout.strip()
        parsed = json.loads(raw) if raw else {"error": (proc.stderr or "no output")[-2000:]}
    except subprocess.TimeoutExpired:
        return {"attempted": True, "summary": "timed out", "error": "decode driver timed out"}
    except Exception as exc:
        return {"attempted": True, "summary": f"driver error: {exc}", "error": str(exc)}

    if isinstance(parsed, dict) and "error" in parsed:
        return {"attempted": True, "summary": parsed["error"], "results": []}
    ok_count = sum(1 for r in parsed if r.get("ok"))
    return {
        "attempted": True,
        "summary": f"{ok_count}/{len(parsed)} captured packets decoded without raising "
                   "(does not by itself prove the decode is semantically correct)",
        "results": parsed,
    }


def run_live_connect_test(client_path: str, host: str = "", port: str = "",
                          timeout: float = 15.0) -> dict:
    """Explicit, opt-in check: run the generated client's --live-connect-test
    against the real network (raw connect + immediate disconnect, no data
    sent — see the requirement in CLIENT_SYSTEM). This is NEVER invoked
    automatically by the pipeline: reaching out to what may be a real C2
    server is a deliberate action for the analyst to take on purpose (via the
    `--live-connect-test` CLI flag), not something an automated run should do
    without a human deciding to."""
    args = [sys.executable, client_path, "--live-connect-test"]
    if host:
        args.append(host)
    if port:
        args.append(str(port))
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        out = (proc.stdout + proc.stderr).strip()
        code = proc.returncode
    except subprocess.TimeoutExpired:
        return {"verdict": "unreachable", "exit_code": None,
                "output": "test process itself timed out — client.py's own timeout may not be working"}
    if "CONNECT OK" in out:
        verdict = "ok"
    elif "CONNECT REFUSED" in out:
        verdict = "refused"
    elif "CONNECT SKIPPED" in out:
        verdict = "skipped"
    else:
        verdict = "unreachable"
    return {"verdict": verdict, "exit_code": code, "output": out[-1000:]}


def generate_client(state: dict, llm: DeepSeek, client: IDAClient) -> dict:
    """Returns {"code": str, "selftest_ok": bool, "selftest_output": str}."""
    evidence = state.get("evidence", {})
    meta = evidence.get("metadata", {}) or state.get("metadata", {})
    re_result = state.get("re_result", {})
    findings = re_result.get("findings", [])
    annotations = re_result.get("annotations", [])
    pcap = state.get("pcap", {})
    symbols = _relevant_symbols(annotations)
    decomp = _protocol_decompilations(client, symbols)

    context = {
        "binary_sha256": meta.get("sha256"),
        "overall_summary": re_result.get("summary", ""),
        "findings": findings,
        "applied_symbols": symbols,
        "protocol_decompilations": decomp,
        "captured_endpoints": pcap.get("endpoints"),
        "captured_dns": pcap.get("dns"),
    }
    user = ("Write the protocol client from this reverse-engineering evidence:\n\n"
            + json.dumps(context, indent=2, default=str))
    code = _strip_fences(llm.complete(CLIENT_SYSTEM, user, temperature=0.2, max_tokens=16000))

    ok, err = _compiles(code)
    if not ok:
        repair = (f"The client you produced failed to compile:\n{err}\n\n"
                  "Return a corrected, complete Python module (source only).")
        code = _strip_fences(llm.complete(CLIENT_SYSTEM, user + "\n\n" + repair,
                                          temperature=0.1, max_tokens=16000))
        ok, err = _compiles(code)
    if not ok:
        return {"code": f"# WARNING: generated client did not compile cleanly: {err}\n" + code,
                "selftest_ok": False, "selftest_output": f"compile error: {err}"}

    # Compiling proves nothing about correctness — actually run --selftest and
    # repair against real failures, up to a couple of rounds.
    st_ok, st_out = run_selftest(code)
    attempts = 0
    while not st_ok and attempts < 2:
        attempts += 1
        repair = (f"Running `python client.py --selftest` failed:\n{st_out}\n\n"
                  "Fix the actual bug (not just the symptom) and return the corrected, "
                  "complete Python module (source only). Keep --selftest exercising every "
                  "packet/frame format and crypto primitive you implemented.")
        code = _strip_fences(llm.complete(CLIENT_SYSTEM, user + "\n\n" + repair,
                                          temperature=0.1, max_tokens=16000))
        ok, err = _compiles(code)
        if not ok:
            return {"code": f"# WARNING: repaired client did not compile cleanly: {err}\n" + code,
                    "selftest_ok": False, "selftest_output": f"compile error: {err}"}
        st_ok, st_out = run_selftest(code)

    header = "" if st_ok else f"# WARNING: --selftest did not pass — treat this client as unverified\n"
    return {"code": header + code, "selftest_ok": st_ok, "selftest_output": st_out}
