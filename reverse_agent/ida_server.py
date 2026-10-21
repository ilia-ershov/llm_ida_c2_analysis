"""Headless IDA Pro MCP server (idalib backend).

This launches the mrexodia `ida-pro-mcp` toolset against a binary using IDA's
`idalib` headless engine, and augments it with a handful of network-analysis
helper tools plus a `save_database` tool so annotations made by the agent can be
persisted to a real `.i64` database.

Run standalone:
    python -m reverse_agent.ida_server <binary> --host 127.0.0.1 --port 8745

The agent (`reverse_agent.cli`) normally starts this as a subprocess.
"""
from __future__ import annotations

import argparse
import importlib
import inspect
import logging
import sys
import typing
from pathlib import Path

# ida_pro_mcp's mcp-plugin defines its result models with ``typing.TypedDict``.
# On Python < 3.12, pydantic (used by FastMCP to build tool schemas) rejects
# those and requires ``typing_extensions.TypedDict``. Patch it in before the
# plugin module is imported so the TypedDict classes are built correctly.
import typing_extensions as _te
typing.TypedDict = _te.TypedDict  # type: ignore[assignment]

# `idapro` must be imported first to initialize idalib.
import idapro  # noqa: F401  (side effect: initializes IDA library)

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_loader
import ida_name
import ida_segment
import idautils
import idc

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("netmap.ida_server")

# ---------------------------------------------------------------------------
# i386 socketcall sub-function numbers (int 0x80, eax = 102).
# ---------------------------------------------------------------------------
SOCKETCALL_SUBCALLS = {
    1: "socket",
    2: "bind",
    3: "connect",
    4: "listen",
    5: "accept",
    6: "getsockname",
    7: "getpeername",
    8: "socketpair",
    9: "send",
    10: "recv",
    11: "sendto",
    12: "recvfrom",
    13: "shutdown",
    14: "setsockopt",
    15: "getsockopt",
    16: "sendmsg",
    17: "recvmsg",
    18: "accept4",
}

# Selected raw i386 int-0x80 syscall numbers that are network/comms relevant.
LINUX_I386_SYSCALLS = {
    102: "socketcall",
    359: "socket",
    362: "connect",
    369: "sendto",
    371: "recvfrom",
    370: "sendmsg",
    372: "recvmsg",
    3: "read",
    4: "write",
    5: "open",
    142: "select",
    168: "poll",
}

NETWORK_KEYWORDS = (
    "socket", "connect", "send", "recv", "bind", "listen", "dns", "http",
    "://", "host", "GET ", "POST ", "user-agent", "port", "tcp", "udp",
)


def _last_imm_to_reg(head_ea: int, reg: str, lookback: int = 16):
    """Walk backwards up to `lookback` instructions from head_ea (exclusive)
    and return the last immediate value moved into `reg`, or None."""
    ea = idc.prev_head(head_ea, 0)
    steps = 0
    while ea != idc.BADADDR and steps < lookback:
        mnem = idc.print_insn_mnem(ea).lower()
        op0 = idc.print_operand(ea, 0).lower()
        if mnem in ("mov", "xor") and op0 == reg:
            if mnem == "xor" and idc.print_operand(ea, 1).lower() == reg:
                return 0
            if idc.get_operand_type(ea, 1) in (idc.o_imm,):
                return idc.get_operand_value(ea, 1)
        # push N ; pop reg  pattern
        if mnem == "pop" and op0 == reg:
            prev = idc.prev_head(ea, 0)
            if idc.print_insn_mnem(prev).lower() == "push" and idc.get_operand_type(prev, 0) == idc.o_imm:
                return idc.get_operand_value(prev, 0)
        ea = idc.prev_head(ea, 0)
        steps += 1
    return None


# ---------------------------------------------------------------------------
# Helper MCP tools
# ---------------------------------------------------------------------------

def find_syscall_sites() -> list[dict]:
    """Locate every int-0x80 syscall in the binary and, where resolvable,
    classify it (raw syscall name and, for socketcall, its sub-function).
    Returns a list of {address, function, function_name, eax, syscall,
    socketcall_sub, socketcall_name, is_network}."""
    results = []
    for f_ea in idautils.Functions():
        f = ida_funcs.get_func(f_ea)
        if not f:
            continue
        fname = ida_funcs.get_func_name(f_ea) or ""
        for head in idautils.Heads(f.start_ea, f.end_ea):
            if idc.print_insn_mnem(head).lower() != "int":
                continue
            if idc.get_operand_value(head, 0) != 0x80:
                continue
            eax = _last_imm_to_reg(head, "eax")
            entry = {
                "address": hex(head),
                "function": hex(f.start_ea),
                "function_name": fname,
                "eax": eax,
                "syscall": LINUX_I386_SYSCALLS.get(eax) if eax is not None else None,
                "socketcall_sub": None,
                "socketcall_name": None,
                "is_network": False,
            }
            if eax == 102:  # socketcall
                sub = _last_imm_to_reg(head, "ebx")
                entry["socketcall_sub"] = sub
                entry["socketcall_name"] = SOCKETCALL_SUBCALLS.get(sub)
                entry["is_network"] = True
            elif eax in (359, 362, 369, 370, 371, 372):
                entry["is_network"] = True
            results.append(entry)
    return results


def find_immediate_refs(values: list[int]) -> list[dict]:
    """For each 32-bit integer in `values`, find code locations that use it as
    an immediate operand. Returns [{value, hits:[{address, function,
    function_name}]}]. Useful for locating references to packed IPs / ports."""
    wanted = {int(v) & 0xFFFFFFFF for v in values}
    out = {v: [] for v in wanted}
    for f_ea in idautils.Functions():
        f = ida_funcs.get_func(f_ea)
        if not f:
            continue
        fname = ida_funcs.get_func_name(f_ea) or ""
        for head in idautils.Heads(f.start_ea, f.end_ea):
            for opn in range(2):
                if idc.get_operand_type(head, opn) == idc.o_imm:
                    val = idc.get_operand_value(head, opn) & 0xFFFFFFFF
                    if val in wanted:
                        out[val].append({
                            "address": hex(head),
                            "function": hex(f.start_ea),
                            "function_name": fname,
                        })
    return [{"value": v, "hits": out[v]} for v in wanted]


def find_byte_pattern(hex_pattern: str) -> list[dict]:
    """Find all addresses where a raw byte sequence (hex string, e.g.
    '08080808') occurs in the image. Returns [{address, segment}]."""
    pat = bytes.fromhex(hex_pattern.replace(" ", ""))
    results = []
    ea = idc.get_inf_attr(idc.INF_MIN_EA)
    max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
    while ea < max_ea:
        found = ida_bytes.find_bytes(pat, ea)
        if found == idc.BADADDR or found >= max_ea:
            break
        results.append({"address": hex(found), "segment": idc.get_segm_name(found)})
        ea = found + 1
        if len(results) > 256:
            break
    return results


def get_string_xrefs(substring: str) -> list[dict]:
    """Find strings containing `substring` (case-insensitive) and every code
    xref to them. Returns [{string, address, xrefs:[{address, function,
    function_name}]}]."""
    needle = substring.lower()
    results = []
    for s in idautils.Strings():
        text = str(s)
        if needle not in text.lower():
            continue
        xrefs = []
        for xr in idautils.XrefsTo(s.ea):
            fn = ida_funcs.get_func(xr.frm)
            xrefs.append({
                "address": hex(xr.frm),
                "function": hex(fn.start_ea) if fn else None,
                "function_name": ida_funcs.get_func_name(xr.frm) or "",
            })
        results.append({"string": text, "address": hex(s.ea), "xrefs": xrefs})
    return results


def list_network_strings(limit: int = 200) -> list[dict]:
    """Return strings that look network-relevant (domains, URLs, HTTP verbs,
    socket keywords). Returns [{address, string}]."""
    out = []
    for s in idautils.Strings():
        text = str(s)
        low = text.lower()
        if any(k in low for k in NETWORK_KEYWORDS) or ("." in text and any(c.isalpha() for c in text) and len(text) < 80):
            out.append({"address": hex(s.ea), "string": text})
        if len(out) >= limit:
            break
    return out


def _parse_addr(address) -> int:
    if isinstance(address, int):
        return address
    address = str(address).strip()
    return int(address, 16) if address.lower().startswith("0x") else int(address, 0)


def list_segments() -> list[dict]:
    """List every loader segment: {name, start, end, size, perm (r|w|x bitmask:
    4=read,2=write,1=exec), bitness}. Ground truth for mapping the binary's real
    memory layout into an emulator (Unicorn) — always prefer this over guessing
    file-offset==vaddr, since ELF load segments are not laid out that way."""
    out = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue
        perm = (4 if seg.perm & ida_segment.SEGPERM_READ else 0) \
             | (2 if seg.perm & ida_segment.SEGPERM_WRITE else 0) \
             | (1 if seg.perm & ida_segment.SEGPERM_EXEC else 0)
        out.append({
            "name": ida_segment.get_segm_name(seg) or "",
            "start": hex(seg.start_ea),
            "end": hex(seg.end_ea),
            "size": seg.end_ea - seg.start_ea,
            "perm": perm,
            "bitness": seg.bitness,
        })
    return out


def list_functions_brief(offset: int = 0, count: int = 150) -> list[dict]:
    """Return a compact slice of the function list as {address, name, size}.
    Page through the whole binary with `offset`/`count`."""
    funcs = list(idautils.Functions())
    out = []
    for ea in funcs[offset:offset + max(1, min(int(count), 500))]:
        f = ida_funcs.get_func(ea)
        out.append({
            "address": hex(ea),
            "name": ida_funcs.get_func_name(ea) or "",
            "size": (f.end_ea - f.start_ea) if f else 0,
        })
    return out


def decompile(address: str) -> str:
    """Decompile the function containing `address` to pseudocode (Hex-Rays),
    headless / without any Qt dependency. Returns the C-like text or ''."""
    try:
        cfunc = ida_hexrays.decompile(_parse_addr(address))
        return str(cfunc) if cfunc else ""
    except Exception as exc:  # decompilation can fail on some functions
        return f"/* decompilation failed: {exc} */"


def disassemble_function(address: str) -> list[dict]:
    """Return the disassembly of the function containing `address` as a list of
    {address, mnem, text}."""
    ea = _parse_addr(address)
    f = ida_funcs.get_func(ea)
    if not f:
        return []
    out = []
    for head in idautils.Heads(f.start_ea, f.end_ea):
        out.append({
            "address": hex(head),
            "mnem": idc.print_insn_mnem(head),
            "text": idc.generate_disasm_line(head, 0) or "",
        })
    return out


def read_bytes(address: str, size: int) -> dict:
    """Read up to 512 bytes at `address`; returns {address, size, hex, ascii}."""
    ea = _parse_addr(address)
    size = max(0, min(int(size), 512))
    data = ida_bytes.get_bytes(ea, size) or b""
    ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return {"address": hex(ea), "size": len(data), "hex": data.hex(), "ascii": ascii_repr}


# 4 MiB cap: comfortably covers .text/.rodata/.data for the small, statically
# linked IoT-bot binaries this project targets, in ONE MCP round trip.
_SEGMENT_READ_CAP = 4 * 1024 * 1024


def read_segment_bytes(address: str, size: int) -> dict:
    """Bulk-read up to 4 MiB at `address` in a single call; returns {address,
    size, hex}. NOT exposed to the RE agent's tool schema — this exists only
    for the Unicorn emulation harness (verify.py) to map a whole loader
    segment in one round trip. Paging a multi-MB segment through the 512-byte
    `read_bytes` tool is what previously hung a run for hours (tens of
    thousands of sequential MCP calls for a single large segment)."""
    ea = _parse_addr(address)
    size = max(0, min(int(size), _SEGMENT_READ_CAP))
    data = ida_bytes.get_bytes(ea, size) or b""
    return {"address": hex(ea), "size": len(data), "hex": data.hex()}


def rename_func(function_address: str, new_name: str) -> dict:
    """Rename the function containing an address (headless-safe; does NOT touch
    the Hex-Rays UI, unlike the stock rename_function which breaks under idalib).
    Persisted to the database. Returns {ok, address, name}."""
    ea = _parse_addr(function_address)
    f = ida_funcs.get_func(ea)
    if not f:
        return {"ok": False, "error": f"no function at {function_address}"}
    ok = ida_name.set_name(f.start_ea, new_name, ida_name.SN_NOCHECK | ida_name.SN_FORCE)
    return {"ok": bool(ok), "address": hex(f.start_ea), "name": ida_funcs.get_func_name(f.start_ea)}


def set_comment_at(address: str, comment: str) -> dict:
    """Attach a repeatable comment at an address (headless-safe, no UI refresh).
    Persisted to the database. Returns {ok, address}."""
    ea = _parse_addr(address)
    ok = idc.set_cmt(ea, comment, False)
    if not ok:
        ok = ida_bytes.set_cmt(ea, comment, False)
    return {"ok": bool(ok), "address": hex(ea)}


def save_database(path: str = "") -> dict:
    """Persist the current IDA database (including all annotations made this
    session) to `path` (a .i64 file). If `path` is empty, saves next to the
    input file as <input>.i64. Returns {saved, path}."""
    if not path:
        path = idc.get_idb_path()
        if not path:
            root = ida_nalt_get_input() + ".i64"
            path = root
    ok = ida_loader.save_database(path, 0)
    return {"saved": bool(ok), "path": path}


def ida_nalt_get_input() -> str:
    import ida_nalt
    return ida_nalt.get_input_file_path() or ida_nalt.get_root_filename() or "output"


# ---------------------------------------------------------------------------
# Server bootstrap (mirrors ida_pro_mcp.idalib_server, plus our helpers)
# ---------------------------------------------------------------------------

def _fixup_tool_argument_descriptions(mcp: FastMCP):
    """Splice Annotated[...] parameter docs from mrexodia tools into MCP metadata."""
    import typing_inspection.introspection as intro
    for tool in mcp._tool_manager.list_tools():
        sig = inspect.signature(tool.fn)
        for name, parameter in sig.parameters.items():
            annotation = parameter.annotation
            if not annotation:
                continue
            try:
                inspected = intro.inspect_annotation(
                    annotation, annotation_source=intro.AnnotationSource.ANY
                )
            except Exception:
                continue
            desc = " ".join(m for m in inspected.metadata if isinstance(m, str))
            if not desc:
                continue
            props = tool.parameters.get("properties", {})
            if name in props:
                props[name]["description"] = desc


def build_server(input_path: Path, host: str, port: int, unsafe: bool = True) -> FastMCP:
    mcp = FastMCP("netmap-ida-mcp")
    mcp.settings.host = host
    mcp.settings.port = port

    logger.info("opening database: %s", input_path)
    if idapro.open_database(str(input_path), run_auto_analysis=True):
        raise RuntimeError(f"failed to analyze input file: {input_path}")
    ida_auto.auto_wait()
    try:
        ida_hexrays.init_hexrays_plugin()
    except Exception as exc:  # decompiler may be unavailable for some arches
        logger.warning("hexrays init failed: %s", exc)

    # Register the full mrexodia tool set (read + annotation tools).
    plugin = importlib.import_module("ida_pro_mcp.mcp-plugin")
    for name, callable_ in plugin.rpc_registry.methods.items():
        if unsafe or name not in plugin.rpc_registry.unsafe:
            mcp.add_tool(callable_, name)

    # Register our network-analysis + persistence helpers.
    for fn in (
        find_syscall_sites,
        find_immediate_refs,
        find_byte_pattern,
        get_string_xrefs,
        list_network_strings,
        decompile,
        disassemble_function,
        read_bytes,
        read_segment_bytes,
        list_segments,
        list_functions_brief,
        rename_func,
        set_comment_at,
        save_database,
    ):
        mcp.add_tool(fn, fn.__name__)

    _fixup_tool_argument_descriptions(mcp)
    return mcp


def main(argv=None):
    parser = argparse.ArgumentParser(description="Headless IDA Pro MCP server (idalib)")
    parser.add_argument("input_path", type=Path, help="Binary to analyze")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8745)
    parser.add_argument("--safe", action="store_true", help="Disable unsafe tools")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger().setLevel(logging.DEBUG if args.verbose else logging.INFO)

    if not args.input_path.exists():
        raise FileNotFoundError(args.input_path)

    mcp = build_server(args.input_path, args.host, args.port, unsafe=not args.safe)
    # streamable-http is far more robust than SSE for this workload: SSE keeps a
    # long-lived chunked GET stream that intermittently drops under rapid tool
    # calls (httpx RemoteProtocolError), killing the session mid-analysis.
    mcp.settings.streamable_http_path = "/mcp"
    logger.info("IDA MCP server ready at http://%s:%d/mcp", args.host, args.port)
    print(f"NETMAP_IDA_READY http://{args.host}:{args.port}/mcp", flush=True)
    try:
        mcp.run(transport="streamable-http")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
