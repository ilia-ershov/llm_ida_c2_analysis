"""Static network-call discovery over the IDA Pro MCP interface.

Gathers the binary-side evidence the DeepSeek mapper needs: syscall sites, the
socketcall wrapper(s) and their callers (the socket/connect/send/recv
primitives), references to network constants derived from the capture (resolver
IP, observed ports), network-looking strings, and decompilations of the most
relevant functions.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field, asdict
from typing import Any

from .ida_client import IDAClient
from .pcap import PcapSummary


def _to_int(x) -> int | None:
    try:
        return int(x, 16) if isinstance(x, str) and x.lower().startswith("0x") else int(x)
    except Exception:
        return None


def _xref_func(x: dict) -> tuple[str | None, str | None]:
    """Normalize the 'function' field of an xref/hit into (address_str, name).

    get_xrefs_to nests it as {'address','name','size'}; the helper tools return
    a hex string plus a separate 'function_name'.
    """
    fn = x.get("function")
    if isinstance(fn, dict):
        return fn.get("address"), fn.get("name")
    if isinstance(fn, str):
        return fn, x.get("function_name")
    return None, None


def _pack_ip(ip: str) -> int | None:
    try:
        return struct.unpack("<I", socket.inet_aton(ip))[0]
    except Exception:
        return None


@dataclass
class CandidateFunction:
    address: str
    name: str
    reason: str
    prototype: str | None = None
    decompilation: str | None = None


@dataclass
class NetEvidence:
    metadata: dict = field(default_factory=dict)
    syscall_sites: list[dict] = field(default_factory=list)
    network_syscalls: list[dict] = field(default_factory=list)
    socketcall_wrappers: list[str] = field(default_factory=list)
    primitive_callers: list[dict] = field(default_factory=list)   # callers of socketcall wrapper
    constant_refs: list[dict] = field(default_factory=list)       # ip/port constants -> code
    network_strings: list[dict] = field(default_factory=list)
    candidates: list[CandidateFunction] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def gather_evidence(client: IDAClient, pcap: PcapSummary,
                    max_decompile: int = 10, decompile_chars: int = 2200) -> NetEvidence:
    ev = NetEvidence()
    ev.metadata = client.try_call("get_metadata", default={}) or {}

    # 1. Syscalls (int 0x80) and the network-relevant subset.
    ev.syscall_sites = client.try_call("find_syscall_sites", default=[]) or []
    ev.network_syscalls = [s for s in ev.syscall_sites if s.get("is_network")]

    # 2. socketcall wrapper functions = functions that contain a socketcall.
    wrappers = sorted({s["function"] for s in ev.syscall_sites
                       if s.get("eax") == 102 and s.get("function")})
    ev.socketcall_wrappers = wrappers

    # 3. Callers of each wrapper — the socket/connect/send/recv primitives, and
    #    the higher-level functions that invoke them.
    caller_reason: dict[str, str] = {}
    names: dict[str, str] = {}
    for w in wrappers:
        xrefs = client.try_call("get_xrefs_to", default=[], address=w) or []
        for xr in xrefs:
            addr, name = _xref_func(xr)
            if addr:
                caller_reason.setdefault(addr, f"calls socketcall wrapper {w}")
                if name:
                    names[addr] = name
        ev.primitive_callers.append({"wrapper": w, "callers": xrefs})

    # 4. Constant references derived from the capture.
    const_targets = _capture_constants(pcap)
    if const_targets:
        refs = client.try_call("find_immediate_refs", default=[], values=list(const_targets.keys())) or []
        for r in refs:
            val = r.get("value")
            hits = r.get("hits", [])
            # Ubiquitous constants (0, broadcast, tiny ints) are not informative;
            # a constant referenced from dozens of functions is almost certainly
            # not the network endpoint we care about.
            if hits and len(hits) <= 24:
                ev.constant_refs.append({
                    "value": val,
                    "value_hex": hex(val) if isinstance(val, int) else str(val),
                    "meaning": const_targets.get(val, "constant"),
                    "hits": hits,
                })
                for h in hits:
                    addr, name = _xref_func(h)
                    if addr:
                        caller_reason.setdefault(addr, f"references {const_targets.get(val, 'network constant')}")
                        if name:
                            names[addr] = name

    # 5. Network-looking strings.
    ev.network_strings = (client.try_call("list_network_strings", default=[], limit=120) or [])[:120]

    # 6. Build the candidate function set (wrappers + callers + const refs) and
    #    decompile a bounded number of them for the LLM.
    ordered: list[tuple[str, str]] = []
    seen = set()
    for fn in wrappers:
        if fn not in seen:
            ordered.append((fn, "socketcall wrapper (multiplexes socket/connect/send/recv)"))
            seen.add(fn)

    # Prioritise functions that reference capture-derived constants (resolver
    # IP, C2 port) over the generic libc socket primitives, since they carry
    # more semantic signal for the mapper.
    def _priority(reason: str) -> int:
        return 0 if reason.startswith("references") else 1

    for fn, reason in sorted(caller_reason.items(), key=lambda kv: _priority(kv[1])):
        if fn not in seen:
            ordered.append((fn, reason))
            seen.add(fn)

    for i, (fn, reason) in enumerate(ordered):
        info = client.try_call("get_function_by_address", default=None, address=fn) or {}
        name = (info.get("name") if isinstance(info, dict) else None) or names.get(fn)
        proto = info.get("prototype") if isinstance(info, dict) else None
        cand = CandidateFunction(address=fn, name=name or fn, reason=reason, prototype=proto)
        if i < max_decompile:
            dec = client.try_call("decompile", default=None, address=fn)
            if isinstance(dec, str) and dec.strip():
                cand.decompilation = dec[:decompile_chars]
        ev.candidates.append(cand)
    return ev


def _capture_constants(pcap: PcapSummary) -> dict[int, str]:
    """Constants worth searching for as immediates in the binary, derived from
    the capture: packed resolver/endpoint IPs and observed ports (host + net
    byte order)."""
    out: dict[int, str] = {}
    ips: set[str] = set()
    ports: set[int] = set()

    for d in pcap.dns:
        if d.get("dst"):
            ips.add(d["dst"])   # resolver
        for a in d.get("a", []):
            ips.add(a)
    for st in pcap.streams:
        if st.get("dst"):
            ips.add(st["dst"])
        for p in (st.get("dstport"), st.get("srcport")):
            if isinstance(p, int):
                ports.add(p)
    for e in pcap.endpoints:
        if e.get("address"):
            ips.add(e["address"])
        if isinstance(e.get("port"), int):
            ports.add(e["port"])

    # Uninformative addresses/ports: unspecified, broadcast, DHCP.
    skip_ips = {"0.0.0.0", "255.255.255.255"}
    skip_ports = {67, 68}

    for ip in ips:
        if ip in skip_ips:
            continue
        packed = _pack_ip(ip)
        if packed is not None:
            out[packed] = f"packed IPv4 {ip}"
    for p in ports:
        if p in skip_ports or not (0 < p < 65536):
            continue
        out[p] = f"port {p} (host order)"
        net = struct.unpack("<H", struct.pack(">H", p))[0]
        out.setdefault(net, f"port {p} (network order)")
    return out
