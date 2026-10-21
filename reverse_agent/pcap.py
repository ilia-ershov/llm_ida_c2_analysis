"""PCAP parsing via tshark.

Turns a capture file into a structured summary the agent can reason over:
protocol hierarchy, conversations (flows), DNS Q/A, endpoints, and the raw
application-layer payloads of TCP/UDP streams (hex).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Any


class TsharkError(RuntimeError):
    pass


def _tshark_bin() -> str:
    path = shutil.which("tshark")
    if not path:
        raise TsharkError("tshark not found on PATH (install Wireshark/tshark)")
    return path


def _run(args: list[str]) -> str:
    # -n disables MAC/network/transport name resolution so IPs stay numeric.
    proc = subprocess.run(
        [_tshark_bin(), "-n", *args],
        capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0 and not proc.stdout:
        raise TsharkError(f"tshark failed: {' '.join(args)}\n{proc.stderr.strip()}")
    return proc.stdout


def _fields(pcap: str, display_filter: str, fields: list[str]) -> list[list[str]]:
    args = ["-r", pcap, "-T", "fields"]
    if display_filter:
        args += ["-Y", display_filter]
    for f in fields:
        args += ["-e", f]
    args += ["-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]
    out = _run(args)
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        rows.append(line.split("\t"))
    return rows


@dataclass
class PcapSummary:
    path: str
    packet_count: int = 0
    protocols: list[dict] = field(default_factory=list)      # protocol hierarchy
    endpoints: list[dict] = field(default_factory=list)      # ip endpoints w/ ports
    flows: list[dict] = field(default_factory=list)          # tcp+udp conversations
    dns: list[dict] = field(default_factory=list)            # dns queries/answers
    streams: list[dict] = field(default_factory=list)        # app payloads (hex)
    timeline: list[dict] = field(default_factory=list)       # per-packet one-liners

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_pcap(pcap: str, max_streams: int = 40, max_stream_bytes: int = 2048) -> PcapSummary:
    s = PcapSummary(path=pcap)

    # Packet count + compact timeline.
    timeline_rows = _fields(
        pcap, "",
        ["frame.number", "frame.time_relative", "ip.src", "ipv6.src", "ip.dst",
         "ipv6.dst", "_ws.col.protocol", "frame.len", "_ws.col.info"],
    )
    s.packet_count = len(timeline_rows)
    for r in timeline_rows:
        r = (r + [""] * 9)[:9]
        s.timeline.append({
            "frame": _int(r[0]), "t": _float(r[1]),
            "src": r[2] or r[3], "dst": r[4] or r[5],
            "proto": r[6], "len": _int(r[7]), "info": r[8],
        })

    # Protocol hierarchy statistics.
    s.protocols = _protocol_hierarchy(pcap)

    # Conversations (TCP + UDP).
    s.flows = _conversations(pcap, "tcp") + _conversations(pcap, "udp")

    # DNS.
    s.dns = _dns(pcap)

    # Application payloads per stream.
    s.streams = _streams(pcap, max_streams, max_stream_bytes)

    # Endpoints derived from streams (reliable numeric IPs/ports + byte counts).
    s.endpoints = _endpoints_from_streams(s.streams)
    return s


def _endpoints_from_streams(streams: list[dict]) -> list[dict]:
    agg: dict[tuple, dict] = {}
    for st in streams:
        for ip, port in ((st["src"], st["srcport"]), (st["dst"], st["dstport"])):
            if not ip:
                continue
            key = (st["proto"], ip, port)
            e = agg.setdefault(key, {"proto": st["proto"], "address": ip, "port": port, "bytes": 0})
            e["bytes"] += st["total_bytes"]
    return list(agg.values())


def _int(x: str):
    try:
        return int(x)
    except Exception:
        return None


def _float(x: str):
    try:
        return float(x)
    except Exception:
        return None


def _protocol_hierarchy(pcap: str) -> list[dict]:
    out = _run(["-r", pcap, "-q", "-z", "io,phs"])
    result = []
    for line in out.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("=") or stripped.startswith("Protocol Hierarchy"):
            continue
        if "frames:" not in stripped:
            continue
        indent = len(line) - len(line.lstrip())
        name = stripped.split()[0]
        frames = _extract_kv(stripped, "frames:")
        byts = _extract_kv(stripped, "bytes:")
        result.append({"protocol": name, "depth": indent // 2, "frames": frames, "bytes": byts})
    return result


def _extract_kv(line: str, key: str):
    try:
        after = line.split(key, 1)[1].strip()
        return int(after.split()[0])
    except Exception:
        return None


def _conversations(pcap: str, proto: str) -> list[dict]:
    try:
        out = _run(["-r", pcap, "-q", "-z", f"conv,{proto}"])
    except TsharkError:
        return []
    flows = []
    for line in out.splitlines():
        if "<->" not in line:
            continue
        parts = line.split()
        try:
            i = parts.index("<->")
        except ValueError:
            continue
        left, right = parts[i - 1], parts[i + 1]
        # Columns after the endpoints are: <- Frames Bytes | -> Frames Bytes |
        # Total Frames Bytes | RelStart | Duration, with literal "bytes" tokens
        # interspersed. Keep the integer tokens only.
        ints = [_int(t) for t in parts[i + 2:]]
        ints = [n for n in ints if n is not None]
        flow = {"proto": proto, "endpoint_a": left, "endpoint_b": right}
        if len(ints) >= 6:
            flow.update({
                "frames_ba": ints[0], "bytes_ba": ints[1],
                "frames_ab": ints[2], "bytes_ab": ints[3],
                "frames_total": ints[4], "bytes_total": ints[5],
            })
        flows.append(flow)
    return flows


def _dns(pcap: str) -> list[dict]:
    rows = _fields(
        pcap, "dns",
        ["frame.number", "frame.time_relative", "dns.flags.response",
         "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa", "dns.cname",
         "ip.src", "ip.dst"],
    )
    result = []
    for r in rows:
        r = (r + [""] * 10)[:10]
        result.append({
            "frame": _int(r[0]), "t": _float(r[1]),
            "is_response": r[2].strip().lower() in ("1", "true"),
            "query": r[3], "qtype": r[4],
            "a": [x for x in r[5].split(",") if x],
            "aaaa": [x for x in r[6].split(",") if x],
            "cname": [x for x in r[7].split(",") if x],
            "src": r[8], "dst": r[9],
        })
    return result


def _streams(pcap: str, max_streams: int, max_bytes: int) -> list[dict]:
    streams: dict[tuple, dict] = {}
    # TCP payloads.
    for proto, plfield, streamfield in (
        ("tcp", "tcp.payload", "tcp.stream"),
        ("udp", "udp.payload", "udp.stream"),
    ):
        rows = _fields(
            pcap, f"{plfield}",
            ["frame.number", streamfield, "ip.src", f"{proto}.srcport",
             "ip.dst", f"{proto}.dstport", plfield],
        )
        for r in rows:
            r = (r + [""] * 7)[:7]
            sid = (proto, r[1])
            payload_hex = r[6].replace(":", "")
            entry = streams.setdefault(sid, {
                "proto": proto, "stream": _int(r[1]),
                "src": r[2], "srcport": _int(r[3]),
                "dst": r[4], "dstport": _int(r[5]),
                "packets": [], "total_bytes": 0,
            })
            nbytes = len(payload_hex) // 2
            entry["total_bytes"] += nbytes
            if sum(len(p["hex"]) // 2 for p in entry["packets"]) < max_bytes:
                entry["packets"].append({
                    "frame": _int(r[0]),
                    "dir": "a>b" if r[2] == entry["src"] and _int(r[3]) == entry["srcport"] else "b>a",
                    "bytes": nbytes,
                    "hex": payload_hex[: max_bytes * 2],
                })
    ordered = sorted(streams.values(), key=lambda e: -(e["total_bytes"]))
    return ordered[:max_streams]


if __name__ == "__main__":
    import sys
    summary = parse_pcap(sys.argv[1])
    print(json.dumps(summary.to_dict(), indent=2)[:4000])
