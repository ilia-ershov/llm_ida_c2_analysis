"""Independent verification: second-source disassembly and real-code emulation.

Two rules from the RE plan this module exists to enforce:

1. Every claim about binary layout must be backed by TWO independent sources —
   raw bytes (what's actually there) and disassembly (how code reads it: field
   offsets, order, stride). Reading IDA's own decompiler output twice is not
   independent; Capstone disassembling the same raw bytes IDA read is. This is
   what catches an off-by-one in a dispatch table before it ships.
2. A crypto primitive is only "verified" if the REAL binary code was executed
   (via Unicorn, using the binary's actual segments) and its output diffed
   against a reference implementation (pycryptodome/hashlib) — not "my Python
   matches the RFC", which says nothing about what this binary actually does.
"""
from __future__ import annotations

from dataclasses import dataclass

from .emu import Emulator, Segment
from .ida_client import IDAClient


# ---------------------------------------------------------------------------
# Second independent disassembler (Capstone) over raw bytes from get_bytes.
# ---------------------------------------------------------------------------
def capstone_disasm(data: bytes, base_addr: int, bitness: int = 32) -> list[dict]:
    """Disassemble raw bytes with Capstone — independent of IDA's own
    disassembler/decompiler. Returns [{address, size, mnemonic, op_str}]."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64 if bitness == 64 else CS_MODE_32)
    md.detail = False
    out = []
    for insn in md.disasm(data, base_addr):
        out.append({
            "address": hex(insn.address),
            "size": insn.size,
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
        })
    return out


def two_source_layout_check(client: IDAClient, address: str, size: int) -> dict:
    """Ground-truth helper for a structure/dispatch-table claim: read the raw
    bytes at `address` AND independently disassemble them with Capstone, so a
    finding can be backed by both "what's there" and "how code would read it"
    without relying on IDA's decompiler twice. Returns
    {address, size, bytes_hex, capstone_disasm, ida_disasm}."""
    raw = client.try_call("read_bytes", default=None, address=address, size=size)
    hex_bytes = raw.get("hex") if isinstance(raw, dict) else None
    ida_dis = client.try_call("disassemble_function", default=[], address=address) or []
    cap_dis: list[dict] = []
    if hex_bytes:
        try:
            base = int(address, 16) if str(address).lower().startswith("0x") else int(address)
            cap_dis = capstone_disasm(bytes.fromhex(hex_bytes), base)
        except Exception as exc:
            cap_dis = [{"error": str(exc)}]
    return {
        "address": address, "size": size,
        "bytes_hex": hex_bytes,
        "capstone_disasm": cap_dis[:40],
        "ida_disasm": ida_dis[:40] if isinstance(ida_dis, list) else ida_dis,
    }


# ---------------------------------------------------------------------------
# Emulation-based primitive verification.
# ---------------------------------------------------------------------------
# Matches ida_server.read_segment_bytes's server-side cap. A segment larger
# than this is mapped zero-filled beyond the cap (fine for the .text/.rodata
# regions emulation actually needs; a huge .bss stays correctly zeroed anyway).
_SEGMENT_READ_CAP = 4 * 1024 * 1024


def build_emulator(client: IDAClient) -> Emulator | None:
    """Map the target binary's real segments (via the IDA MCP's list_segments +
    read_segment_bytes) into a fresh Unicorn instance. Returns None if segment
    info is unavailable (older server / tool not registered).

    Uses read_segment_bytes (one bulk call per segment, up to 4 MiB) rather
    than the LLM-facing read_bytes (capped at 512B server-side): paging a
    multi-MB segment through 512-byte reads is tens of thousands of
    sequential MCP round trips — that pathological loop is what hung a run
    for hours in practice before this fix."""
    segs = client.try_call("list_segments", default=None)
    if not segs:
        return None
    segments = []
    for s in segs:
        start = int(s["start"], 16)
        end = int(s["end"], 16)
        size = end - start
        if size <= 0 or size > 64 * 1024 * 1024:
            continue
        data = b""
        if s.get("perm", 0) & 4:  # readable -> pull actual bytes for accurate emulation
            chunk = client.try_call("read_segment_bytes", default=None,
                                    address=hex(start), size=min(size, _SEGMENT_READ_CAP))
            if isinstance(chunk, dict) and chunk.get("hex"):
                data = bytes.fromhex(chunk["hex"])
        segments.append(Segment(start=start, end=end, perm=s.get("perm", 5),
                                data=data, name=s.get("name", "")))
    if not segments:
        return None
    return Emulator(segments)


@dataclass
class PrimitiveVerdict:
    verified: bool
    reason: str
    emulated_hex: str = ""
    reference_hex: str = ""


def _reference_digest(primitive: str, data: bytes, key: bytes = b"") -> bytes | None:
    """Compute a reference value with pycryptodome/hashlib for known primitive
    names. Returns None for anything not recognized (caller must then fall back
    to "not verified" rather than guessing)."""
    p = primitive.lower()
    try:
        if p in ("md5",):
            import hashlib
            return hashlib.md5(data).digest()
        if p in ("sha1",):
            import hashlib
            return hashlib.sha1(data).digest()
        if p in ("sha256",):
            import hashlib
            return hashlib.sha256(data).digest()
        if p in ("rc4", "arc4"):
            from Crypto.Cipher import ARC4
            return ARC4.new(key).encrypt(data)
        if p in ("chacha20",):
            from Crypto.Cipher import ChaCha20
            nonce = key[32:40] if len(key) >= 40 else b"\x00" * 8
            k = key[:32]
            return ChaCha20.new(key=k, nonce=nonce).encrypt(data)
        if p in ("aes-ecb",):
            from Crypto.Cipher import AES
            return AES.new(key, AES.MODE_ECB).encrypt(data)
        if p in ("xor",):
            return bytes(b ^ key[i % len(key)] for i, b in enumerate(data)) if key else None
    except Exception:
        return None
    return None


def verify_primitive(client: IDAClient, function_address: str, primitive: str,
                     input_hex: str, key_hex: str = "",
                     out_size: int = 0) -> PrimitiveVerdict:
    """Execute the REAL binary function in Unicorn against `input_hex`/`key_hex`
    and diff the result against a pycryptodome/hashlib reference for
    `primitive`. This is the only thing that counts as "verified" per the RE
    plan — a Python reimplementation matching an RFC vector says nothing about
    what THIS binary does.

    Calling convention assumed: cdecl, args (buf_ptr, buf_len[, key_ptr,
    key_len[, out_ptr]]) — adjust by wrapping this for anything more exotic;
    record an unverified finding rather than fabricating a match.

    Always returns a PrimitiveVerdict, never raises: a harness failure (e.g. a
    Unicorn mapping error) is itself a meaningful "not verified, here's why"
    result, not something that should propagate as an exception and vanish
    before it's recorded as an attempt — that previously let the finish-gate
    (which requires at least one recorded attempt) and this function's own
    honest failures deadlock against each other."""
    try:
        emu = build_emulator(client)
    except Exception as exc:
        return PrimitiveVerdict(False, f"emulator setup failed: {type(exc).__name__}: {exc}")
    if emu is None:
        return PrimitiveVerdict(False, "no segment info available (list_segments missing) — cannot emulate")

    data = bytes.fromhex(input_hex)
    key = bytes.fromhex(key_hex) if key_hex else b""
    ref = _reference_digest(primitive, data, key)
    if ref is None:
        return PrimitiveVerdict(False, f"no reference implementation for primitive {primitive!r} "
                                       "(unsupported) — record as not verified, do not claim RFC match")

    try:
        addr = int(function_address, 16) if function_address.lower().startswith("0x") else int(function_address)
        buf_ptr = emu.alloc(len(data) + 16)
        emu.write_bytes(buf_ptr, data)
        out_ptr = emu.alloc(max(out_size, len(ref)) + 16)
        args = [buf_ptr, len(data)]
        if key:
            key_ptr = emu.alloc(len(key) + 16)
            emu.write_bytes(key_ptr, key)
            args += [key_ptr, len(key)]
        args.append(out_ptr)
        result = emu.call_cdecl(addr, args)
        if not result.ok:
            return PrimitiveVerdict(False, f"emulation failed: {result.error}")
        emitted = emu.read_bytes(out_ptr, len(ref))
    except Exception as exc:
        return PrimitiveVerdict(False, f"emulation harness error: {type(exc).__name__}: {exc}")

    match = emitted == ref
    return PrimitiveVerdict(
        verified=match,
        reason="emulated output matches reference" if match else
               "MISMATCH — emulated real code disagrees with reference; the primitive/harness "
               "assumption (args, offsets, convention) is wrong, not just unlucky",
        emulated_hex=emitted.hex(), reference_hex=ref.hex(),
    )
