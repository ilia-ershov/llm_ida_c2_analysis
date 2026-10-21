"""Unicorn-based emulation harness for verifying recovered code in isolation.

The whole point (per the RE plan's Stage 3): don't just trust a Python
reimplementation against RFC test vectors — execute the REAL binary code for a
candidate primitive (crypto, KDF, PRNG, ...) inside a CPU emulator, with the
binary's actual segments (.text/.rodata/.data/.bss) mapped 1:1 at their real
virtual addresses, and diff the result against a reference implementation
(pycryptodome/hashlib). If it doesn't match, the primitive is NOT verified —
that must be stated as such, not glossed over.

This module is architecture-generic in structure but the calling-convention
helper (`call_cdecl`) currently implements x86 cdecl (stack-passed args, callee
result in EAX), which matches the i386 ELF sample this project ships with.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from unicorn import (
    Uc, UC_ARCH_X86, UC_MODE_32,
    UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_INVALID,
    UC_MEM_READ_UNMAPPED, UC_MEM_WRITE_UNMAPPED, UC_MEM_FETCH_UNMAPPED,
    UcError,
)
from unicorn.x86_const import (
    UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_EAX, UC_X86_REG_EIP,
)

PAGE = 0x1000


def _align_down(x: int, a: int = PAGE) -> int:
    return x & ~(a - 1)


def _align_up(x: int, a: int = PAGE) -> int:
    return (x + a - 1) & ~(a - 1)


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping/adjacent [lo, hi) ranges so each page gets mapped at
    most once."""
    if not ranges:
        return []
    ordered = sorted(ranges)
    merged = [ordered[0]]
    for lo, hi in ordered[1:]:
        last_lo, last_hi = merged[-1]
        if lo <= last_hi:
            merged[-1] = (last_lo, max(last_hi, hi))
        else:
            merged.append((lo, hi))
    return merged


@dataclass
class Segment:
    start: int
    end: int
    perm: int          # unicorn UC_PROT_* bitmask
    data: bytes = b""
    name: str = ""


@dataclass
class EmuResult:
    ok: bool
    eax: int = 0
    error: str = ""
    instructions: int = 0
    stopped_reason: str = ""


class SyscallStop(Exception):
    """Raised internally when a syscall means 'terminate this call cleanly'."""


class Emulator:
    """A reusable Unicorn instance with the target binary's memory mapped in,
    plus scratch heap/stack regions and a minimal Linux i386 syscall shim so
    self-contained functions (crypto, KDF, PRNG, string/struct helpers) can run
    to completion without a real OS underneath them."""

    STACK_BASE = 0x00500000
    STACK_SIZE = 0x00100000          # 1 MiB
    HEAP_BASE = 0x00700000
    HEAP_SIZE = 0x00400000           # 4 MiB scratch heap for caller-provided buffers
    BRK_BASE = 0x00C00000
    BRK_SIZE = 0x00400000            # fake brk()/mmap2() arena for malloc()
    RET_HOOK_ADDR = 0x00EFF000       # magic "return address" that stops emulation

    def __init__(self, segments: list[Segment]):
        self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
        self._map_segments(segments)
        self._map_scratch()
        self._heap_bump = self.HEAP_BASE
        self._brk_bump = self.BRK_BASE
        self._install_hooks()
        self.trace: list[int] = []
        self._tracing = False

    # -- setup ----------------------------------------------------------------
    def _map_segments(self, segments: list[Segment]):
        from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
        # IDA's logical segments (.text/.rodata/.data/...) are routinely NOT
        # page-aligned and packed tight against each other; independently
        # page-aligning and mem_map()-ing each one (the previous approach)
        # will very often try to map the SAME page twice for two adjacent
        # segments, which Unicorn rejects with UC_ERR_MAP. Map once per
        # merged, non-overlapping page range instead, then write each
        # segment's real bytes into it — permission granularity below a page
        # doesn't matter for this sandbox (nothing here is a security
        # boundary), only "can the emulated code touch it" does.
        ranges: list[tuple[int, int]] = []
        for seg in segments:
            lo = _align_down(seg.start)
            hi = _align_up(seg.end)
            if hi > lo:
                ranges.append((lo, hi))
        for lo, hi in _merge_ranges(ranges):
            self.mu.mem_map(lo, hi - lo, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        for seg in segments:
            if seg.data:
                self.mu.mem_write(seg.start, seg.data)

    def _map_scratch(self):
        from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
        self.mu.mem_map(self.STACK_BASE, self.STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.mu.mem_map(self.HEAP_BASE, self.HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.mu.mem_map(self.BRK_BASE, self.BRK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        # RET_HOOK_ADDR (0xEFF000) falls INSIDE the BRK arena
        # (0xC00000-0x1000000) by construction — mapping its page again here
        # unconditionally used to raise UC_ERR_MAP (double-mapping the same
        # page is rejected by Unicorn); only map it separately if it actually
        # falls outside every range already mapped above.
        hook_page = _align_down(self.RET_HOOK_ADDR)
        already_covered = self.BRK_BASE <= hook_page < self.BRK_BASE + self.BRK_SIZE
        if not already_covered:
            self.mu.mem_map(hook_page, PAGE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        # A tiny executable trap: a HLT byte the code hook intercepts before
        # it would ever execute as real code.
        self.mu.mem_write(self.RET_HOOK_ADDR, b"\xf4")

    def _install_hooks(self):
        self.mu.hook_add(UC_HOOK_INTR, self._on_interrupt)
        self.mu.hook_add(UC_HOOK_MEM_INVALID, self._on_invalid_mem)
        self.mu.hook_add(UC_HOOK_CODE, self._on_code)

    # -- Linux i386 int 0x80 shim ----------------------------------------------
    # Only what's needed to let self-contained helpers (crypto/KDF/PRNG/string
    # utilities, and small malloc()s) run to completion. Anything else returns
    # a harmless 0/-ENOSYS rather than crashing the emulation, and is recorded
    # so callers can see a syscall was stubbed (relevant e.g. to PRNG seeds).
    def _on_interrupt(self, uc, intno, data):
        if intno != 0x80:
            return
        eax = uc.reg_read(UC_X86_REG_EAX)
        self.last_syscalls = getattr(self, "last_syscalls", [])
        if eax == 45 or eax == 192:          # brk / mmap2 -> bump-allocate fake heap
            size = uc.reg_read(__import__("unicorn.x86_const", fromlist=["UC_X86_REG_ECX"]).UC_X86_REG_ECX) if eax == 45 else 0x1000
            ptr = self._brk_bump
            self._brk_bump += _align_up(max(size, 0x1000))
            uc.reg_write(UC_X86_REG_EAX, ptr)
            self.last_syscalls.append(("brk/mmap2", size, ptr))
        elif eax in (20, 64):                 # getpid / getppid -> deterministic mock
            uc.reg_write(UC_X86_REG_EAX, 4242 if eax == 20 else 4241)
            self.last_syscalls.append(("getpid/getppid(mocked)", eax))
        elif eax in (13, 78):                 # time / gettimeofday -> deterministic mock
            uc.reg_write(UC_X86_REG_EAX, 1_700_000_000)
            self.last_syscalls.append(("time(mocked)", eax))
        elif eax in (1, 252):                 # exit / exit_group -> stop cleanly
            self.last_syscalls.append(("exit", eax))
            uc.emu_stop()
        else:
            uc.reg_write(UC_X86_REG_EAX, 0)
            self.last_syscalls.append((f"syscall_{eax}(stubbed->0)", eax))

    def _on_invalid_mem(self, uc, access, address, size, value, data):
        self._mem_fault = (access, address, size)
        return False  # let emu_start raise, we catch it in call_cdecl

    def _on_code(self, uc, address, size, data):
        if self._tracing:
            self.trace.append(address)
        if address == _align_down(self.RET_HOOK_ADDR) or address == self.RET_HOOK_ADDR:
            uc.emu_stop()

    # -- scratch allocator ------------------------------------------------------
    def alloc(self, size: int) -> int:
        size = max(4, size)
        ptr = self._heap_bump
        self._heap_bump += _align_up(size, 16)
        if self._heap_bump - self.HEAP_BASE > self.HEAP_SIZE:
            raise MemoryError("emulator scratch heap exhausted")
        return ptr

    def write_bytes(self, address: int, data: bytes):
        self.mu.mem_write(address, data)

    def read_bytes(self, address: int, size: int) -> bytes:
        return bytes(self.mu.mem_read(address, size))

    # -- calling convention (x86 cdecl) ------------------------------------------
    def call_cdecl(self, function_address: int, int_args: list[int],
                    max_instructions: int = 300_000, timeout_us: int = 3_000_000,
                    trace: bool = False) -> EmuResult:
        """Call `function_address` with `int_args` (already-resolved 32-bit
        values / pointers) using the cdecl convention: push args right-to-left,
        push a synthetic return address, jump in. Returns EAX on normal return."""
        esp = self.STACK_BASE + self.STACK_SIZE - 0x1000
        for val in reversed(int_args):
            esp -= 4
            self.mu.mem_write(esp, (val & 0xFFFFFFFF).to_bytes(4, "little"))
        esp -= 4
        self.mu.mem_write(esp, self.RET_HOOK_ADDR.to_bytes(4, "little"))

        self.mu.reg_write(UC_X86_REG_ESP, esp)
        self.mu.reg_write(UC_X86_REG_EBP, esp)
        self._mem_fault = None
        self.trace = []
        self._tracing = trace
        self.last_syscalls = []
        try:
            self.mu.emu_start(function_address, self.RET_HOOK_ADDR,
                              timeout=timeout_us, count=max_instructions)
        except UcError as exc:
            if self._mem_fault:
                access, addr, size = self._mem_fault
                return EmuResult(ok=False, error=f"UcError: {exc} (mem fault @ {hex(addr)}, size={size})")
            return EmuResult(ok=False, error=f"UcError: {exc}")
        eax = self.mu.reg_read(UC_X86_REG_EAX)
        eip = self.mu.reg_read(UC_X86_REG_EIP)
        reached_ret = eip in (self.RET_HOOK_ADDR, _align_down(self.RET_HOOK_ADDR))
        return EmuResult(ok=True, eax=eax, instructions=len(self.trace) if trace else -1,
                         stopped_reason="returned" if reached_ret else f"stopped @ {hex(eip)} (instruction/time budget)")
