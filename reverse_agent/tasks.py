"""Subtask tracker for the reverse-engineering agent.

The RE plan is staged (triage -> anchors -> crypto -> protocol/dispatch ->
deliverables -> self-check -> pcap validation). Left to itself, an LLM agent
tends to wander: it declares "finish" after the first plausible story instead
of working through every stage, and it quietly drops stages it finds hard
(crypto verification, dispatch cross-checks) rather than admitting they are
unresolved. A tracker that the model must explicitly populate and update — and
that the loop can inspect to gate `finish` — makes both failure modes visible
instead of silent.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

VALID_STATUSES = ("pending", "in_progress", "done", "blocked")

DEFAULT_STAGES = [
    "triage",             # file/shasum, idb_open, survey_binary; hold family hypothesis loosely
    "anchors",            # strings + xrefs to protocol/crypto/attack labels
    "crypto",             # identify primitives, derive KDF/handshake from disasm, emulate to verify
    "protocol_dispatch",  # main loop -> c2_process_plaintext -> dispatch table, two-source verified
    "neighbors",          # decompile every helper visible in main, even the small ones
    "deliverables",       # report.md + client.py (with --selftest), annotate + save IDB
    "self_check",         # "does the report suffice to rebuild behavior?" + explicit gaps
    "pcap_validation",    # decrypt a real captured payload with the recovered stack
]

# Stages the re_explore agentic loop itself is responsible for (and that gate
# its `finish` call). "deliverables" and "pcap_validation" happen in later
# graph nodes (write_report/write_client/save_idb, pcap-decrypt check) that run
# deterministically after re_explore, so they are not gated here.
AGENT_GATED_STAGES = [
    "triage", "anchors", "crypto", "protocol_dispatch", "neighbors", "self_check",
]


@dataclass
class Task:
    id: int
    stage: str
    title: str
    status: str = "pending"
    note: str = ""


class TaskTracker:
    def __init__(self):
        self.tasks: list[Task] = []
        self._next_id = 1

    def plan(self, items: list[dict]) -> list[dict]:
        """Bulk-create the initial task list. `items` is [{stage, title}, ...]."""
        for it in items:
            stage = it.get("stage", "misc")
            title = it.get("title", "")
            if not title:
                continue
            self.tasks.append(Task(id=self._next_id, stage=stage, title=title))
            self._next_id += 1
        return self.as_dicts()

    def touch_stage(self, stage: str, note: str = "auto-touched by tool activity") -> None:
        """Auto-advance a stage from 'pending' to 'in_progress' when the model
        actually uses a tool that belongs to that stage (verify_primitive for
        crypto, two_source_layout_check for protocol_dispatch, ...). Relying
        purely on the model to call update_task turned out to be unreliable —
        real work was happening while the tracker sat untouched at 'pending'
        for every stage past the first. This does not mark anything 'done'
        (only the model can judge that); it just keeps the tracker honest
        about what's actually in progress."""
        for t in self.tasks:
            if t.stage == stage and t.status == "pending":
                t.status = "in_progress"
                if not t.note:
                    t.note = note
                return

    def update(self, task_id: int, status: str, note: str = "") -> dict:
        if status not in VALID_STATUSES:
            return {"error": f"invalid status {status!r}; use one of {VALID_STATUSES}"}
        for t in self.tasks:
            if t.id == task_id:
                t.status = status
                if note:
                    t.note = note
                return {"ok": True, "task": asdict(t)}
        return {"error": f"no task with id {task_id}"}

    def as_dicts(self) -> list[dict]:
        return [asdict(t) for t in self.tasks]

    def digest(self) -> str:
        if not self.tasks:
            return "(no tasks planned yet)"
        lines = []
        for t in self.tasks:
            mark = {"pending": " ", "in_progress": "~", "done": "x", "blocked": "!"}[t.status]
            note = f" — {t.note}" if t.note else ""
            lines.append(f"[{mark}] #{t.id} ({t.stage}) {t.title}{note}")
        return "\n".join(lines)

    def stage_status(self, stage: str) -> str:
        """'done' only if every task in the stage is done; 'blocked' if any
        blocked task remains; else 'open' (pending/in_progress work remains)."""
        items = [t for t in self.tasks if t.stage == stage]
        if not items:
            return "unplanned"
        if any(t.status == "blocked" for t in items):
            return "blocked"
        if all(t.status == "done" for t in items):
            return "done"
        return "open"

    def open_stages(self, stages: list[str] = DEFAULT_STAGES) -> list[str]:
        seen = []
        for stage in stages:
            st = self.stage_status(stage)
            if st in ("open", "unplanned"):
                seen.append(f"{stage}:{st}")
        return seen

    def blocked_tasks(self) -> list[Task]:
        return [t for t in self.tasks if t.status == "blocked"]
