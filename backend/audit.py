"""Tamper-evident audit trail.

Every event stores the hash of the event before it, so the log is a hash chain: change or delete one line and
every later hash stops matching. `verify()` recomputes the chain. The trail survives /state/reset on purpose:
resetting demo state is itself an audited event.

This is evidence of integrity inside one process. It is not a signed, off-host log; shipping the head hash to
an external store is the obvious next step and is listed in the limitations.
"""
import csv
import hashlib
import io
import json
from typing import Any, Dict, List, Optional, Tuple

from models import AuditEvent

GENESIS = "0" * 64
MAX_EVENTS = 5000


def _digest(prev_hash: str, body: Dict[str, Any]) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev_hash + canon).encode("utf-8")).hexdigest()


def _body(e: AuditEvent) -> Dict[str, Any]:
    return {"seq": e.seq, "timestamp": e.timestamp, "type": e.type, "scenario_id": e.scenario_id,
            "actor": e.actor, "summary": e.summary, "data": e.data}


class AuditLog:
    """Not thread-safe by itself: the Engine appends under its lock."""

    def __init__(self) -> None:
        self.events: List[AuditEvent] = []
        self._seq = 0
        self._head = GENESIS

    @property
    def head_hash(self) -> str:
        return self._head

    def append(self, timestamp: str, type_: str, summary: str, scenario_id: Optional[str] = None,
               actor: str = "system", data: Optional[Dict[str, Any]] = None) -> AuditEvent:
        self._seq += 1
        body = {"seq": self._seq, "timestamp": timestamp, "type": type_, "scenario_id": scenario_id,
                "actor": actor, "summary": summary, "data": data or {}}
        event = AuditEvent(prev_hash=self._head, hash=_digest(self._head, body), **body)
        self._head = event.hash
        self.events.append(event)
        if len(self.events) > MAX_EVENTS:
            del self.events[: len(self.events) - MAX_EVENTS]  # the oldest kept event's prev_hash anchors the chain
        return event

    def verify(self) -> Tuple[bool, Optional[int]]:
        """(chain is intact, seq of the first broken event)."""
        prev = self.events[0].prev_hash if self.events else GENESIS
        for e in self.events:
            if e.prev_hash != prev or _digest(prev, _body(e)) != e.hash:
                return False, e.seq
            prev = e.hash
        return prev == self._head or not self.events, None

    def newest(self, limit: int, scenario_id: Optional[str] = None, type_prefix: Optional[str] = None) -> List[AuditEvent]:
        out = [e for e in reversed(self.events)
               if (scenario_id is None or e.scenario_id == scenario_id) and (type_prefix is None or e.type.startswith(type_prefix))]
        return out[:limit]

    # ---- exports (oldest first, the order an auditor replays them in)
    def to_jsonl(self) -> str:
        return "".join(json.dumps(e.model_dump(), ensure_ascii=False, sort_keys=True) + "\n" for e in self.events)

    def to_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["seq", "timestamp", "type", "scenario_id", "actor", "summary", "data", "prev_hash", "hash"])
        for e in self.events:
            w.writerow([e.seq, e.timestamp, e.type, e.scenario_id or "", e.actor, e.summary,
                        json.dumps(e.data, ensure_ascii=False, sort_keys=True), e.prev_hash, e.hash])
        return buf.getvalue()
