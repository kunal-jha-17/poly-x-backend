"""Executed-action ledger. Scenario-neutral: an entry is (time, subject, amount, reference).

support pack: subject = customer id, amount = rupees refunded, reference = order id
devops pack:  subject = environment, amount = 1 per executed deploy, reference = service

Only EXECUTED actions enter the ledger. Denied / escalated calls never do.
Not thread-safe by itself: the Engine serialises access with its lock.
"""
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from models import WINDOW_HOURS, RefundState


class Ledger:
    def __init__(self, receipt_prefix: str = "RFD", ticket_prefix: str = "TKT") -> None:
        self._entries: List[Tuple[datetime, str, int, str]] = []  # (ts, subject, amount, reference)
        self.receipt_prefix = receipt_prefix
        self.ticket_prefix = ticket_prefix
        self.refund_seq = 0
        self.ticket_seq = 0

    def next_refund_id(self) -> str:
        self.refund_seq += 1
        return f"{self.receipt_prefix}-{self.refund_seq:04d}"

    def next_ticket_id(self) -> str:
        self.ticket_seq += 1
        return f"{self.ticket_prefix}-{self.ticket_seq:04d}"

    def add(self, customer_id: str, amount_inr: int, ts: datetime, order_id: str) -> None:
        self._entries.append((ts, customer_id, amount_inr, order_id))

    @staticmethod
    def _in_window(ts: datetime, now: datetime, window_type: str, hours: int) -> bool:
        if ts > now:
            return False
        if window_type == "calendar_day":
            return ts.astimezone(timezone.utc).date() == now.astimezone(timezone.utc).date()
        return ts > now - timedelta(hours=hours)  # rolling: (now - hours, now]

    def total(self, customer_id: str, now: datetime, window_type: str = "rolling", hours: int = WINDOW_HOURS) -> int:
        return sum(a for ts, c, a, _ in self._entries if c == customer_id and self._in_window(ts, now, window_type, hours))

    def count(self, customer_id: str, now: datetime, window_type: str = "rolling", hours: int = WINDOW_HOURS) -> int:
        return sum(1 for ts, c, _, _ in self._entries if c == customer_id and self._in_window(ts, now, window_type, hours))

    def snapshot(self, customer_id: str, now: datetime) -> RefundState:
        """Support-shaped snapshot (rupees per customer, rolling 24h)."""
        total, count = self.total(customer_id, now), self.count(customer_id, now)
        return RefundState(
            customer_id=customer_id, refund_total_24h_inr=total, refund_count_24h=count, window_hours=WINDOW_HOURS,
            subject=customer_id, unit="inr", total=total, count=count,
        )

    def __len__(self) -> int:
        return len(self._entries)

    def clear(self, customer_id: Optional[str] = None) -> int:
        before = len(self._entries)
        self._entries = [e for e in self._entries if customer_id is not None and e[1] != customer_id]
        return before - len(self._entries)
