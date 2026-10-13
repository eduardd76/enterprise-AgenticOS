"""Risk- and deadline-aware agent scheduler (vExpertAI §3.B; AOS-0001 §10.6, §12.9).

The scarce resource is an *active reasoning slot* (model/inference capacity), not CPU.
Agents hold a slot while RUNNING and release it whenever they block (WAITING) or are
suspended, so a human-blocked agent never starves others — the agentic analogue of a
process sleeping on I/O. Selection: priority class + aging (starvation prevention),
ties broken by earliest deadline (EDF).
"""

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass, field

PRIORITY_BASE = {"critical": 300.0, "high": 200.0, "normal": 100.0, "low": 0.0}


@dataclass
class _Waiter:
    agent_id: str
    priority: str
    deadline: float | None
    enqueued: float
    fut: asyncio.Future = field(repr=False)


class Scheduler:
    def __init__(self, slots: int = 3, aging_per_s: float = 10.0, aging_quantum_s: float = 1.0):
        self.slots = slots
        self.aging_per_s = aging_per_s
        self.aging_quantum_s = aging_quantum_s   # age in whole quanta so EDF can break ties
        self.running: set[str] = set()
        self._pending: list[_Waiter] = []
        self.dispatch_log: list[str] = []   # order of grants, for tests/benchmarks

    def score(self, w: _Waiter, now: float) -> tuple[float, float]:
        quanta = math.floor((now - w.enqueued) / self.aging_quantum_s)
        aged = PRIORITY_BASE.get(w.priority, 100.0) + self.aging_per_s * quanta * self.aging_quantum_s
        return (-aged, w.deadline if w.deadline is not None else math.inf)

    async def acquire(self, agent_id: str, priority: str, deadline: float | None) -> None:
        if agent_id in self.running:
            return
        fut = asyncio.get_running_loop().create_future()
        self._pending.append(_Waiter(agent_id, priority, deadline, time.monotonic(), fut))
        self._pump()
        try:
            await fut
        except asyncio.CancelledError:
            self._pending = [w for w in self._pending if w.fut is not fut]
            if fut.done() and not fut.cancelled():
                self.release(agent_id)
            raise

    def release(self, agent_id: str) -> None:
        if agent_id in self.running:
            self.running.discard(agent_id)
            self._pump()

    def _pump(self) -> None:
        now = time.monotonic()
        self._pending = [w for w in self._pending if not w.fut.done()]
        while len(self.running) < self.slots and self._pending:
            best = min(self._pending, key=lambda w: self.score(w, now))
            self._pending.remove(best)
            self.running.add(best.agent_id)
            self.dispatch_log.append(best.agent_id)
            best.fut.set_result(None)
