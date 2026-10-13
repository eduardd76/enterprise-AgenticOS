"""Lease-based lock manager with wait-for-graph deadlock detection (vExpertAI §3.G).

Leases bound how long a crashed or looping agent can hold a resource; cycle detection
turns a would-be deadlock into an immediate DEADLOCK error for the requester, which is
the cheapest victim (it holds nothing new yet). Locks are in-memory: a kernel restart
releases them all, which is safe because leases are short and holders are restarted.
"""

from __future__ import annotations

import asyncio
import time

from .errors import SyscallError


class LockManager:
    def __init__(self) -> None:
        self.holders: dict[str, tuple[str, float]] = {}   # resource -> (agent, lease expiry)
        self.waiting: dict[str, str] = {}                  # agent -> resource it waits for
        self._changed = asyncio.Event()

    def _holder(self, resource: str) -> str | None:
        h = self.holders.get(resource)
        if h and h[1] < time.monotonic():
            del self.holders[resource]          # lease expired
            return None
        return h[0] if h else None

    def _would_deadlock(self, agent: str, resource: str) -> list[str] | None:
        path, cur = [agent], self._holder(resource)
        while cur is not None:
            if cur in path[1:]:
                return None                     # cycle not involving us; leases will break it
            path.append(cur)
            if cur == agent:
                return path
            nxt = self.waiting.get(cur)
            cur = self._holder(nxt) if nxt else None
        return None

    async def acquire(self, agent: str, resource: str, lease_s: float, timeout_s: float) -> dict:
        deadline = time.monotonic() + timeout_s
        while True:
            holder = self._holder(resource)
            if holder is None or holder == agent:
                self.holders[resource] = (agent, time.monotonic() + lease_s)
                self.waiting.pop(agent, None)
                return {"resource": resource, "lease_s": lease_s}
            cycle = self._would_deadlock(agent, resource)
            if cycle:
                self.waiting.pop(agent, None)
                raise SyscallError("DEADLOCK", f"wait-for cycle {' -> '.join(cycle)} on {resource}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.waiting.pop(agent, None)
                raise SyscallError("DEADLINE_EXCEEDED", f"lock {resource} held by {holder}")
            self.waiting[agent] = resource
            self._changed.clear()
            try:
                await asyncio.wait_for(self._changed.wait(), timeout=min(remaining, 0.25))
            except asyncio.TimeoutError:
                pass

    def release(self, agent: str, resource: str) -> bool:
        if self._holder(resource) == agent:
            del self.holders[resource]
            self._changed.set()
            return True
        return False

    def release_all(self, agent: str) -> list[str]:
        mine = [r for r, (a, _) in self.holders.items() if a == agent]
        for r in mine:
            del self.holders[r]
        self.waiting.pop(agent, None)
        self._changed.set()
        return mine
